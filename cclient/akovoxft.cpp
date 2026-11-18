#include "./../srv/akovoxserver.h"

#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <cstring>
#include <chrono>
#include <iostream>
#include <iomanip>
#include <cstdio>

#include <sodium.h>

#include <poll.h>
#include <unistd.h>
#define READLINE_CALLBACKS
#include <readline/readline.h>

#include "akovoxmsg.hpp"

struct profile {
    unsigned char 
        spk[crypto_sign_ed25519_PUBLICKEYBYTES], 
        ssk[crypto_sign_ed25519_SECRETKEYBYTES],
        cpk[crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES],
        csk[crypto_box_curve25519xchacha20poly1305_SECRETKEYBYTES];
    std::string name;
};

struct participant {
    udp_peer peer;
    std::string name;
    std::vector<unsigned char> crypt_pk;
    std::vector<unsigned char> sign_pk;
    std::vector<unsigned char> for_me;

    participant(const unsigned char * const cpk,    const size_t cpk_len,
                const unsigned char * const spk,    const size_t spk_len,
                const          char * const name_p, const size_t name_len,
                const udp_peer * const ppeer
               ): crypt_pk(cpk, cpk + cpk_len)
                , sign_pk(spk, spk + spk_len)
                , name(name_p, name_p + name_len) {
        memcpy(&peer, ppeer, sizeof(peer));
    }
};

typedef std::unordered_map<id_t, participant> participant_map;

enum log_level {
    // Everything
    VERBOSE = 0,
    // Some debug info
    DEBUG = 2,
    // State changes
    INFO = 4,
    // Ignorable errors
    WARNING = 6,
    // Recoverobale and I/O errors
    ERROR = 8,
    // Fatal bug indicator
    FATAL = 10,
    // Shut the logger up
    SILENT = 127
};

class _readline_guard {
public:
    bool run = true;
    _readline_guard() {
        rl_save_prompt();
        std::fprintf(rl_outstream, "\r\033K");
        std::fflush(rl_outstream);
    }
    ~_readline_guard() {
        std::fprintf(rl_outstream, "\r\n");
        std::fflush(rl_outstream);
        rl_on_new_line();
        rl_restore_prompt();
        rl_redisplay();
    }
};

#define SAFE_OUT for (_readline_guard _guard; _guard.run; _guard.run = false)

#define LOG(x) if ((x) >= state.current_log_level) SAFE_OUT

struct {
    profile me;
    udp_peer me_as_peer;
    participant_map participants;
    std::unordered_map<std::string, id_t> known_names;
    int sock;
    in_addr_t sip;
    in_port_t sport;
    int64_t srv_ka_timeout_ms = 5 * 60 * 1000;
    int64_t srv_ka_rtt_timeout_ms = 10 * 1000;
    log_level current_log_level = ERROR;
    std::unordered_set<id_t> unknown_ids;
    bool continue_run = true;
} state;

static uint8_t UDP_BUFFER[0xffff];

void zero_buffer(const size_t up_to = 0xffff) {
    std::memset(UDP_BUFFER, 0, up_to);
}

// Send n first bytes of UDP_BUFFER to ip:port
int send_buffer(const in_addr_t ip, const in_port_t port, const size_t n) {
    const sockaddr_in a = { AF_INET, port, { ip } };
    LOG(VERBOSE) {
        std::cerr << "Sending " << n << " bytes to " << inet_ntoa(a.sin_addr) << ":" << ntohs(port) << std::endl;
    }
	int ret = sendto(state.sock, UDP_BUFFER, n, 0, reinterpret_cast<const sockaddr * const>(&a), sizeof(a));
    LOG(VERBOSE) {
        std::cerr << "Sent " << n << " bytes to " << inet_ntoa(a.sin_addr) << ":" << ntohs(port) << std::endl;
    }
	return ret;
}

int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}

std::ostream &operator<<(std::ostream &out, const udp_peer &peer) {
    out << std::hex << std::setw(4) << std::setfill('0') << peer.id 
        << std::dec << std::setw(0) << std::setfill(' ') << "|" 
        << inet_ntoa(in_addr { peer.ip }) << ":" << ntohs(peer.port) 
        << "|" << peer.valid_until;
    return out;
}

void login() {
    auto req = reinterpret_cast<request * const>(UDP_BUFFER);
    auto ld = reinterpret_cast<login_data * const>(UDP_BUFFER + sizeof(request));
    zero_buffer(sizeof(header) + sizeof(login_data));
    req->req_type = REQ_LOGIN;
    req->requestor_id = 0; // no id yet
    req->salt = randombytes_random();
    req->valid_until = htobe64(now_ms() + state.srv_ka_timeout_ms + state.srv_ka_rtt_timeout_ms);
    auto csize = crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES;
    auto ssize = crypto_sign_ed25519_PUBLICKEYBYTES;
    auto nsize = state.me.name.length();
    auto vsize = crypto_sign_BYTES;
    ld->csize = htons(csize - 1);
    ld->ssize = htons(ssize - 1);
    ld->nsize = htons(nsize - 1);
    req->vsize = htons(vsize - 1);
    auto i = ld->tail;
    std::memcpy(i, state.me.spk, ssize);
    i += ssize;
    std::memcpy(i, state.me.cpk, csize);
    i += csize;
    std::memcpy(i, state.me.name.data(), nsize);
    i += nsize;
    unsigned long long siglen;
    auto s_rc = crypto_sign_ed25519_detached(i, &siglen, UDP_BUFFER, i - UDP_BUFFER, state.me.ssk);
    if (s_rc != 0 || siglen - 1 != ntohs(req->vsize)) {
        LOG(FATAL) {
            std::cerr << "Signature length (" << s_rc << ") "
                      << "does not match with expected " << (((uint32_t) ntohs(req->vsize)) + 1)
                      << std::endl;
        }
        return;
    }
    i += siglen;
    if (0 > send_buffer(state.sip, state.sport, i - UDP_BUFFER)) {
        LOG(ERROR) {
            std::cerr << "Cannot send login" << std::endl;
        }
    }
}

void send_keep_alive() {
    auto req = reinterpret_cast<request * const>(UDP_BUFFER);
    auto ka = reinterpret_cast<keep_alive * const>(UDP_BUFFER + sizeof(request));
    zero_buffer(sizeof(header) + sizeof(keep_alive));
    req->req_type = REQ_KEEP_ALIVE;
    req->requestor_id = htonl(state.me_as_peer.id);
    req->salt = randombytes_random();
    req->valid_until = htobe64(now_ms() + state.srv_ka_timeout_ms + state.srv_ka_rtt_timeout_ms);
    req->vsize = htons(crypto_sign_BYTES - 1);
    unsigned long long siglen;
    auto s_rc = crypto_sign_ed25519_detached(ka->signature, &siglen, UDP_BUFFER, ka->signature - UDP_BUFFER, state.me.ssk);
    if (s_rc != 0 || siglen - 1 != ntohs(req->vsize)) {
        LOG(FATAL) {
            std::cerr << "Signature length (" << s_rc << ") "
                      << "does not match with expected " << (((uint32_t) ntohs(req->vsize)) + 1)
                      << std::endl;
        }
        return;
    }
    if (0 > send_buffer(state.sip, state.sport, sizeof(request) + sizeof(keep_alive) + siglen)) {
        LOG(ERROR) {
            std::cerr << "Cannot send keep alive" << std::endl;
        }
    }
}

void request_unknown_ids() {
    auto req = reinterpret_cast<request * const>(UDP_BUFFER);
    auto ri = reinterpret_cast<request_ids * const>(UDP_BUFFER + sizeof(request));
    zero_buffer(sizeof(header) + sizeof(request_ids));
    req->req_type = REQ_REQ_IDS;
    req->requestor_id = htonl(state.me_as_peer.id);
    req->salt = randombytes_random();
    req->valid_until = htobe64(now_ms() + state.srv_ka_timeout_ms + state.srv_ka_rtt_timeout_ms);
    req->vsize = htons(crypto_sign_BYTES - 1);
    auto uis = state.unknown_ids.size();
    ri->size = uis > 255 ? 255 : uis;
    auto i = ri->tail;
    std::size_t cnt = 0;
    for (const id_t uid : state.unknown_ids) {
        i[0] = uid >> 24;
        i[1] = uid >> 16;
        i[2] = uid >>  8;
        i[3] = uid;
        i += 4;
        if (ri->size == ++cnt) break;
    }
    unsigned long long siglen;
    auto s_rc = crypto_sign_ed25519_detached(i, &siglen, UDP_BUFFER, i - UDP_BUFFER, state.me.ssk);
    if (s_rc != 0 || siglen - 1 != ntohs(req->vsize)) {
        LOG(FATAL) {
            std::cerr << "Signature length (" << s_rc << ") "
                      << "does not match with expected " << (((uint32_t) ntohs(req->vsize)) + 1)
                      << std::endl;
        }
        return;
    }
    i += siglen;
    if (0 > send_buffer(state.sip, state.sport, i - UDP_BUFFER)) {
        LOG(ERROR) {
            std::cerr << "Cannot request unknown ids" << std::endl;
        }
    }
}

void accept_me_as_peer(const header * const hdr) {
    state.me_as_peer.id = be32toh(hdr->id);
    state.me_as_peer.ip = hdr->dip;
    state.me_as_peer.port = hdr->dport;
}

uint8_t *handle_full_data(uint8_t *buffer, const uint8_t * const end) {
    auto i = buffer;
    while (i < end) {
        uint16_t nlen = 0;
        if (i + 2 <= end) {
            nlen = *i;
            ++i;
            nlen = (nlen << 8) + *i;
            ++i;
            nlen += 1;
        } else break;
        if (i + nlen > end) {
            LOG(ERROR) {
                std::cerr << "Too long name: " << nlen << " bytes." << std::endl;
            }
            break;
        }
        auto name_p = reinterpret_cast<const char * const>(i);
        i += nlen;

        uint16_t ilen = 0;
        if (i + 2 <= end) {
            ilen = *i;
            ++i;
            ilen = (ilen << 8) + *i;
            ++i;
            ilen += 1;
        } else break;
        if (i + ilen > end) {
            LOG(ERROR) {
                std::cerr << "Too long signing PK: " << ilen << " bytes." << std::endl;
            }
            break;
        }
        auto identity_p = reinterpret_cast<const unsigned char * const>(i);
        i += ilen;

        uint16_t clen = 0;
        if (i + 2 <= end) {
            clen = *i;
            ++i;
            clen = (clen << 8) + *i;
            ++i;
            clen += 1;
        } else break;
        if (i + clen > end) {
            LOG(ERROR) {
                std::cerr << "Too long encryption PK: " << clen << " bytes." << std::endl;
            }
            break;
        }
        auto enc_p = reinterpret_cast<const unsigned char * const>(i);
        i += clen;

        if (i + sizeof(udp_peer) > end) {
            LOG(ERROR) {
                std::cerr << "Incomplete UDP peer (" << (end - i) << "/" << sizeof(udp_peer) << " bytes)" << std::endl;
            }
            break;
        }
        auto peer_net = reinterpret_cast<udp_peer * const>(i);
        udp_peer peer_host;
        ntoh_peer(peer_net, &peer_host);
        const id_t ph_id = peer_host.id; // unpack

        state.participants.emplace(
            std::piecewise_construct,
            std::forward_as_tuple(ph_id),
            std::forward_as_tuple(enc_p, (size_t) clen, identity_p, (size_t) ilen, name_p, (size_t) nlen, &peer_host)
        );
        state.unknown_ids.erase(peer_host.id);
        state.known_names.emplace(
            std::piecewise_construct,
            std::forward_as_tuple(name_p, nlen),
            std::forward_as_tuple(ph_id)
        );
        i += sizeof(udp_peer);

        LOG(INFO) {
            std::cerr << "New arrival: " << std::hex << std::setw(4) << std::setfill('0') << peer_host.id 
                      << std::dec << std::setw(0) << std::setfill(' ') << "|" 
                      << std::string_view(name_p, (std::size_t) nlen) << " on "
                      << inet_ntoa(in_addr { peer_host.ip }) << ":" << ntohs(peer_host.port) << std::endl;
        }
    }
    if (i != end) {
        LOG(WARNING) {
            std::cerr << "Not fully parsed package (" << (end - i) << " bytes remained)" << std::endl;
        }
    }
    return i;
}

uint8_t *handle_peer_list_update(uint8_t *buffer, const uint8_t * const end) {
    auto i = buffer;
    while (i < end) {
        if (i + sizeof(udp_peer) > end) {
            LOG(ERROR) {
                std::cerr << "Incomplete UDP peer (" << (end - i) << "/" << sizeof(udp_peer) << " bytes)" << std::endl;
            }
            break;
        }
        auto peer_net = reinterpret_cast<const udp_peer * const>(i);
        udp_peer peer_host;
        ntoh_peer(peer_net, &peer_host);

        auto it = state.participants.find(peer_host.id);

        if (it == state.participants.end()) {
            // add unknown id
            state.unknown_ids.insert(peer_host.id);
            LOG(VERBOSE) {
                std::cerr << "Got an update for unknown peer: " << peer_host << std::endl;
            }
        } else {
            // update peer
            if (peer_host.ip != it->second.peer.ip || peer_host.port != it->second.peer.port) {
                LOG(INFO) {
                    std::cerr << "Address changed: " << std::hex << std::setw(4) << std::setfill('0') << peer_host.id
                              << std::dec << std::setw(0) << std::setfill(' ') << "|"
                              << it->second.name << " "
                              << inet_ntoa(in_addr { it->second.peer.ip }) << ":" << ntohs(it->second.peer.port)
                              << " -> "
                              << inet_ntoa(in_addr { peer_host.ip }) << ":" << ntohs(peer_host.port) << std::endl;
                }
            }
            LOG(VERBOSE) {
                std::cerr << it->second.peer << " -> " << peer_host
                          << " (" << (peer_host.valid_until - it->second.peer.valid_until) << "ms)" << std::endl;
            }
            memcpy(&(it->second.peer), &peer_host, sizeof(udp_peer));
        }

        i += sizeof(udp_peer);
    }
    if (i != end) {
        LOG(WARNING) {
            std::cerr << "Not fully parsed package (" << (end - i) << " bytes remained)" << std::endl;
        }
    }
    return i;
}

void handle_incoming_server(const size_t len) {
    auto resp = reinterpret_cast<const header * const>(UDP_BUFFER);
    auto tail = UDP_BUFFER + sizeof(header);
    auto end = UDP_BUFFER + len;
    bool success = false;
    switch (resp->type) {
    case HDR_FULL_DATA: {
            auto last_parsed = handle_full_data(tail, end);
            success = last_parsed == end;
            break;
        }
    case HDR_SHORT_DATA: {
            // handle peer list update
            auto last_parsed = handle_peer_list_update(tail, end);
            success = last_parsed == end;
            break;
        }
    default: {
            LOG(DEBUG) {
                std::cerr << "Got server package of unknown type " << resp->type << std::endl;
            }
            break;
        }
    }
    if (success) {
        accept_me_as_peer(resp);
    }
}

void handle_incoming_client(const size_t len) {
    auto msg = akovox::parse(UDP_BUFFER, len);
    auto user_id_it = state.known_names.find(msg.sender());
    const unsigned char *spk = nullptr, *cpk = nullptr;
    size_t spkl = 0, cpkl = 0;
    participant_map::iterator pit = state.participants.end();
    if (user_id_it != state.known_names.end()) {
        pit = state.participants.find(user_id_it->second);
        if (pit == state.participants.end()) {
            LOG(FATAL) {
                std::cerr << "User '" << msg.sender() << "' have id ("
                          << user_id_it->second << "), but no 'participant'" << std::endl;
            }
            return;
        }
        spk = pit->second.sign_pk.data();
        cpk = pit->second.crypt_pk.data();
        spkl = pit->second.sign_pk.size();
        cpkl = pit->second.crypt_pk.size();
    }
    // auto peer = state. // todo: name -> id mapping
    if (msg.is_encrypted() && cpk != nullptr) {
        if (pit->second.for_me.empty()) {
            std::vector<uint8_t> shared(crypto_box_BEFORENMBYTES);
            auto r = crypto_box_curve25519xsalsa20poly1305_beforenm(shared.data(), cpk, state.me.csk);
            if (r == -1) throw -7;
            pit->second.for_me.swap(shared);
        }
        akovox::decrypt(msg, pit->second.for_me.data(), pit->second.for_me.size());
    }
    if (msg.is_signed() && spk != nullptr) {
        akovox::break_seal(msg, spk, spkl);
    }
    if (msg.is_compressed()) {
        akovox::decompress(msg);
    }
    SAFE_OUT {
        std::cout << msg.sender() << "\n\t" << std::string_view((const char *) msg.raw_data().data(), msg.raw_data().size()) << std::endl;
    }
}

void handle_incoming(
    const sockaddr_in &src,
    const size_t len
) {
    if (src.sin_addr.s_addr == state.sip
     && src.sin_port == state.sport
     && len >= sizeof(header) 
     && *(reinterpret_cast<const uint64_t * const>(UDP_BUFFER)) == 0) {
        handle_incoming_server(len);
    } else {
        handle_incoming_client(len);
        // maybe client
        // SAFE_OUT {
        //     std::cout << std::string_view(reinterpret_cast<const char * const>(UDP_BUFFER), len) << std::endl;
        // }
    }
}

int sock_init() {
    state.sock = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP);
	if (state.sock < 0) {
		perror("Net init");
		return -1;
	}
	sockaddr_in a = { 
        AF_INET, 
        htons((uint16_t) (49152 + (randombytes_random() % (65535 - 49152)))), 
        INADDR_ANY 
    };

	int e = bind(state.sock, (struct sockaddr *)&a, sizeof(a));
	if(e) {
		perror("Net init");
		return -2;
	}
    return 0;
}

void broadcast(const char *line) {
    akovox::akovoxmsg base(
        (akomsg_mtype) AKOMSG_TEXT,
        (uint8_t) 0,
        (uint32_t) 1,
        (uint64_t) now_ms(),
        state.me.name,
        std::string(""),
        std::unordered_map<std::string, std::variant<int64_t, std::string> >(),
        std::vector<uint8_t>((const uint8_t *) line, ((const uint8_t *) line) + strlen(line))
    );
    if (base.raw_data().size() > 400) akovox::compress(base, std::string_view(akovox::DEFLATE));
    // akovox::sign(base, akovox::ED25519, state.me.ssk, crypto_sign_SECRETKEYBYTES);
    for (auto &p : state.participants) {
        if (p.first == state.me_as_peer.id) continue;
        if (p.second.for_me.empty()) {
            std::vector<uint8_t> shared(crypto_box_BEFORENMBYTES);
            auto r = crypto_box_curve25519xsalsa20poly1305_beforenm(shared.data(), p.second.crypt_pk.data(), state.me.csk);
            if (r == -1) throw -7;
            p.second.for_me.swap(shared);
        }
        akovox::akovoxmsg c(base);
        c._receiver = p.second.name;
        // akovox::encrypt(c, akovox::X25519XSalsa, p.second.for_me.data(), crypto_box_BEFORENMBYTES);
        auto end = akovox::write(UDP_BUFFER, c);
        send_buffer(p.second.peer.ip, p.second.peer.port, end - UDP_BUFFER);
    }
}

void line_handler(char *line) {
    if (line == nullptr) {
        state.continue_run = false;
        std::cout << ":!" << std::endl;
        return;
    }
    if (line[0] != 0) {
        broadcast(line);
        // strncpy((char *) UDP_BUFFER, line, 500);
        // auto len = std::strlen(line);
        // auto n = len > 500 ? 500 : len;
        // for (auto &p : state.participants) {
        //     send_buffer(p.second.peer.ip, p.second.peer.port, n);
        //     // sleep(1);
        // }
    }
    rl_free(line);
}

int main(int argc, char *argv[]) {
    // todo configure it
    in_addr sip;
    in_port_t sport = 44505;
    inet_aton("192.168.0.19", &sip);
    state.me.name = argc == 2 ? std::string(argv[1]) : "faerytea";
    state.sip = sip.s_addr;
    state.sport = htons(sport);
    state.current_log_level = VERBOSE;
    state.srv_ka_timeout_ms = 10 * 1000;
    // odot

    // init
    if (sodium_init() != 0) {
        perror("Sodium init");
        return 1;
    };
    if (sock_init() != 0) {
        return 2;
    }
    rl_callback_handler_install((state.me.name + "> ").c_str(), line_handler);
    zero_buffer();

    // todo load keys
    crypto_sign_ed25519_keypair(state.me.spk, state.me.ssk);
    crypto_box_curve25519xchacha20poly1305_keypair(state.me.cpk, state.me.csk);
    // odot

    // run
    int64_t last_ka = now_ms();
    pollfd fds[] {
        { STDIN_FILENO, POLLIN, 0 },
        { state.sock, POLLIN, 0 }
    };
    login();
    while (state.continue_run) {
        auto poll_cnt = poll(fds, 2, now_ms() - last_ka + state.srv_ka_timeout_ms);
        if (poll_cnt < 0) {
            LOG(ERROR) {
                perror("poll error");
            }
            break;
        }
        if (poll_cnt == 0 || now_ms() > last_ka + state.srv_ka_timeout_ms) {
            LOG(VERBOSE) {
                std::cerr << "Send KA" << std::endl;
            }
            // KA TA
            if (state.unknown_ids.empty())
                send_keep_alive();
            else
                request_unknown_ids();
            last_ka = now_ms();
        }
        if (fds[1].revents & POLLIN) {
            // something on sockets
            ssize_t len;
            sockaddr_in src;
            socklen_t srclen;
            do {
                len = recvfrom(state.sock, UDP_BUFFER, 0xffff, 0, (sockaddr *) &src, &srclen);
                if (len > 0) {
                    handle_incoming(src, len);
                }
            } while (len > 0);
            
            if (len < 0 && errno != EWOULDBLOCK && errno != EAGAIN) {
                LOG(ERROR) {
                    perror("recvfrom");
                }
                state.continue_run = false;
            }
        }
        if (fds[0].revents & POLLIN) {
            // something on stdin
            rl_callback_read_char();
        }
    }

    rl_callback_handler_remove();
    return 0;
}

#undef READLINE_CALLBACKS
