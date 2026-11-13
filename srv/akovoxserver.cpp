#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <string.h>

#include <sodium.h>

#define PACK_MAXLEN	(508)
#define NAME    	"akovoxserver"

#include <map>
#include <unordered_set>
#include <unordered_map>
#include <string>
#include <vector>
#include <memory_resource>
#include <chrono>
#include <thread>
#include <algorithm>

#include <unistd.h>

#include "akovoxserver.h"

inline std::pmr::memory_resource* get_shared_vector_pool() {
    static std::pmr::pool_options options = [] {
        std::pmr::pool_options opts;
        opts.max_blocks_per_chunk = 1024;
        opts.largest_required_pool_block = 32;
        return opts;
    }();

    static std::pmr::unsynchronized_pool_resource pool(options);
    return &pool;
}

struct client {
	std::pmr::vector<unsigned char> identity;
	std::pmr::vector<unsigned char> cipher_pub;
	udp_peer peer;
	
	client(const uint8_t *ipk_data, size_t ipk_len,
           const uint8_t *cpk_data, size_t cpk_len,
           const uint64_t valid_until,
		   const id_t id,
		   const in_addr_t ip,
		   const in_port_t port,
           std::pmr::memory_resource* mr = get_shared_vector_pool())
        : identity(ipk_data, ipk_data + ipk_len, mr),
          cipher_pub(cpk_data, cpk_data + cpk_len, mr),
          peer({
			valid_until,
			id,
			ip,
			port
		  }) {};
};

typedef std::map<std::string, client, std::less<> > client_map;

struct {
	client_map known_clients;
	std::unordered_map<id_t, std::string_view> known_names;
	std::vector<id_t> free_ids;
	id_t lowest_free_id;
	int64_t cleaning_period_ms = 600000;
	int sock;
} state;

id_t allocate_id() {
	if (state.free_ids.empty()) {
	    return (state.lowest_free_id)++;
	} else {
		auto v = state.free_ids.back();
		state.free_ids.pop_back();
		return v;
	}
}

void free_id(const id_t id) {
	state.free_ids.push_back(id);
}

uint8_t UDP_BUFFER[PACK_MAXLEN];

void zero_buffer() {
	memset((void *) UDP_BUFFER, 0, PACK_MAXLEN);
}

// size of packed client
size_t client_size(const std::string &key, const client &c) {
	size_t res = 0;
	res += 2 + key.length();
	res += 2 + c.identity.size();
	res += 2 + c.cipher_pub.size();
	res += sizeof(udp_peer);
	return res;
}

// Fills UPD answer for initial request
uint8_t *fill_init_clients(
	client_map::iterator &start, 
	const client_map::iterator &end, 
	const std::unordered_set<id_t> &filter
) {
	auto i = UDP_BUFFER + sizeof(header);
	size_t ccsize;
	while (start != end && i + (ccsize = client_size(start->first, start->second)) <= UDP_BUFFER + PACK_MAXLEN) {
		auto &cc = start->second;
		if (!filter.empty() && filter.find(cc.peer.id) == filter.end()) {
			start++;
			continue;
		}
		auto len = start->first.length();
		*i = (len - 1) >> 8;
		++i;
		*i = (len - 1);
		++i;
		memcpy(i, start->first.data(), len);
		i += len;
		auto id_len = cc.identity.size();
		*i = (id_len - 1) >> 8;
		++i;
		*i = (id_len - 1);
		++i;
		memcpy(i, cc.identity.data(), id_len);
		i += id_len;
		auto c_len = cc.cipher_pub.size();
		*i = (c_len - 1) >> 8;
		++i;
		*i = (c_len - 1);
		++i;
		memcpy(i, cc.cipher_pub.data(), c_len);
		i += c_len;
		hton_peer(&(cc.peer), reinterpret_cast<udp_peer * const>(i));
		i += sizeof(udp_peer);
		start++;
	}
	return i;
}

// Fills short UDP answer
uint8_t *fill_update_clients(client_map::iterator &start, const client_map::iterator &end) {
	auto i = UDP_BUFFER + sizeof(header);
	while (start != end && i + sizeof(udp_peer) <= UDP_BUFFER + PACK_MAXLEN) {
		auto &cc = start->second;
		// memcpy(i, &(cc.peer), sizeof(udp_peer));
		hton_peer(&(cc.peer), reinterpret_cast<udp_peer * const>(i));
		i += sizeof(udp_peer);
		start++;
	}
	return i;
}

// Send answer to login data
void send_full(
	in_addr_t dip, 
	in_port_t dport, 
	id_t did, 
	const sockaddr_in &src, 
	const std::unordered_set<id_t> &filter = {}
) {
    auto hdr = reinterpret_cast<header *>(UDP_BUFFER);
    auto iter = state.known_clients.begin();
    auto end = state.known_clients.end();
    uint16_t page = 0;
    do {
        zero_buffer();
        auto buf_end = fill_init_clients(iter, end, filter);
        hdr->dip = dip;
        hdr->dport = dport;
        hdr->page_no = htons(page);
        hdr->id = htobe32(did);
		hdr->type = HDR_FULL_DATA;
        if (iter == end) {
            hdr->flags = 0;
            sendto(state.sock, UDP_BUFFER, buf_end - UDP_BUFFER, 0, (struct sockaddr *)&src, sizeof(src));
            break;
        } else {
            hdr->flags = 1;
            ++page;
            sendto(state.sock, UDP_BUFFER, buf_end - UDP_BUFFER, 0, (struct sockaddr *)&src, sizeof(src));
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    } while (1);
}

// Send answer to update request
void send_update(
	in_addr_t dip, 
	in_port_t dport, 
	id_t did, 
	const sockaddr_in &src
) {
    auto hdr = reinterpret_cast<header *>(UDP_BUFFER);
    auto iter = state.known_clients.begin();
    auto end = state.known_clients.end();
    uint16_t page = 0;
    do {
        zero_buffer();
        auto buf_end = fill_update_clients(iter, end);
        hdr->dip = dip;
        hdr->dport = dport;
        hdr->page_no = htons(page);
        hdr->id = htobe32(did);
		hdr->type = HDR_SHORT_DATA;
        if (iter == end) {
            hdr->flags = 0;
            sendto(state.sock, UDP_BUFFER, buf_end - UDP_BUFFER, 0, (struct sockaddr *)&src, sizeof(src));
            break;
        } else {
            hdr->flags = 1;
            page += 1;
            sendto(state.sock, UDP_BUFFER, buf_end - UDP_BUFFER, 0, (struct sockaddr *)&src, sizeof(src));
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    } while (1);
}

void print_malformed_udp_error() {
	fprintf(stderr, "Got malformed UDP request:");
	for (size_t i = 0; i < PACK_MAXLEN; ++i) {
		switch (i % 32) {
		case 0:
			fprintf(stderr, "\n\t");
			break;
		case 8:
		case 16:
		case 24:
			fprintf(stderr, " ");
			break;
		default:
			break;
		}
		fprintf(stderr, "%02x ", UDP_BUFFER[i]);
	}
	fprintf(stderr, "\n");
}

void vacuum() {
	static int64_t last_clean;
	// fucking STL abdomination
	const auto cur_time = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
	if (last_clean > cur_time) {
		// initialization problems
		last_clean = cur_time;
	} else if (last_clean + state.cleaning_period_ms < cur_time) {
		// perform cleaning
		unsigned removed = 0;
		for (auto it = state.known_clients.begin(); it != state.known_clients.end(); ) {
			if (it->second.peer.valid_until < cur_time) {
				auto id = it->second.peer.id;
				state.known_names.erase(id);
				it = state.known_clients.erase(it);
				free_id(id);
				removed += 1;
			} else {
				++it;
			}
		}
		size_t lowered_ids = 0;
		std::sort(state.free_ids.begin(), state.free_ids.end());
		while (!state.free_ids.empty() && state.lowest_free_id == state.free_ids.back() + 1) {
			state.free_ids.pop_back();
			lowered_ids += 1;
		}
		last_clean = cur_time;
		fprintf(stderr, "Vacuum cleaned %d nodes, %d survived, %d ids returned\n", removed, state.known_clients.size(), lowered_ids);
	} else {
		fprintf(stderr, "Next vacuum in %dms\n", last_clean + state.cleaning_period_ms - cur_time);
	}
}

void mainloop() {
	struct sockaddr_in src;
	socklen_t sl;
	zero_buffer();
	fprintf(stderr, "Waiting for data...\n");
	int l = recvfrom(state.sock, &UDP_BUFFER, PACK_MAXLEN, 0, (struct sockaddr *)&src, &sl);
	vacuum();
	if (l < 0) {
		perror("recvfrom");
		return;
	}
	fprintf(stderr, "<%d bytes from %x:%d\n", l, src.sin_addr.s_addr, ntohs(src.sin_port));
	if (l < sizeof(request)) {
		fprintf(stderr, "Too small package: %d < %d\n", l, sizeof(request));
	}
	auto dip = src.sin_addr.s_addr;
	auto dport = src.sin_port;
	auto req_raw = reinterpret_cast<request * const>(UDP_BUFFER);
	static request req;
	ntoh_request(req_raw, &req);
	const uint16_t vsize = req.vsize + 1;
	// fprintf(stderr, "Next line is fake\n");
	// print_malformed_udp_error();
	switch (req.req_type)
	{
	case REQ_LOGIN: {
		auto ld = reinterpret_cast<login_data * const>(UDP_BUFFER + sizeof(request));
		auto ld_len = sizeof(request) + sizeof(login_data);
		const uint16_t
			csize = ntohs(ld->csize) + 1,
			nsize = ntohs(ld->nsize) + 1,
			ssize = ntohs(ld->ssize) + 1;
		auto tail_size = csize
		               + nsize
					   + ssize
					   + vsize;
		if (tail_size + ld_len != l) {
			fprintf(stderr, "Malsized login package: got %d, expected %d\n", l, tail_size + ld_len);
			fprintf(stderr, "c %d + s %d + n %d + v %d = %d\n", csize, ssize, nsize, vsize, tail_size);
			// malformed pack
			print_malformed_udp_error();
			return;
		}
		auto spk_start = UDP_BUFFER + ld_len;
		auto cpk_start = spk_start + ssize;
		auto name_start = cpk_start + csize;
		auto sig_start = name_start + nsize;
		auto nsv = std::string_view((char *) name_start, nsize);
		auto ci = state.known_clients.find(nsv);
		if (ci == state.known_clients.end()) {
			// new client
			auto did = allocate_id();
			auto valid_until = req.valid_until; // allow bind packet field
			auto res = state.known_clients.emplace(
				std::piecewise_construct,
				std::forward_as_tuple(nsv),
				std::forward_as_tuple(
					spk_start, ssize,
					cpk_start, csize,
					valid_until,
					did,
					dip,
					dport
				)
			);
			ci = res.first;
			state.known_names.emplace(
				std::piecewise_construct,
				std::forward_as_tuple(did),
				std::forward_as_tuple(ci->first)
			);
			time_t vu = valid_until / 1000;
			fprintf(stderr, "New client %s on %s:%d, valid until %s\n", std::string(nsv).c_str(), inet_ntoa({dip}), ntohs(dport), ctime(&vu));
            // Send all data
			send_full(dip, dport, did, src);
            // done.
        } else {
			// old client
			if (crypto_sign_verify_detached(
					sig_start, 
					UDP_BUFFER, 
					sig_start - UDP_BUFFER, 
					ci->second.identity.data()
				) != 0) {
				// bad signed message
				// so no PK updates
				if (dip != ci->second.peer.ip
				 || dport != ci->second.peer.port
				 || csize != ci->second.cipher_pub.size()
				 || ssize != ci->second.identity.size()
				 || 0 != memcmp(cpk_start, ci->second.cipher_pub.data(), csize)
				 || 0 != memcmp(spk_start, ci->second.identity.data(), ssize)
				) {
					// Spoofing attempt!
					fprintf(stderr, "Spoofing attempt for %s!\n", ci->first.c_str());
					fprintf(stderr, "\told IP: %s:%d\n", inet_ntoa(in_addr { ci->second.peer.ip }), ci->second.peer.port);
					fprintf(stderr, "\tnew IP: %s:%d\n", inet_ntoa(in_addr { dip }), dport);
					fprintf(stderr, "\told SPK: ");
					for (auto c : ci->second.identity) {
						fprintf(stderr, "%02x", c);
					}
					fprintf(stderr, "\n\tnew SPK: ");
					for (auto i = spk_start; i < cpk_start; ++i) {
						fprintf(stderr, "%02x", *i);
					}
					fprintf(stderr, "\n\told CPK: ");
					for (auto c : ci->second.cipher_pub) {
						fprintf(stderr, "%02x", c);
					}
					fprintf(stderr, "\n\tnew CPK: ");
					for (auto i = cpk_start; i < name_start; ++i) {
						fprintf(stderr, "%02x", *i);
					}
					fprintf(stderr, "\n\tNot answered.\n");
					return;
				}
				fprintf(stderr, "Suspicious wrongly signed request for %s.\n", ci->first.c_str());
				// go on as long as the address and keys are same
			}
			ci->second.cipher_pub.assign(cpk_start, cpk_start + csize);
			ci->second.identity.assign(spk_start, spk_start + ssize);
			ci->second.peer.ip = dip;
			ci->second.peer.port = dport;
			ci->second.peer.valid_until = req.valid_until;
			// again, send all data
			send_full(dip, dport, ci->second.peer.id, src);
		}
		break;
	}
	case REQ_KEEP_ALIVE: {
		auto ka = reinterpret_cast<const keep_alive * const>(UDP_BUFFER + sizeof(request));
		auto ka_len = sizeof(request) + sizeof(keep_alive);
		if (vsize + ka_len != l) {
			fprintf(stderr, "Malsized keep alive package: got %d, expected %d\n", l, vsize + ka_len);
			// malformed pack
			print_malformed_udp_error();
			return;
		}
		auto iname = state.known_names.find(req.requestor_id);
		if (iname == state.known_names.end()) {
			fprintf(stderr, "req KA from unknown id %d\n", req.requestor_id);
			return;
		}
		auto iclient = state.known_clients.find(iname->second);
		if (iclient == state.known_clients.end()) {
			fprintf(stderr, "no client for id %d?!\n", req.requestor_id);
			return;
		}
		// Check credentials
		if ((iclient->second.identity.size() == 1 && iclient->second.identity[0] == 0) // identityless
		 || crypto_sign_verify_detached(
				UDP_BUFFER + ka_len, 
				UDP_BUFFER, ka_len, 
				iclient->second.identity.data()
			) == 0
		) {
			// All good
			iclient->second.peer.ip = dip;
			iclient->second.peer.port = dport;
			iclient->second.peer.valid_until = req.valid_until;
			send_update(dip, dport, req.requestor_id, src);
		} else {
			fprintf(stderr, "Got wrongly signed update request for %d\n", req.requestor_id);
		}
		break;
	}
	case REQ_REQ_IDS: {
		auto ri = reinterpret_cast<const request_ids * const>(UDP_BUFFER + sizeof(request));
		auto ri_len = sizeof(request) + sizeof(request_ids);
		auto ids_size_bytes = ri->size * sizeof(id_t);
		if (vsize + ids_size_bytes + ri_len != l) {
			fprintf(stderr, "Malsized request ids package: got %d, expected %d\n", l, vsize + ri_len + ids_size_bytes);
			// malformed pack
			print_malformed_udp_error();
			return;
		}
		auto idp = reinterpret_cast<const id_t * const>(UDP_BUFFER + ri_len);
		auto sig = UDP_BUFFER + ri_len + ids_size_bytes;
		auto iname2 = state.known_names.find(req.requestor_id);
		if (iname2 == state.known_names.end()) {
			fprintf(stderr, "req req ids from unknown id %d\n", req.requestor_id);
			return;
		}
		auto iclient2 = state.known_clients.find(iname2->second);
		if (iclient2 == state.known_clients.end()) {
			fprintf(stderr, "no client for id %d?!\n", req.requestor_id);
			return;
		}
		// Check credentials
		if ((iclient2->second.identity.size() == 1 && iclient2->second.identity[0] == 0) // identityless
		 || crypto_sign_verify_detached(
				sig, 
				UDP_BUFFER, ri_len + ids_size_bytes, 
				iclient2->second.identity.data()
			) == 0
		) {
			// All good
			iclient2->second.peer.ip = dip;
			iclient2->second.peer.port = dport;
			iclient2->second.peer.valid_until = req.valid_until;
			// auto filter = std::unordered_set<id_t>(idp, idp + ri->size, (size_t) ri->size);
			auto filter = std::unordered_set<id_t>();
			for (idp; idp < (void *) (UDP_BUFFER + ri_len + ids_size_bytes); idp += 1) {
				filter.insert(ntohl(*idp));
			}
			send_full(dip, dport, req.requestor_id, src, filter);
		} else {
			fprintf(stderr, "Got wrongly signed ids request for %d\n", req.requestor_id);
		}
		break;
	}
	default:
		print_malformed_udp_error();
		break;
	}
}

int init(
	const uint16_t port
) {
	state.sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if(state.sock < 0) {
		perror(NAME);
		return 1;
	}
	struct sockaddr_in addr = {
		AF_INET, htons(port), INADDR_ANY
	};
	int e = bind(state.sock, (struct sockaddr *)&addr, sizeof(addr));
	if(e) {
		perror(NAME);
		return 2;
	}
	if (sodium_init() == -1) {
		fprintf(stderr, "Cannot init NaCl\n");
		return 3;
	};
	return 0;
}

int main(int argc, char *argv[]) {
	int opt;
	int64_t port_raw = 0xAc0;
	while ((opt = getopt(argc, argv, "p:c:")) != -1) {
        switch (opt) {
            case 'p':
                port_raw = std::atoll(optarg);
                break;
            case 'c':
                state.cleaning_period_ms = std::atoll(optarg);
                break;
            default:
                fprintf(stderr, "Usage: %s [-p port (%d)] [-c cleaning period ms (%d)]\n", argv[0], port_raw, state.cleaning_period_ms);
                return 1;
        }
    }
	auto port = (uint16_t) port_raw;
	int e = init(port);
	if(e) {
		return e;
	}
	printf("Listening on port %d\n", port);
	while(1) {
		mainloop();
	}
}
