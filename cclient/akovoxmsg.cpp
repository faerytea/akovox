#include "akovoxmsg.hpp"

#include "zlib.h"
#include <sodium.h>

using namespace akovox;

akovoxmsg::akovoxmsg(akomsg_mtype type
                   , uint8_t flags
                   , uint32_t protocol
                   , uint64_t msg_id
                   , std::string sender
                   , std::string receiver
                   , std::unordered_map<std::string, std::variant<int64_t, std::string> > headers
                   , std::vector<uint8_t> data
                   ) 
                   : _type(type)
                   , _flags(flags)
                   , _protocol(protocol)
                   , _msg_id(msg_id)
                   , _sender(std::move(sender))
                   , _receiver(std::move(receiver))
                   , _headers(std::move(headers))
                   , _data(std::move(data))
                   {};

struct pointers {
    akomsg_mtype type;
    uint8_t flags;
    uint32_t proto;
    uint64_t id;
    str_slice sender;
    str_slice receiver;
    std::unordered_map<std::string, std::variant<int64_t, std::string> > *m;
    const uint8_t *data;
    size_t data_len;
    uint32_t crc;
};

int on_sig(void *ctx, akomsg_mtype type, uint8_t flags, uint32_t proto_version) {
    auto ps = reinterpret_cast<pointers *>(ctx);
    ps->type = type;
    ps->flags = flags;
    ps->proto = proto_version;
    return AKOMSG_CONTINUE;
}

int on_hs(void *ctx, uint64_t msg_id, str_slice sender, str_slice receiver) {
    auto ps = reinterpret_cast<pointers *>(ctx);
    ps->id = msg_id;
    ps->sender = sender;
    ps->receiver = receiver;
    return AKOMSG_CONTINUE;
}

int on_hrs(void *ctx, str_slice name, str_slice value) {
    auto ps = reinterpret_cast<pointers *>(ctx);
    ps->m->emplace(
        std::piecewise_construct,
        std::forward_as_tuple(name.p, name.len),
        std::forward_as_tuple(std::in_place_type<std::string>, value.p, value.len)
    );
    return AKOMSG_CONTINUE;
}

int on_hri(void *ctx, str_slice name, int64_t value) {
    auto ps = reinterpret_cast<pointers *>(ctx);
    ps->m->emplace(
        std::piecewise_construct,
        std::forward_as_tuple(name.p, name.len),
        std::forward_as_tuple(std::in_place_type<int64_t>, value)
    );
    return AKOMSG_CONTINUE;
}

int on_data(void *ctx, const uint8_t *data, uint32_t length, uint32_t crc) {
    auto ps = reinterpret_cast<pointers *>(ctx);
    ps->data = data;
    ps->data_len = length;
    ps->crc = crc;
    return AKOMSG_CONTINUE;
}

akovoxmsg akovox::parse(const uint8_t * const data, uint32_t length) {
    pointers ps;
    std::unordered_map<std::string, std::variant<int64_t, std::string> > headers;
    ps.m = &headers;
    auto res = parse(&ps, data, length, on_sig, on_hs, on_hrs, on_hri, on_data);
    switch (res) {
    case 0:
        [[likely]]
        break; // OK
    case -1:
        throw malformed_msg_exception("Message is too small");
    case -2:
        throw malformed_msg_exception(fastconcat::concat("Bad signature: ", data[0], data[1]));
    case -3:
        throw malformed_msg_exception("Malformed header");
    case -4:
        throw malformed_msg_exception("Unbounded string");
    case -5:
        throw malformed_msg_exception("Unfinished i56 field");
    case -6:
        throw malformed_msg_exception("Mangled body");
    default:
        throw impossible("'parse' returned nonz " + std::to_string(res));
    }
    auto ccrc = posix_crc32(ps.data, ps.data_len);
    if (ccrc != ps.crc) 
        throw malformed_msg_exception(
            "bad CRC: provided " + std::to_string(ps.crc) + " calculated " + std::to_string(ccrc)
        );
    return akovoxmsg(ps.type, ps.flags, ps.proto, ps.id, 
                     std::string(ps.sender.p, ps.sender.len),
                     std::string(ps.receiver.p, ps.receiver.len),
                     headers,
                     std::vector<uint8_t>(ps.data, ps.data + ps.data_len)
                    );
}

size_t akovox::byte_length(const akovoxmsg &msg) {
    size_t res = signature_len;
    res += start_header_length(msg.sender().length(), msg.receiver().length());
    for (auto &e : msg.headers()) {
        res += header_field_length(
            e.first.length(),
            std::holds_alternative<int64_t>(e.second) ? 8 : std::get<std::string>(e.second).length()
        );
    }
    return res + data_length(msg.raw_data().size());
}

struct header_field_writer {
    const std::string *name;
    uint8_t *dest;

    uint8_t *operator()(int64_t idata) {
        return append_header_int(dest, { name->data(), name->length() }, idata);
    }

    uint8_t *operator()(const std::string &sdata) {
        return append_header_str(dest, { name->data(), name->length() }, { sdata.data(), sdata.length() });
    }
};

uint8_t *akovox::write(uint8_t *dest, const akovoxmsg &msg) {
    dest = write_signature(dest, msg.type(), msg.raw_flags(), msg.protocol());
    dest = start_header(dest, msg.id(), { msg.sender().data(), msg.sender().length() }, { msg.receiver().data(), msg.receiver().length() });
    for (auto &e : msg.headers()) {
        dest = std::visit(header_field_writer { &e.first, dest }, e.second);
    }
    return append_data(dest, msg.raw_data().data(), msg.raw_data().size());
}

std::unordered_map<std::string_view, std::pair<compression_f, compression_f>> &akovox::get_compression_registry() {
    static std::unordered_map<std::string_view, std::pair<compression_f, compression_f>> map = []() {
        std::unordered_map<std::string_view, std::pair<compression_f, compression_f>> map;
        map[NO_TRANSFORM] = std::make_pair(noop, noop);
        map[DEFLATE] = std::make_pair(compression_deflate, compression_inflate);
        return map;
    }();
    return map;
}

std::unordered_map<std::string_view, std::pair<crypto_f, crypto_f>> &akovox::get_signing_registry() {
    static std::unordered_map<std::string_view, std::pair<crypto_f, crypto_f>> map = []() {
        std::unordered_map<std::string_view, std::pair<crypto_f, crypto_f>> map;
        map[NO_TRANSFORM] = std::make_pair(noop_c, noop_c);
        map[ED25519] = std::make_pair(sign_ed25519, verify_ed25519);
        return map;
    }();
    return map;
}

std::unordered_map<std::string_view, std::pair<crypto_f, crypto_f>> &akovox::get_encryption_registry() {
    static std::unordered_map<std::string_view, std::pair<crypto_f, crypto_f>> map = []() {
        std::unordered_map<std::string_view, std::pair<crypto_f, crypto_f>> map;
        map[NO_TRANSFORM] = std::make_pair(noop_c, noop_c);
        map[X25519XSalsa] = std::make_pair(encrypt_sodium, decrypt_sodium);
        return map;
    }();
    return map;
}

void akovox::noop(std::vector<uint8_t> &data) {}
void akovox::noop_c(std::vector<uint8_t> &data, const uint8_t *key, const size_t key_len) {}

class zlib_exception : public compression_exception {
public:
    explicit zlib_exception(std::string where, int zlib_code): 
    compression_exception("ZLib error: " + std::move(where) + " returned " + std::to_string(zlib_code)) {};
};

void akovox::compression_deflate(std::vector<uint8_t> &data) {
    z_stream s;
    s.zalloc = Z_NULL;
    s.zfree = Z_NULL;
    s.opaque = Z_NULL;
    int z_init = deflateInit2(&s, 9, Z_DEFLATED, -15, 9, Z_DEFAULT_STRATEGY);
    if (z_init != Z_OK) throw zlib_exception("deflateInit2", z_init);
    s.avail_in = data.size();
    s.next_in = data.data();
    std::vector<uint8_t> compressed((size_t) deflateBound(&s, data.size()));
    s.avail_out = compressed.size();
    s.next_out = compressed.data();
    auto def_res = deflate(&s, Z_FINISH);
    if (def_res != Z_STREAM_END) throw zlib_exception("deflate", def_res);
    compressed.resize(compressed.size() - s.avail_out);
    deflateEnd(&s);
    data.swap(compressed);
}

void akovox::compression_inflate(std::vector<uint8_t> &data) {
    z_stream s;
    s.zalloc = Z_NULL;
    s.zfree = Z_NULL;
    s.opaque = Z_NULL;
    int z_init = inflateInit2(&s, -15);
    if (z_init != Z_OK) throw zlib_exception("inflateInit2", z_init);
    s.avail_in = data.size();
    s.next_in = data.data();
    std::vector<uint8_t> decompressed(data.size() << 1);
    size_t have = 0;
    do {
        s.avail_out = decompressed.size() - have;
        s.next_out = decompressed.data() + have;
        auto inf_ret = inflate(&s, Z_NO_FLUSH);
        if (inf_ret == Z_NEED_DICT || inf_ret == Z_DATA_ERROR || inf_ret == Z_MEM_ERROR)
            throw zlib_exception("deflate", inf_ret);
        have = decompressed.size() - s.avail_out;
        if (inf_ret == Z_STREAM_END) break;
        if ((have << 1) > decompressed.size()) {
            decompressed.resize(decompressed.size() << 1);
        }
    } while (1);
    decompressed.resize(have);
    inflateEnd(&s);
    data.swap(decompressed);
}

void akovox::sign_ed25519(std::vector<uint8_t> &data, const uint8_t *key, const size_t key_len) {
    auto si = sodium_init();
    if (si < 0) throw signature_exception("cannot init libsodium: " + std::to_string(si));
    auto data_len = data.size();
    data.resize(data_len + crypto_sign_BYTES);
    auto s_r = crypto_sign_ed25519_detached(data.data() + data_len, NULL, data.data(), data_len, key);
    if (s_r != 0) throw signature_exception("cannot sign: " + std::to_string(s_r));
}
void akovox::verify_ed25519(std::vector<uint8_t> &data, const uint8_t *key, const size_t key_len) {
    auto si = sodium_init();
    if (si < 0) throw signature_exception("cannot init libsodium: " + std::to_string(si));
    auto data_len = data.size() - crypto_sign_BYTES;
    auto v_r = crypto_sign_ed25519_verify_detached(data.data() + data_len, data.data(), data_len, key);
    if (v_r != 0) throw signature_exception("bad signature: " + std::to_string(v_r));
    data.resize(data_len);
}
static_assert(
    std::string_view(crypto_box_PRIMITIVE) ==
    "curve25519xsalsa20poly1305"
);
void akovox::encrypt_sodium(std::vector<uint8_t> &data, const uint8_t *key, const size_t key_len) {
    auto si = sodium_init();
    if (si < 0) throw encryption_exception("cannot init libsodium: " + std::to_string(si));
    // if (data.size() < 32) data.resize(32, 0);
    std::vector<uint8_t> result(data.size() + crypto_box_curve25519xsalsa20poly1305_MACBYTES + crypto_box_curve25519xsalsa20poly1305_NONCEBYTES);
    uint8_t *nonce_p = result.data() + data.size() + crypto_box_curve25519xsalsa20poly1305_MACBYTES;
    randombytes_buf(nonce_p, crypto_box_curve25519xsalsa20poly1305_NONCEBYTES);
    auto c_r = crypto_box_easy_afternm(result.data(), data.data(), data.size(), nonce_p, key);
    if (c_r != 0) throw encryption_exception("cannot encrypt: " + std::to_string(c_r));
    data.swap(result);
}
void akovox::decrypt_sodium(std::vector<uint8_t> &data, const uint8_t *key, const size_t key_len) {
    auto si = sodium_init();
    if (si < 0) throw encryption_exception("cannot init libsodium: " + std::to_string(si));
    std::vector<uint8_t> result(data.size() - crypto_box_curve25519xsalsa20poly1305_NONCEBYTES - crypto_box_curve25519xsalsa20poly1305_MACBYTES);
    uint8_t *nonce_p = data.data() + (data.size() - crypto_box_curve25519xsalsa20poly1305_NONCEBYTES);
    auto c_r = crypto_box_open_easy_afternm(result.data(), data.data(), data.size() - crypto_box_curve25519xsalsa20poly1305_NONCEBYTES, nonce_p, key);
    if (c_r != 0) throw encryption_exception("cannot decrypt: " + std::to_string(c_r));
    data.swap(result);
}

bool flag_is_highest(uint8_t flag, uint8_t flags) {
    return ((flag << 1) - 1) >= flags && ((flag & flags) != 0);
}

akovoxmsg &akovox::compress(
    akovoxmsg &msg,
    const std::string_view compression_name,
    const std::unordered_map<std::string_view, std::pair<compression_f, compression_f>> &registry// = get_compression_registry()
) {
    if (msg.raw_flags() != 0) throw illegal_state("trying to compress modified body (f:" + std::to_string(msg.raw_flags()) + ")");
    auto it = registry.find(compression_name);
    if (it == registry.end()) throw unknown_algorythm(compression_name);
    it->second.first(msg._data);
    if (it->first != DEFLATE) {
        msg._headers.emplace(
            std::piecewise_construct,
            std::forward_as_tuple("C"),
            std::forward_as_tuple(std::in_place_type<std::string>, compression_name)
        );
    }
    msg._flags |= 0x01;
    return msg;
}

akovoxmsg &akovox::sign(
    akovoxmsg &msg,
    const std::string_view signing_name, const uint8_t *s_key, size_t s_key_len,
    const std::unordered_map<std::string_view, std::pair<crypto_f, crypto_f>> &registry
) {
    if (msg.raw_flags() >= 0x02) throw illegal_state("trying to sign modified body (f:" + std::to_string(msg.raw_flags()) + ")");
    auto it = registry.find(signing_name);
    if (it == registry.end()) throw unknown_algorythm(signing_name);
    it->second.first(msg._data, s_key, s_key_len);
    if (it->first != ED25519) {
        msg._headers.emplace(
            std::piecewise_construct,
            std::forward_as_tuple("S"),
            std::forward_as_tuple(std::in_place_type<std::string>, signing_name)
        );
    }
    msg._flags |= 0x02;
    return msg;
}

akovoxmsg &akovox::encrypt(
    akovoxmsg &msg,
    const std::string_view encryption_name, const uint8_t *e_key, size_t e_key_len,
    const std::unordered_map<std::string_view, std::pair<crypto_f, crypto_f>> &registry
) {
    if (msg.raw_flags() >= 0x04) throw illegal_state("trying to encrypt modified body (f:" + std::to_string(msg.raw_flags()) + ")");
    auto it = registry.find(encryption_name);
    if (it == registry.end()) throw unknown_algorythm(encryption_name);
    it->second.first(msg._data, e_key, e_key_len);
    if (it->first != X25519XSalsa) {
        msg._headers.emplace(
            std::piecewise_construct,
            std::forward_as_tuple("E"),
            std::forward_as_tuple(std::in_place_type<std::string>, encryption_name)
        );
    }
    msg._flags |= 0x04;
    return msg;
}

akovoxmsg &akovox::decrypt(
    akovoxmsg &msg,
    const uint8_t *e_key, size_t e_key_len,
    const std::unordered_map<std::string_view, std::pair<crypto_f, crypto_f>> &registry
) {
    if (!msg.is_encrypted()) return msg;
    if (!flag_is_highest(0x04, msg.raw_flags())) 
        throw illegal_state("trying to decrypt modified body (f:" + std::to_string(msg.raw_flags()) + ")");
    auto encryption_header = msg.headers().find("E");
    std::string_view encryption_name = X25519XSalsa;
    if (encryption_header != msg.headers().end()) {
        auto &v = encryption_header->second;
        if (std::holds_alternative<std::string>(v)) {
            encryption_name = std::string_view(std::get<std::string>(v));
        } else {
            throw malformed_msg_exception("value of header 'E' is not a string, it is " + std::to_string(std::get<int64_t>(v)));
        }
    }
    auto it = registry.find(encryption_name);
    if (it == registry.end()) throw unknown_algorythm(encryption_name);
    it->second.second(msg._data, e_key, e_key_len);
    msg._flags &= ~(0x04);
    return msg;
}

akovoxmsg &akovox::break_seal(
    akovoxmsg &msg,
    const uint8_t *s_key, size_t s_key_len,
    const std::unordered_map<std::string_view, std::pair<crypto_f, crypto_f>> &registry
) {
    if (!msg.is_signed()) return msg;
    if (!flag_is_highest(0x02, msg.raw_flags()))
        throw illegal_state("trying to unseal modified body (f:" + std::to_string(msg.raw_flags()) + ")");
    auto signing_header = msg.headers().find("S");
    std::string_view signing_name = ED25519;
    if (signing_header != msg.headers().end()) {
        auto &v = signing_header->second;
        if (std::holds_alternative<std::string>(v)) {
            signing_name = std::string_view(std::get<std::string>(v));
        } else {
            throw malformed_msg_exception("value of header 'S' is not a string, it is " + std::to_string(std::get<int64_t>(v)));
        }
    }
    auto it = registry.find(signing_name);
    if (it == registry.end()) throw unknown_algorythm(signing_name);
    it->second.second(msg._data, s_key, s_key_len);
    msg._flags &= ~(0x02);
    return msg;
}

akovoxmsg &akovox::decompress(
    akovoxmsg &msg,
    const std::unordered_map<std::string_view, std::pair<compression_f, compression_f>> &registry
) {
    if (!msg.is_compressed()) return msg;
    if (!flag_is_highest(0x01, msg.raw_flags()))
        throw illegal_state("trying to decompress modified body (f:" + std::to_string(msg.raw_flags()) + ")");;
    auto compression_header = msg.headers().find("C");
    std::string_view compression_name = DEFLATE;
    if (compression_header != msg.headers().end()) {
        auto &v = compression_header->second;
        if (std::holds_alternative<std::string>(v)) {
            compression_name = std::string_view(std::get<std::string>(v));
        } else {
            throw malformed_msg_exception("value of header 'C' is not a string, it is " + std::to_string(std::get<int64_t>(v)));
        }
    }
    auto it = registry.find(compression_name);
    if (it == registry.end()) throw unknown_algorythm(compression_name);
    it->second.second(msg._data);
    msg._flags &= ~(0x01);
    return msg;
}
