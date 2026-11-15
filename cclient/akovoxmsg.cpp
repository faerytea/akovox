#include "akovoxmsg.hpp"

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

akovoxmsg parse(const uint8_t * const data, uint32_t length) {
    pointers ps;
    std::unordered_map<std::string, std::variant<int64_t, std::string> > headers;
    ps.m = &headers;
    auto res = parse(&ps, data, length, on_sig, on_hs, on_hrs, on_hri, on_data);
    if (res != 0) throw res;
    return akovoxmsg(ps.type, ps.flags, ps.proto, ps.id, 
                     std::string(ps.sender.p, ps.sender.len),
                     std::string(ps.receiver.p, ps.receiver.len),
                     headers,
                     std::vector<uint8_t>(ps.data, ps.data + ps.data_len)
                    );
}

inline bool akovoxmsg::is_encrypted() const noexcept {
    return AKOMSG_IS_ENCRYPTED(this->_flags);
}

inline bool akovoxmsg::is_signed() const noexcept {
    return AKOMSG_IS_SIGNED(this->_flags);
}

inline bool akovoxmsg::is_compressed() const noexcept {
    return AKOMSG_IS_COMPRESSED(this->_flags);
}


inline akomsg_mtype akovoxmsg::type() const noexcept {
    return this->_type;
}
inline uint32_t akovoxmsg::protocol() const noexcept {
    return this->_protocol;
}
inline uint64_t akovoxmsg::id() const noexcept {
    return this->_msg_id;
}
inline const std::string &akovoxmsg::sender() const noexcept {
    return this->_sender;
}
inline const std::string &akovoxmsg::receiver() const noexcept {
    return this->_receiver;
}
inline const std::unordered_map<std::string, std::variant<int64_t, std::string> > akovoxmsg::headers() const noexcept {
    return this->_headers;
}
inline const std::vector<uint8_t> akovoxmsg::raw_data() const noexcept {
    return this->_data;
}
