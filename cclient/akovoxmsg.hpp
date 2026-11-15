#include "akomsgparser.h"

#include <string>
#include <unordered_map>
#include <variant>
#include <vector>

namespace akovox {

class akovoxmsg {
private:
    akomsg_mtype _type;
    uint8_t _flags;
    uint32_t _protocol;
    uint64_t _msg_id;
    std::string _sender;
    std::string _receiver;
    std::unordered_map<std::string, std::variant<int64_t, std::string> > _headers;
    std::vector<uint8_t> _data;
public:

    // All arg ctor
    akovoxmsg(akomsg_mtype type
            , uint8_t flags
            , uint32_t protocol
            , uint64_t msg_id
            , std::string sender
            , std::string receiver
            , std::unordered_map<std::string, std::variant<int64_t, std::string> > headers
            , std::vector<uint8_t> data
            );
    // ~akovoxmsg();

    inline bool is_compressed() const noexcept;
    inline bool is_signed() const noexcept;
    inline bool is_encrypted() const noexcept;

    inline akomsg_mtype type() const noexcept;
    inline uint32_t protocol() const noexcept;
    inline uint64_t id() const noexcept;
    inline const std::string &sender() const noexcept;
    inline const std::string &receiver() const noexcept;
    inline const std::unordered_map<std::string, std::variant<int64_t, std::string> > headers() const noexcept;
    inline const std::vector<uint8_t> raw_data() const noexcept;
};

akovoxmsg parse(const uint8_t * const data, uint32_t length);

}