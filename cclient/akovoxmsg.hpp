#include "akomsgparser.h"

#include <string>
#include <unordered_map>
#include <variant>
#include <vector>
#include <functional>

namespace akovox {

class akovoxmsg;

typedef void(* compression_f)(std::vector<uint8_t> &);
typedef void(* crypto_f)(std::vector<uint8_t> &, const uint8_t *key, const size_t key_len);

inline std::string NO_TRANSFORM = "";
void noop(std::vector<uint8_t> &data);
void noop_c(std::vector<uint8_t> &data, const uint8_t *key, const size_t key_len);

inline std::string DEFLATE = "DEFLATE";
void compression_inflate(std::vector<uint8_t> &data);
void compression_deflate(std::vector<uint8_t> &data);

inline std::string ED25519 = "Ed25519";
void sign_ed25519(std::vector<uint8_t> &data, const uint8_t *key, const size_t key_len);
void verify_ed25519(std::vector<uint8_t> &data, const uint8_t *key, const size_t key_len);

inline std::string X25519XSalsa = "X25519 XSalsa20 Poly-1305";
void encrypt_sodium(std::vector<uint8_t> &data, const uint8_t *key, const size_t key_len);
void decrypt_sodium(std::vector<uint8_t> &data, const uint8_t *key, const size_t key_len);

// map[name] = (pack, unpack)
std::unordered_map<std::string_view, std::pair<compression_f, compression_f>> &get_compression_registry();

// map[name] = (sign, verify)
std::unordered_map<std::string_view, std::pair<crypto_f, crypto_f>> &get_signing_registry();

// map[name] = (encrypt, decrypt)
std::unordered_map<std::string_view, std::pair<crypto_f, crypto_f>> &get_encryption_registry();

class akovoxmsg {
private:
    akomsg_mtype _type;
    uint8_t _flags;
    uint32_t _protocol;
    uint64_t _msg_id;
    std::unordered_map<std::string, std::variant<int64_t, std::string> > _headers;
    std::vector<uint8_t> _data;
public:
    std::string _sender;
    std::string _receiver;

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
    inline uint8_t raw_flags() const noexcept;

    inline akomsg_mtype type() const noexcept;
    inline uint32_t protocol() const noexcept;
    inline uint64_t id() const noexcept;
    inline const std::string &sender() const noexcept;
    inline const std::string &receiver() const noexcept;
    inline const std::unordered_map<std::string, std::variant<int64_t, std::string> > &headers() const noexcept;
    inline const std::vector<uint8_t> &raw_data() const noexcept;

//     template <typename FCType, typename FSType, typename FEType>
// #if defined(__cpp_concepts) && __cpp_concepts >= 201907L
//     requires std::invocable<FCType, std::vector<uint8_t>&>
//           && std::invocable<FSType, std::vector<uint8_t>&>
//           && std::invocable<FEType, std::vector<uint8_t>&>
// #endif
    friend akovoxmsg &compress(
        akovoxmsg &msg,
        const std::string_view compression_name,
        const std::unordered_map<std::string_view, std::pair<compression_f, compression_f>> &registry// = get_compression_registry()
    );
    friend akovoxmsg &sign(
        akovoxmsg &msg,
        const std::string_view signing_name, const uint8_t *s_key, size_t s_key_len,
        const std::unordered_map<std::string_view, std::pair<crypto_f, crypto_f>> &registry// = get_signing_registry()
    );
    friend akovoxmsg &encrypt(
        akovoxmsg &msg,
        const std::string_view encryption_name, const uint8_t *e_key, size_t e_key_len,
        const std::unordered_map<std::string_view, std::pair<crypto_f, crypto_f>> &registry// = get_encryption_registry()
    );
    friend akovoxmsg &decrypt(
        akovoxmsg &msg,
        const uint8_t *e_key, size_t e_key_len,
        const std::unordered_map<std::string_view, std::pair<crypto_f, crypto_f>> &registry// = get_encryption_registry()
    );
    friend akovoxmsg &break_seal(
        akovoxmsg &msg,
        const uint8_t *s_key, size_t s_key_len,
        const std::unordered_map<std::string_view, std::pair<crypto_f, crypto_f>> &registry// = get_signing_registry()
    );
    friend akovoxmsg &decompress(
        akovoxmsg &msg,
        const std::unordered_map<std::string_view, std::pair<compression_f, compression_f>> &registry// = get_compression_registry()
    );
};
akovoxmsg &compress(
    akovoxmsg &msg,
    const std::string_view compression_name,
    const std::unordered_map<std::string_view, std::pair<compression_f, compression_f>> &registry = get_compression_registry()
);
akovoxmsg &sign(
    akovoxmsg &msg,
    const std::string_view signing_name, const uint8_t *s_key, size_t s_key_len,
    const std::unordered_map<std::string_view, std::pair<crypto_f, crypto_f>> &registry = get_signing_registry()
);
akovoxmsg &encrypt(
    akovoxmsg &msg,
    const std::string_view encryption_name, const uint8_t *e_key, size_t e_key_len,
    const std::unordered_map<std::string_view, std::pair<crypto_f, crypto_f>> &registry = get_encryption_registry()
);
akovoxmsg &decrypt(
    akovoxmsg &msg,
    const uint8_t *e_key, size_t e_key_len,
    const std::unordered_map<std::string_view, std::pair<crypto_f, crypto_f>> &registry = get_encryption_registry()
);
akovoxmsg &break_seal(
    akovoxmsg &msg,
    const uint8_t *s_key, size_t s_key_len,
    const std::unordered_map<std::string_view, std::pair<crypto_f, crypto_f>> &registry = get_signing_registry()
);
akovoxmsg &decompress(
    akovoxmsg &msg,
    const std::unordered_map<std::string_view, std::pair<compression_f, compression_f>> &registry = get_compression_registry()
);

akovoxmsg parse(const uint8_t * const data, uint32_t length);

size_t byte_length(const akovoxmsg &msg);
uint8_t *write(uint8_t *dest, const akovoxmsg &msg);

}