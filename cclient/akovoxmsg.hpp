#ifndef AKOVOXMSG_HPP
#define AKOVOXMSG_HPP
#include "akomsgparser.h"

#include <string>
#include <unordered_map>
#include <variant>
#include <vector>
#include <functional>

namespace akovox {

namespace fastconcat {
    inline std::string_view as_view(const std::string& s) noexcept { return s; }
    inline std::string_view as_view(std::string_view s) noexcept { return s; }

    template <std::size_t N>
    constexpr std::string_view as_view(const char (&s)[N]) noexcept {
        // Exclude the terminating null character for string literals.
        return {s, N - 1};
    }

    inline std::string_view as_view(const char* s) noexcept {
        return s ? std::string_view{s} : std::string_view{};
    }

    template <typename... Args>
    std::string concat(const Args&... args) {
        const std::size_t total_size =
            (std::size_t{0} + ... + as_view(args).size());

        std::string result;
        result.reserve(total_size);

        (result.append(as_view(args)), ...);

        return result;
    }

} // namespace fastconcat

class exception : public std::exception {
protected:
    std::string _message;

public:
    explicit exception(std::string msg) : _message(std::move(msg)) {}

    const char* what() const noexcept override {
        return _message.c_str();
    }
};

class impossible : public exception {
public:
    explicit impossible(std::string msg): exception("This must never happen: " + std::move(msg)) {};
};

class compression_exception : public exception {
public:
    explicit compression_exception(std::string msg): exception("Cannot compress / decompress: " + std::move(msg)) {};
};

class signature_exception : public exception {
public:
    explicit signature_exception(std::string msg): exception("Cannot sign / verify: " + std::move(msg)) {};
};

class encryption_exception : public exception {
public:
    explicit encryption_exception(std::string msg): exception("Cannot encrypt / decrypt: " + std::move(msg)) {};
};

class malformed_msg_exception : public exception {
public:
    explicit malformed_msg_exception(std::string msg): exception("Malformed message: " + std::move(msg)) {};
};

class unknown_algorythm : public exception {
public:
    const std::string_view algo;

    explicit unknown_algorythm(std::string_view algo): 
    exception(fastconcat::concat("Unknown algorythm '", algo, "'")), algo(algo) {};
};

class illegal_state : public exception {
public:
    explicit illegal_state(std::string msg): exception("Illegal state: " + std::move(msg)) {};
};

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

    inline bool is_compressed() const noexcept {
        return AKOMSG_IS_COMPRESSED(this->_flags);
    }
    inline bool is_signed() const noexcept {
        return AKOMSG_IS_SIGNED(this->_flags);
    }
    inline bool is_encrypted() const noexcept {
        return AKOMSG_IS_ENCRYPTED(this->_flags);
    }
    inline uint8_t raw_flags() const noexcept {
        return this->_flags;
    }

    inline akomsg_mtype type() const noexcept {
        return this->_type;
    }
    inline uint32_t protocol() const noexcept {
        return this->_protocol;
    }
    inline uint64_t id() const noexcept {
        return this->_msg_id;
    }
    inline const std::string &sender() const noexcept {
        return this->_sender;
    }
    inline const std::string &receiver() const noexcept {
        return this->_receiver;
    }
    inline const std::unordered_map<std::string, std::variant<int64_t, std::string> > &headers() const noexcept {
        return this->_headers;
    }
    inline const std::vector<uint8_t> &raw_data() const noexcept {
        return this->_data;
    }

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

#endif
