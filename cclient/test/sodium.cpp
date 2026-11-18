#include <sodium.h>
#include "../akovoxmsg.hpp"
#include <cstdio>

void dump(const std::vector<uint8_t> &data) {
    for (auto b : data) {
        fprintf(stderr, "%02x ", b);
    }
    fprintf(stderr, "\n");
}

void dump(const unsigned char *data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        fprintf(stderr, "%02x ", data[i]);
    }
    fprintf(stderr, "\n");
}

int main(int argc, char *argv[]) {
    sodium_init();
    auto cstr = argc == 1 ? argv[0] : argv[1];
    auto sstr = std::string(cstr);
    auto vstr = std::vector<uint8_t>((uint8_t *) cstr, ((uint8_t *) cstr) + sstr.length());
    akovox::akovoxmsg msg(AKOMSG_TEXT, 0, 1, 17, "Alice", "Bob", std::unordered_map<std::string, std::variant<int64_t, std::string> >(), vstr);
    unsigned char apk[crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES], 
                  ask[crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES], 
                  bpk[crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES], 
                  bsk[crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES], 
                  sak[crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES],
                  sbk[crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES];
    crypto_box_curve25519xsalsa20poly1305_keypair(apk, ask);
    crypto_box_curve25519xsalsa20poly1305_keypair(bpk, bsk);
    crypto_box_curve25519xsalsa20poly1305_beforenm(sak, bpk, ask);
    crypto_box_curve25519xsalsa20poly1305_beforenm(sbk, apk, bsk);
    fprintf(stderr, "Alice PK: ");
    dump(apk, crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES);
    fprintf(stderr, "Alice SK: ");
    dump(ask, crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES);
    fprintf(stderr, "Bob   PK: ");
    dump(bpk, crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES);
    fprintf(stderr, "Bob   SK: ");
    dump(bsk, crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES);
    fprintf(stderr, "Alice  K: ");
    dump(sak, crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES);
    fprintf(stderr, "Bob    K: ");
    dump(sbk, crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES);
    fprintf(stderr, "Message: %s\n", cstr);
    fprintf(stderr, "Message bytes: ");
    dump(vstr);
    // akovox::encrypt(msg, akovox::X25519XSalsa, sak, crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES);
    akovox::encrypt_sodium(vstr, sak, crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES);
    fprintf(stderr, "Encrypted bytes: ");
    dump(vstr);
    // dump(msg.raw_data());
    // akovox::decrypt(msg, sbk, crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES);
    akovox::decrypt_sodium(vstr, sbk, crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES);
    fprintf(stderr, "Decrypted bytes: ");
    dump(vstr);
    // dump(msg.raw_data());
    std::string dstr = std::string((const char *) msg.raw_data().data(), msg.raw_data().size());
    fprintf(stderr, "Decoded message: %s\n", dstr.c_str());
    return 0;
}