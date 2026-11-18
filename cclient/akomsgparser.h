#ifndef AKOMSG_PARSER_H
#define AKOMSG_PARSER_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    AKOMSG_TECH = 1,
    AKOMSG_INTER = 2,
    AKOMSG_TEXT = 3,
    AKOMSG_BIN = 4,
    AKOMSG_BIN_RAW = 5,
    AKOMSG_MAGNET = 6
} akomsg_mtype;

#define AKOMSG_IS_ENCRYPTED(X) (!!((X) & 0x04))
#define AKOMSG_IS_SIGNED(X) (!!((X) & 0x02))
#define AKOMSG_IS_COMPRESSED(X) (!!((X) & 0x01))

typedef struct str_slice {
    const char *p;
    size_t len;
} str_slice;

typedef union {
    uint32_t number;
    str_slice text;
} header_value;

#define AKOMSG_CONTINUE 0

typedef int (*akomsg_on_signature)(void *ctx, akomsg_mtype type, uint8_t flags, uint32_t proto_version);

typedef int (*akomsg_on_header_start)(void *ctx, uint64_t msg_id, str_slice sender, str_slice receiver);

typedef int (*akomsg_on_header_field_str)(void *ctx, str_slice name, str_slice value);
typedef int (*akomsg_on_header_field_int)(void *ctx, str_slice name, int64_t value);
typedef int (*akomsg_on_data)(void *ctx, const uint8_t *data, uint32_t length, uint32_t crc);

int parse(void *ctx, const uint8_t * const data, uint32_t length
        , akomsg_on_signature on_signature
        , akomsg_on_header_start on_header_start
        , akomsg_on_header_field_str on_header_field_str
        , akomsg_on_header_field_int on_header_field_int
        , akomsg_on_data on_data
        );

#ifdef __cplusplus
inline constexpr size_t signature_len = 8;
#else
static const size_t signature_len = 8;
#endif
uint8_t *write_signature(uint8_t *dest, const akomsg_mtype type, const uint8_t flags, const uint32_t proto_version);
size_t start_header_length(const size_t sender_len, const size_t receiver_len);
uint8_t *start_header(uint8_t *dest, const uint64_t msg_id, const str_slice sender, const str_slice receiver);
size_t header_field_length(const size_t name_len, const size_t value_len);
uint8_t *append_header_str(uint8_t *dest, const str_slice key, const str_slice value);
uint8_t *append_header_int(uint8_t *dest, const str_slice key, const int64_t value);
size_t data_length(const size_t data_len);
uint8_t *append_data(uint8_t *dest, const uint8_t *data, const size_t data_len);

uint32_t posix_crc32(const uint8_t *data, size_t data_len);

#ifdef __cplusplus
}
#endif

#endif
