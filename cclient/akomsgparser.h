#include <inttypes.h>

typedef enum {
    AKOMSG_TECH = 1,
    AKOMSG_INTER = 2,
    AKOMSG_TEXT = 3,
    AKOMSG_BIN = 4,
    AKOMSG_BIN_RAW = 5,
    AKOMSG_MAGNET = 6
} akomsg_mtype;

#define AKOMSG_IS_ENCRYPTED(X) (!!((X) & 0x01))
#define AKOMSG_IS_SIGNED(X) (!!((X) & 0x02))
#define AKOMSG_IS_COMPRESSED(X) (!!((X) & 0x04))

typedef struct str_slice {
    const char *p;
    uint32_t len;
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
