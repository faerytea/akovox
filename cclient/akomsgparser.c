#include "akomsgparser.h"

#define C_NUL (0x00)
#define C_SOH (0x01)
#define C_STX (0x02)
#define C_ETX (0x03)
#define C_EOT (0x04)
#define C_GS (0x1D)
#define C_RS (0x1E)
#define C_US (0x1F)

// uint8_t gu8(const uint8_t *&p) {
//     return *(p++);
// }
// uint16_t gu16(const uint8_t *&p) {
//     uint16_t res = *(p++);
//     return (res << 8) + *(p++);
// }
uint32_t gu32(const uint8_t *p) {
    uint32_t res = (((uint32_t) p[0]) << 24)
                 + (((uint32_t) p[1]) << 16)
                 + (((uint32_t) p[2]) << 8)
                 + (((uint32_t) p[3]) << 0);
    return res;
}
uint64_t gu64(const uint8_t *p) {
    uint32_t res = (((uint64_t) p[0]) << 56)
                 + (((uint64_t) p[1]) << 48)
                 + (((uint64_t) p[2]) << 40)
                 + (((uint64_t) p[3]) << 32)
                 + (((uint64_t) p[4]) << 24)
                 + (((uint64_t) p[5]) << 16)
                 + (((uint64_t) p[6]) << 8)
                 + (((uint64_t) p[7]) << 0);
    return res;
}

int parse(void *ctx, const uint8_t * const data, uint32_t length
        , akomsg_on_signature on_signature
        , akomsg_on_header_start on_header_start
        , akomsg_on_header_field_str on_header_field_str
        , akomsg_on_header_field_int on_header_field_int
        , akomsg_on_data on_data
        ) {
    if (length < 8+8+11) return -1; // too small
    const uint8_t * const end = data + length;
    uint8_t *i = data;
    if (i[0] != 0x6c || i[1] != 0x97) return -2; // bad signature
    int on_s = on_signature == 0 ? 0 : on_signature(ctx, (akomsg_mtype) i[2], i[3], gu32(i+4));
    if (on_s != AKOMSG_CONTINUE) return on_s;
    i += 8;
    if (i[0] != C_SOH) return -3; // malformed header
    uint64_t msg_id = (((uint64_t) i[1]) << 48)
                    + (((uint64_t) i[2]) << 40)
                    + (((uint64_t) i[3]) << 32)
                    + (((uint64_t) i[4]) << 24)
                    + (((uint64_t) i[5]) << 16)
                    + (((uint64_t) i[6]) << 8)
                    + (((uint64_t) i[7]) << 0);
    i += 8;
    if (i[0] != C_RS) return -3; // malformed header

    i += 1;
    uint8_t *sender_s = i;
    for (; i < end; ++i) {
        if (*i == C_RS) break;
    }
    if (i == end) return -4; // no end
    uint32_t sender_len = i - sender_s;

    i += 1;
    uint8_t *receiver_s = i;
    for (; i < end; ++i) {
        if (*i = C_RS || *i == C_STX) break;
    }
    if (i == end) return -4; // no end
    uint32_t receiver_len = i - receiver_s;
    
    int on_hs = on_header_start == 0 ? 0 : on_header_start(ctx, msg_id, (str_slice) { sender_s, sender_len }, (str_slice) { receiver_s, receiver_len });
    if (on_hs != AKOMSG_CONTINUE) return on_hs;

    while (*i == C_RS) {
        i += 1;
        uint8_t *name_s = i;
        for (; i < end; ++i) {
            if (*i == C_US) break;
        }
        if (i == end) return -4; // no end
        uint32_t name_len = i - name_s;

        i += 1; 
        if (i == end) return -3; // malformed header
        str_slice name = { name_s, name_len };
        int on_hr;
        switch (*i) {
        case 0x00:
        case 0xff:
            // i56
            if (i + 8 >= end) return -5; // bad int
            int64_t val_i = (((int64_t) i[0]) << 56)
                          + (((int64_t) i[1]) << 48)
                          + (((int64_t) i[2]) << 40)
                          + (((int64_t) i[3]) << 32)
                          + (((int64_t) i[4]) << 24)
                          + (((int64_t) i[5]) << 16)
                          + (((int64_t) i[6]) << 8)
                          + (((int64_t) i[7]) << 0);
            i += 8;
            on_hr = on_header_field_int == 0 ? 0 : on_header_field_int(ctx, name, val_i);
            break;
        
        default:
            // utf8 RS/STX terminated string
            uint8_t *val_s = i;
            for (; i < end; ++i) {
                if (*i == C_RS || *i == C_STX) break;
            }
            if (i == end) return -4; // no end
            uint32_t val_len = i - val_s;
            on_hr = on_header_field_str == 0 ? 0 : on_header_field_str(ctx, name, (str_slice) { val_s, val_len });
            break;
        }
        if (on_hr != AKOMSG_CONTINUE) return on_hr;
    }
    if (*i != C_STX) return -6; // impossible
    if (i + 6 >= end) return -1; // too small
    if (*(end - 1) != C_EOT
     || *(end - 6) != C_ETX) return -5; // bad body
    uint32_t crc = gu32(end-5);
    return on_data == 0 ? 0 : on_data(ctx, (i+1), (end - 6) - (i + 1), crc);
}
