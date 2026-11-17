#include "akomsgparser.h"
#include <string.h>

#define C_NUL (0x00)
#define C_SOH (0x01)
#define C_STX (0x02)
#define C_ETX (0x03)
#define C_EOT (0x04)
#define C_GS (0x1D)
#define C_RS (0x1E)
#define C_US (0x1F)

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
    const uint8_t *i = data;
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
    const uint8_t *sender_s = i;
    for (; i < end; ++i) {
        if (*i == C_RS) break;
    }
    if (i == end) return -4; // no end
    uint32_t sender_len = i - sender_s;

    i += 1;
    const uint8_t *receiver_s = i;
    for (; i < end; ++i) {
        if (*i == C_RS || *i == C_STX) break;
    }
    if (i == end) return -4; // no end
    uint32_t receiver_len = i - receiver_s;
    
    int on_hs = on_header_start == 0 ? 0 : on_header_start(ctx, msg_id, (str_slice) { (const char *) sender_s, sender_len }, (str_slice) { (const char *) receiver_s, receiver_len });
    if (on_hs != AKOMSG_CONTINUE) return on_hs;

    while (*i == C_RS) {
        i += 1;
        const uint8_t *name_s = i;
        for (; i < end; ++i) {
            if (*i == C_US) break;
        }
        if (i == end) return -4; // no end
        uint32_t name_len = i - name_s;

        i += 1; 
        if (i == end) return -3; // malformed header
        str_slice name = { (const char *) name_s, name_len };
        int on_hr;
        switch (*i) {
        case 0x00:
        case 0xff: {
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
        }
        default: {
            // utf8 RS/STX terminated string
            const uint8_t *val_s = i;
            for (; i < end; ++i) {
                if (*i == C_RS || *i == C_STX) break;
            }
            if (i == end) return -4; // no end
            uint32_t val_len = i - val_s;
            on_hr = on_header_field_str == 0 ? 0 : on_header_field_str(ctx, name, (str_slice) { (const char *) val_s, val_len });
            break;
        }
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

uint8_t *write_signature(uint8_t *dest, const akomsg_mtype type, const uint8_t flags, const uint32_t proto_version) {
    dest[0] = 0x6C;
    dest[1] = 0x97;
    dest[2] = type;
    dest[3] = flags;
    dest[4] = (proto_version >> 24) & 0xff;
    dest[5] = (proto_version >> 16) & 0xff;
    dest[6] = (proto_version >>  8) & 0xff;
    dest[7] = (proto_version >>  0) & 0xff;
    return dest + 8;
}
size_t start_header_length(const size_t sender_len, const size_t receiver_len) {
    return sender_len + receiver_len + 10;
}
uint8_t *start_header(uint8_t *dest, const uint64_t msg_id, const str_slice sender, const str_slice receiver) {
    if ((msg_id & 0xff00000000000000) != 0) return 0;
    dest[0] = C_SOH;
    dest[1] = (msg_id >> 48) & 0xff;
    dest[2] = (msg_id >> 40) & 0xff;
    dest[3] = (msg_id >> 32) & 0xff;
    dest[4] = (msg_id >> 24) & 0xff;
    dest[5] = (msg_id >> 16) & 0xff;
    dest[6] = (msg_id >>  8) & 0xff;
    dest[7] = (msg_id >>  0) & 0xff;
    dest[8] = C_RS;
    dest += 9;
    memcpy(dest, (const uint8_t *) sender.p, sender.len);
    dest += sender.len;
    (*dest) = C_RS;
    dest += 1;
    memcpy(dest, (const uint8_t *) receiver.p, receiver.len);
    return dest + receiver.len;
}
size_t header_field_length(const size_t name_len, const size_t value_len) {
    return name_len + value_len + 2;
}
uint8_t *append_header_str(uint8_t *dest, const str_slice key, const str_slice value) {
    dest[0] = C_RS;
    memcpy(dest, (const uint8_t *) key.p, key.len);
    dest += key.len;
    (*dest) = C_RS;
    dest += 1;
    memcpy(dest, (const uint8_t *) value.p, value.len);
    dest += value.len;
    return dest;
}
uint8_t *append_header_int(uint8_t *dest, const str_slice key, const int64_t value) {
    if (value > 0x00ffffffffffffff || value < 0xff00000000000000) return 0;
    dest[0] = C_RS;
    memcpy(dest, (const uint8_t *) key.p, key.len);
    dest += key.len;
    (*dest) = C_RS;
    dest += 1;
    const uint64_t wvalue = (uint64_t) value;
    dest[0] = (wvalue >> 56) & 0xff;
    dest[1] = (wvalue >> 48) & 0xff;
    dest[2] = (wvalue >> 40) & 0xff;
    dest[3] = (wvalue >> 32) & 0xff;
    dest[4] = (wvalue >> 24) & 0xff;
    dest[5] = (wvalue >> 16) & 0xff;
    dest[6] = (wvalue >>  8) & 0xff;
    dest[7] = (wvalue >>  0) & 0xff;
    return dest + 8;
}
size_t data_length(const size_t data_len) {
    return data_len + 7;
}
uint8_t *append_data(uint8_t *dest, const uint8_t *data, const size_t data_len) {
    if (__builtin_expect((data + data_len <= dest) || (dest + data_len + 7 <= data), 0)) {
        return 0;
    }
    dest[0] = C_STX;
    dest += 1;
    if (dest != data) {
        memcpy(dest, data, data_len);
    }
    const uint32_t crc = posix_crc32(dest, data_len);
    dest += data_len;
    (*dest) = C_ETX;
    dest += 1;
    dest[0] = (crc >> 24) & 0xff;
    dest[1] = (crc >> 16) & 0xff;
    dest[2] = (crc >>  8) & 0xff;
    dest[3] = (crc >>  0) & 0xff;
    dest += 4;
    (*dest) = C_EOT;
    return dest + 1;
}

static const uint32_t crc_table[256] = {
        0x00000000,
        0x04c11db7, 0x09823b6e, 0x0d4326d9, 0x130476dc, 0x17c56b6b,
        0x1a864db2, 0x1e475005, 0x2608edb8, 0x22c9f00f, 0x2f8ad6d6,
        0x2b4bcb61, 0x350c9b64, 0x31cd86d3, 0x3c8ea00a, 0x384fbdbd,
        0x4c11db70, 0x48d0c6c7, 0x4593e01e, 0x4152fda9, 0x5f15adac,
        0x5bd4b01b, 0x569796c2, 0x52568b75, 0x6a1936c8, 0x6ed82b7f,
        0x639b0da6, 0x675a1011, 0x791d4014, 0x7ddc5da3, 0x709f7b7a,
        0x745e66cd, 0x9823b6e0, 0x9ce2ab57, 0x91a18d8e, 0x95609039,
        0x8b27c03c, 0x8fe6dd8b, 0x82a5fb52, 0x8664e6e5, 0xbe2b5b58,
        0xbaea46ef, 0xb7a96036, 0xb3687d81, 0xad2f2d84, 0xa9ee3033,
        0xa4ad16ea, 0xa06c0b5d, 0xd4326d90, 0xd0f37027, 0xddb056fe,
        0xd9714b49, 0xc7361b4c, 0xc3f706fb, 0xceb42022, 0xca753d95,
        0xf23a8028, 0xf6fb9d9f, 0xfbb8bb46, 0xff79a6f1, 0xe13ef6f4,
        0xe5ffeb43, 0xe8bccd9a, 0xec7dd02d, 0x34867077, 0x30476dc0,
        0x3d044b19, 0x39c556ae, 0x278206ab, 0x23431b1c, 0x2e003dc5,
        0x2ac12072, 0x128e9dcf, 0x164f8078, 0x1b0ca6a1, 0x1fcdbb16,
        0x018aeb13, 0x054bf6a4, 0x0808d07d, 0x0cc9cdca, 0x7897ab07,
        0x7c56b6b0, 0x71159069, 0x75d48dde, 0x6b93dddb, 0x6f52c06c,
        0x6211e6b5, 0x66d0fb02, 0x5e9f46bf, 0x5a5e5b08, 0x571d7dd1,
        0x53dc6066, 0x4d9b3063, 0x495a2dd4, 0x44190b0d, 0x40d816ba,
        0xaca5c697, 0xa864db20, 0xa527fdf9, 0xa1e6e04e, 0xbfa1b04b,
        0xbb60adfc, 0xb6238b25, 0xb2e29692, 0x8aad2b2f, 0x8e6c3698,
        0x832f1041, 0x87ee0df6, 0x99a95df3, 0x9d684044, 0x902b669d,
        0x94ea7b2a, 0xe0b41de7, 0xe4750050, 0xe9362689, 0xedf73b3e,
        0xf3b06b3b, 0xf771768c, 0xfa325055, 0xfef34de2, 0xc6bcf05f,
        0xc27dede8, 0xcf3ecb31, 0xcbffd686, 0xd5b88683, 0xd1799b34,
        0xdc3abded, 0xd8fba05a, 0x690ce0ee, 0x6dcdfd59, 0x608edb80,
        0x644fc637, 0x7a089632, 0x7ec98b85, 0x738aad5c, 0x774bb0eb,
        0x4f040d56, 0x4bc510e1, 0x46863638, 0x42472b8f, 0x5c007b8a,
        0x58c1663d, 0x558240e4, 0x51435d53, 0x251d3b9e, 0x21dc2629,
        0x2c9f00f0, 0x285e1d47, 0x36194d42, 0x32d850f5, 0x3f9b762c,
        0x3b5a6b9b, 0x0315d626, 0x07d4cb91, 0x0a97ed48, 0x0e56f0ff,
        0x1011a0fa, 0x14d0bd4d, 0x19939b94, 0x1d528623, 0xf12f560e,
        0xf5ee4bb9, 0xf8ad6d60, 0xfc6c70d7, 0xe22b20d2, 0xe6ea3d65,
        0xeba91bbc, 0xef68060b, 0xd727bbb6, 0xd3e6a601, 0xdea580d8,
        0xda649d6f, 0xc423cd6a, 0xc0e2d0dd, 0xcda1f604, 0xc960ebb3,
        0xbd3e8d7e, 0xb9ff90c9, 0xb4bcb610, 0xb07daba7, 0xae3afba2,
        0xaafbe615, 0xa7b8c0cc, 0xa379dd7b, 0x9b3660c6, 0x9ff77d71,
        0x92b45ba8, 0x9675461f, 0x8832161a, 0x8cf30bad, 0x81b02d74,
        0x857130c3, 0x5d8a9099, 0x594b8d2e, 0x5408abf7, 0x50c9b640,
        0x4e8ee645, 0x4a4ffbf2, 0x470cdd2b, 0x43cdc09c, 0x7b827d21,
        0x7f436096, 0x7200464f, 0x76c15bf8, 0x68860bfd, 0x6c47164a,
        0x61043093, 0x65c52d24, 0x119b4be9, 0x155a565e, 0x18197087,
        0x1cd86d30, 0x029f3d35, 0x065e2082, 0x0b1d065b, 0x0fdc1bec,
        0x3793a651, 0x3352bbe6, 0x3e119d3f, 0x3ad08088, 0x2497d08d,
        0x2056cd3a, 0x2d15ebe3, 0x29d4f654, 0xc5a92679, 0xc1683bce,
        0xcc2b1d17, 0xc8ea00a0, 0xd6ad50a5, 0xd26c4d12, 0xdf2f6bcb,
        0xdbee767c, 0xe3a1cbc1, 0xe760d676, 0xea23f0af, 0xeee2ed18,
        0xf0a5bd1d, 0xf464a0aa, 0xf9278673, 0xfde69bc4, 0x89b8fd09,
        0x8d79e0be, 0x803ac667, 0x84fbdbd0, 0x9abc8bd5, 0x9e7d9662,
        0x933eb0bb, 0x97ffad0c, 0xafb010b1, 0xab710d06, 0xa6322bdf,
        0xa2f33668, 0xbcb4666d, 0xb8757bda, 0xb5365d03, 0xb1f740b4
};

uint32_t posix_crc32(const uint8_t * const data, size_t data_len) {
    uint32_t crc;
    size_t remain;
    const uint8_t *bp;

    for (crc = 0, bp = data, remain = data_len; remain > 0; bp++, remain--)
        crc = (crc << 8) ^ crc_table[((crc >> 24) ^ *bp) & 0xff];

    for (; data_len != 0; data_len >>= 8)
        crc = (crc << 8) ^ crc_table[((crc >> 24) ^ data_len) & 0xff];

    return ~crc & 0xffffffff;
}
