#include <inttypes.h>

typedef struct {

} msg;

#define C_NUL (0x00)
#define C_SOH (0x01)
#define C_STX (0x02)
#define C_ETX (0x03)
#define C_EOT (0x04)
#define C_GS (0x1D)
#define C_RS (0x1E)
#define C_US (0x1F)

uint8_t gu8(const uint8_t *p) {
    return *(p++);
}
uint16_t gu16(const uint8_t *p) {
    uint16_t res = *(p++);
    return (res << 8) + *(p++);
}
uint32_t gu32(const uint8_t *p) {
    uint32_t res = (((uint32_t) p[0]) << 24)
                 + (((uint32_t) p[1]) << 16)
                 + (((uint32_t) p[2]) << 8)
                 + (((uint32_t) p[3]) << 0);
    p += 4;
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
    p += 8;
}

unsigned msg_parse_signature(const uint8_t *p) {

}