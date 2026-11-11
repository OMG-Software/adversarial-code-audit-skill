/* Synthetic fixture. Read-only: never compile or run. */
#include <stdint.h>
#include <string.h>

#define FRAME_MAX 64

struct frame {
    uint8_t type;
    uint8_t body[FRAME_MAX];
};

/* Decodes one packet from a network peer that has not authenticated.
 * `pkt` holds `pkt_len` bytes read from the socket. */
int decode_frame(const uint8_t *pkt, size_t pkt_len, struct frame *out)
{
    uint8_t body_len = pkt[1];

    out->type = pkt[0];
    if (pkt_len < (size_t)body_len + 2)
        return -1;
    memcpy(out->body, pkt + 2, body_len);
    return 0;
}

/* Called by the socket loop for every packet. This file is the whole receive path. */
int handle_packet(const uint8_t *pkt, size_t pkt_len)
{
    struct frame f;

    if (pkt_len < 2)
        return -1;
    return decode_frame(pkt, pkt_len, &f);
}
