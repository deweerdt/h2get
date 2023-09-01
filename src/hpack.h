#ifndef HPACK_H__
#define HPACK_H__

#include "h2get.h"

struct h2get_decoded_header {
    struct h2get_buf key;
    struct h2get_buf value;
    struct list node;
    unsigned char compressed : 1;
};
#define list_to_dh(ln) (container_of((ln), struct h2get_decoded_header, node))

void h2get_hpack_ctx_init(struct h2get_hpack_ctx *hhc, size_t dyn_size);
void h2get_hpack_ctx_empty(struct h2get_hpack_ctx *hhc);
void h2get_hpack_ctx_resize(struct h2get_hpack_ctx *hhc, size_t dyn_size);
uint8_t *decode_string(uint8_t *buf, uint8_t *end, struct h2get_buf *ret);
struct list;
int h2get_hpack_decode(struct h2get_hpack_ctx *hhc, char *payload, size_t plen, struct list *headers);
void h2get_decoded_header_free(struct h2get_decoded_header *h);

// https://www.rfc-editor.org/rfc/rfc7541.html#section-5.1
static inline size_t h2get_hpack_vli_encoding_size(const size_t first_byte_bits, size_t value)
{
    // 2^N - 1
    const size_t first_byte_bound = (((size_t)1) << first_byte_bits) - 1;
    if (value < first_byte_bound)
        return 1;
    value -= first_byte_bound;
    size_t nbytes = 2;
    while (value >= 0x80) {
        nbytes += 1;
        value >>= 7;
    }
    return nbytes;
}

static inline char *h2get_hpack_vli_encode(const size_t first_byte_bits, size_t value, char *payload)
{
    const size_t first_byte_bound = (((size_t)1) << first_byte_bits) - 1;
    if (value < first_byte_bound) {
        *payload++ = value;
        return payload;
    }
    *payload++ = first_byte_bound;
    value -= first_byte_bound;
    while (value >= 0x80) {
        *payload++ = 0x80 | (value & 0x7F);
        value >>= 7;
    }
    *payload++ = value & 0x7F;
    return payload;
}

static inline size_t h2get_hpack_get_encoded_header_size(const struct h2get_buf *key, const struct h2get_buf *value)
{
    return 1 + h2get_hpack_vli_encoding_size(7, key->len) + key->len + h2get_hpack_vli_encoding_size(7, value->len) + value->len;
}

static inline char *h2get_hpack_add_header(const struct h2get_buf *key, const struct h2get_buf *value, char *payload)
{
    *payload++ = 0x00; /* no indexing */
    payload = h2get_hpack_vli_encode(7, key->len, payload);
    memcpy(payload, key->buf, key->len);
    payload += key->len;
    payload = h2get_hpack_vli_encode(7, value->len, payload);
    memcpy(payload, value->buf, value->len);
    payload += value->len;
    return payload;
}

#endif /* HPACK_H__ */
/* vim: set expandtab ts=4 sw=4: */
