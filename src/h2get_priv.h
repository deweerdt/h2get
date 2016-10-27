#ifndef H2GET_PRIV_H__
#define H2GET_PRIV_H__

#include "hpack.h"
#include <signal.h>

int h2get_send_settings_ack(struct h2get_ctx *ctx, int timeout);
typedef void (*h2get_frame_render_t)(struct h2get_ctx *ctx, struct h2get_buf *, struct h2get_h2_header *, char *, size_t);
h2get_frame_render_t h2get_frame_get_renderer(uint8_t type);
const char *h2get_frame_type_to_str(uint8_t type);

extern const char *err_read_timeout;
int h2get_read_one_frame(struct h2get_ctx *ctx, struct h2get_h2_header *header, struct h2get_buf *buf, int timeout, const char **err);

void *h2get_reader_thread(void *arg);

#define H2GET_HEADERS_SETTINGS_HEADER_TABLE_SIZE 0x1
#define H2GET_HEADERS_SETTINGS_ENABLE_PUSH 0x2
#define H2GET_HEADERS_SETTINGS_MAX_CONCURRENT_STREAMS 0x3
#define H2GET_HEADERS_SETTINGS_INITIAL_WINDOW_SIZE 0x4
#define H2GET_HEADERS_SETTINGS_MAX_FRAME_SIZE 0x5
#define H2GET_HEADERS_SETTINGS_MAX_HEADER_LIST_SIZE 0x6

struct h2get_h2_settings {
    uint32_t header_table_size;
    uint32_t enable_push;
    uint32_t max_concurrent_streams;
    uint32_t initial_window_size;
    uint32_t max_frame_size;
    uint32_t max_header_list_size;
};

struct h2get_url {
    struct {
        struct h2get_buf scheme;
        struct h2get_buf authority;
        struct h2get_buf host;
        struct h2get_buf port;
        struct h2get_buf path;
    } raw;
    struct {
        uint16_t port;
        const char *parse_err;
    } parsed;
    struct h2get_buf unparsed;
};

struct h2get_ctx {
    struct h2get_conn conn;
    struct h2get_ops *ops;
    void *xprt_priv;

    struct h2get_h2_settings peer_settings;
    struct h2get_h2_settings own_settings;
    uint32_t max_open_sid_client;
    uint32_t max_open_sid_server;

    struct h2get_ops *registered_ops;
    size_t nr_ops;

    struct h2get_hpack_ctx peer_hpack;
    struct h2get_hpack_ctx own_hpack;

    struct h2get_url url;
};

typedef enum h2get_cmd_res (*h2get_on_cmd_t)(struct h2get_ctx *ctx, int argc, struct h2get_buf *argv);
typedef void (*h2get_cmd_usage_t)(struct h2get_ctx *ctx);

struct h2get_command {
    struct h2get_buf name;
    h2get_on_cmd_t on_cmd;
    h2get_cmd_usage_t usage;
};

void run_mruby(const char *rbfile, int argc, char **argv);

#endif /* H2GET_PRIV_H__ */
