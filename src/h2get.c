#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/ssl.h>

#include <mruby.h>
#include <mruby/compile.h>

#include "h2get.h"
#include "hpack.h"

#define sizetoh2len(l) ((htonl(l)) >> 8)

static int h2get_buf_cmp(struct h2get_buf *b1, struct h2get_buf *b2)
{
    if (b1->len != b2->len) {
        return b1->len - b2->len;
    }
    return memcmp(b1->buf, b2->buf, b1->len);
}

static struct h2get_ops *h2get_ctx_get_ops(struct h2get_ctx *ctx, enum h2get_transport xprt)
{
    int i;
    for (i = 0; i < ctx->nr_ops; i++) {
        if (ctx->registered_ops[i].xprt == xprt) {
            return &ctx->registered_ops[i];
        }
    }
    return NULL;
}

static struct h2get_h2_settings default_settings = {
    4096, 1, 2147483647, 65535, 16384, 2147483647,
};

static void h2get_ctx_register_ops(struct h2get_ctx *ctx, struct h2get_ops *ops)
{
    ctx->registered_ops = realloc(ctx->registered_ops, sizeof(*ctx->registered_ops) * ++ctx->nr_ops);
    ctx->registered_ops[ctx->nr_ops - 1] = *ops;
}

static void conn_init(struct h2get_ctx *ctx, struct h2get_conn *conn)
{
    *conn = (struct h2get_conn){
        .ctx = ctx,
        .fd = -1,
        .peer_settings = default_settings,
        .own_settings = default_settings,
        .max_open_sid_client = 1,
        .max_open_sid_server = 0,
    };
    h2get_hpack_ctx_init(&conn->own_hpack, conn->own_settings.header_table_size);
}

void h2get_ctx_init(struct h2get_ctx *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
    conn_init(ctx, &ctx->server.listener);

    h2get_ctx_register_ops(ctx, &plain_ops);
    h2get_ctx_register_ops(ctx, &ssl_ops);
}

bool h2get_ctx_is_server(struct h2get_ctx *ctx)
{
    return ctx->is_server;
}

#define CHECK_CONN() do { \
        if (conn->fd < 0) { \
            *err = "connection already closed"; \
            return -1; \
        } \
    } while (0)

int h2get_conn_on_settings_ack(struct h2get_conn *conn, const char **err)
{
    CHECK_CONN();
    h2get_hpack_ctx_init(&conn->own_hpack, conn->own_settings.header_table_size);
    return 0;
}

int h2get_conn_on_peer_settings(struct h2get_conn *conn, struct h2get_h2_header *h, char *payload, int plen, const char **err)
{
    CHECK_CONN();
    struct h2get_h2_setting *settings;
    int i;

    if (h->flags & H2GET_HEADERS_SETTINGS_FLAGS_ACK) {
        if (plen) {
            /* Receipt of a SETTINGS frame with the ACK flag set and a length
             * field value other than 0 MUST be treated as a connection error */
            return -H2GET_ERR_FRAME_SIZE_ERROR;
        }
        return h2get_conn_on_settings_ack(conn, err);
    }
    /* The stream identifier for a SETTINGS frame MUST be zero (0x0). */
    if (h->stream_id) {
        return -H2GET_ERR_PROTOCOL_ERROR;
    }

    /* A SETTINGS frame with a length other than a multiple of 6 octets MUST
     * be treated as a connection error. */
    if (plen % 6) {
        return -H2GET_ERR_FRAME_SIZE_ERROR;
    }

    settings = (struct h2get_h2_setting *)payload;
    for (i = 0; i < (plen) / sizeof(*settings); i++) {
        unsigned int v = ntohl(settings[i].value);
        switch (ntohs(settings[i].id)) {
        case H2GET_HEADERS_SETTINGS_HEADER_TABLE_SIZE:
            conn->peer_settings.header_table_size = v;
            break;
        case H2GET_HEADERS_SETTINGS_ENABLE_PUSH:
            /** Any value other than 0 or 1 MUST be treated as a connection
             * error. */
            if (v != 0 && v != 1) {
                return -H2GET_ERR_PROTOCOL_ERROR;
            }
            conn->peer_settings.enable_push = v;
            break;
        case H2GET_HEADERS_SETTINGS_MAX_CONCURRENT_STREAMS:
            conn->peer_settings.max_concurrent_streams = v;
            break;
        case H2GET_HEADERS_SETTINGS_INITIAL_WINDOW_SIZE:
            conn->peer_settings.initial_window_size = v;
            break;
        case H2GET_HEADERS_SETTINGS_MAX_FRAME_SIZE:
            conn->peer_settings.max_frame_size = v;
            break;
        case H2GET_HEADERS_SETTINGS_MAX_HEADER_LIST_SIZE:
            conn->peer_settings.max_header_list_size = v;
            break;
        default:
            /* An endpoint that receives a SETTINGS frame with any unknown or
             * unsupported identifier MUST ignore that setting. */
            break;
        }
    }
    h2get_hpack_ctx_init(&conn->peer_hpack, conn->peer_settings.header_table_size);
    return 0;
}

static const char *err_url_is_empty = "Empty URL";
static const char *err_url_scheme_unrecognized = "Unrecognized scheme in URL";
static const char *err_url_invalid_port = "Invalid port in URL";
static const char *err_url_invalid_chars_after_authority = "Invalid chars after authority in URL";

static struct h2get_url h2get_buf_parse_url(struct h2get_buf url)
{
    struct h2get_url ret;
    int i, start_host;
    bool found_scheme = false;
    unsigned int uport = 0;

    memset(&ret, 0, sizeof(ret));
    /* https://www.ietf.org/rfc/rfc3986.txt */
    /* absolute-URI  = scheme ":" hier-part [ "?" query ] */
    /* step 1: scheme        = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." ) */
    /* step 2:
       hier-part     = "//" authority path-abempty
                       / path-absolute
                       / path-rootless
                       / path-empty
       */
    /* step 3:    authority     = [ userinfo "@" ] host [ ":" port ] */
    /* We stop at the path. */
    if (!url.len) {
        ret.parsed.parse_err = err_url_is_empty;
        return ret;
    }
    if (!isalpha(url.buf[0])) {
        ret.parsed.parse_err = err_url_scheme_unrecognized;
        return ret;
    }
    for (i = 1; i < url.len && url.buf[i] != ':'; i++) {
        if (!isalpha(url.buf[i]) && !isdigit(url.buf[i]) && url.buf[i] != '+' && url.buf[i] != '-' &&
            url.buf[i] != '.') {
            ret.raw.scheme.buf = NULL;
            ret.raw.scheme.len = 0;
            goto no_scheme;
        }
    }
    if (i + 2 >= url.len || url.buf[i + 1] != '/' || url.buf[i + 2] != '/') {
        goto no_scheme;
    }
    found_scheme = true;

no_scheme:
    if (found_scheme) {
        ret.raw.scheme.buf = &url.buf[0];
        ret.raw.scheme.len = i;
        i += 3;
    } else {
        ret.raw.scheme.buf = NULL;
        ret.raw.scheme.len = 0;
        i = 0;
    }

    start_host = i;
    ret.raw.host.buf = &url.buf[i];
    ret.raw.host.len = 0;

    for (; i < url.len; i++) {
        if (url.buf[i] == ':') {
            ret.raw.host.len = i - start_host;
            ret.raw.port.buf = &url.buf[i + 1];
            for (i = i + 1; i < url.len; i++) {
                if (!isdigit(url.buf[i])) {
                    break;
                }
                uport = uport * 10 + (url.buf[i] - '0');
                if (uport > 0xffff) {
                    ret.parsed.parse_err = err_url_invalid_port;
                    return ret;
                }
            }
            ret.raw.port.len = &url.buf[i] - ret.raw.port.buf;
            break;
        } else if (url.buf[i] == '/') {
            ret.raw.host.len = i;
            ret.raw.path.buf = &url.buf[i];
            ret.raw.path.len = url.len - i;
            break;
        }
    }
    if (i == url.len && !ret.raw.host.len) {
        ret.raw.host.len = i - start_host;
    }
    if (i != url.len && url.buf[i] != '/') {
        ret.parsed.parse_err = err_url_invalid_chars_after_authority;
        return ret;
    }
    ret.parsed.port = (uint16_t)uport;
    /*
    fprintf(stderr, "parsed port is %d\n", uport);
    fprintf(stderr, "raw host is %.*s\n", (int)ret.raw.host.len,
    ret.raw.host.buf);
    fprintf(stderr, "raw scheme is %.*s\n", (int)ret.raw.scheme.len,
    ret.raw.scheme.buf);
    fprintf(stderr, "raw port is %.*s\n", (int)ret.raw.port.len,
    ret.raw.port.buf);
    fprintf(stderr, "raw path is %.*s\n", (int)ret.raw.path.len,
    ret.raw.path.buf);
    */
    return ret;
}

int h2get_conn_close(struct h2get_conn *conn, const char **err)
{
    CHECK_CONN();
    int ret;
    h2get_hpack_ctx_empty(&conn->own_hpack);
    free(conn->url.unparsed.buf);
    if ((ret = conn->ops->close(conn)) != 0) {
        *err = "close failed";
        return ret;
    }
    return 0;
}

int h2get_destroy(struct h2get_ctx *ctx, const char **err)
{
    int ret;
    if (h2get_ctx_is_server(ctx)) {
        if ((ret = h2get_conn_close(&ctx->server.listener, err)) != 0) {
            return ret;
        }
    }
    free(ctx->registered_ops);
    return 0;
}

int h2get_connect(struct h2get_ctx *ctx, struct h2get_conn *conn, struct h2get_buf url_buf, char *servername, const char **err)
{
    conn_init(ctx, conn);

    struct h2get_url url;
    enum h2get_transport xprt;
    int ret;

    url = h2get_buf_parse_url(url_buf);
    if (url.parsed.parse_err) {
        *err = url.parsed.parse_err;
        return -1;
    }

    if (!url.raw.scheme.buf) {
        xprt = H2GET_TRANSPORT_SSL;
    } else {
        if (!h2get_buf_cmp(&url.raw.scheme, &H2GET_BUFSTR("http"))) {
            xprt = H2GET_TRANSPORT_PLAIN;
        } else if (!h2get_buf_cmp(&url.raw.scheme, &H2GET_BUFSTR("https"))) {
            xprt = H2GET_TRANSPORT_SSL;
        } else if (!h2get_buf_cmp(&url.raw.scheme, &H2GET_BUFSTR("unix"))) {
            xprt = H2GET_TRANSPORT_UNIX;
        } else {
            *err = "Unknown URL scheme";
            return -1;
        }
    }
    const char *default_port = NULL;
    if (!url.parsed.port) {
        if (xprt == H2GET_TRANSPORT_SSL) {
            default_port = "443";
        } else if (xprt == H2GET_TRANSPORT_PLAIN) {
            default_port = "80";
        }
    }

    if (xprt == H2GET_TRANSPORT_PLAIN || xprt == H2GET_TRANSPORT_SSL) {
        struct addrinfo hints;
        struct addrinfo *result, *rp;
        int sfd, s;
        const char *service = default_port ?: H2GET_TO_STR_ALLOCA(url.raw.port);
        char *host = H2GET_TO_STR_ALLOCA(url.raw.host);

        memset(&hints, 0, sizeof(struct addrinfo));
        hints.ai_family = AF_UNSPEC;     /* Allow IPv4 or IPv6 */
        hints.ai_socktype = SOCK_STREAM; /* Datagram socket */
        hints.ai_flags = AI_NUMERICSERV;
        hints.ai_protocol = 0;
        hints.ai_canonname = NULL;
        hints.ai_addr = NULL;
        hints.ai_next = NULL;

        s = getaddrinfo(host, service, &hints, &result);
        if (s != 0) {
            *err = "Cannot resolve host";
            return -1;
        }
        for (rp = result; rp != NULL; rp = rp->ai_next) {
            sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
            if (sfd == -1)
                continue;
            close(sfd);
            break;
        }
        if (!rp) {
            *err = "Connection failed";
            return -1;
        }
        conn->protocol = rp->ai_protocol;
        conn->socktype = rp->ai_socktype;
        conn->sa.sa = (void *)&conn->sa.sa_storage;
        memcpy(conn->sa.sa, rp->ai_addr, rp->ai_addrlen);
        conn->sa.len = rp->ai_addrlen;

        freeaddrinfo(result);
    }
    conn->ops = h2get_ctx_get_ops(ctx, xprt);
    if (!conn->ops) {
        *err = "Transport not supported";
        return -1;
    }
    if (conn->ops->init) {
        int ret;
        if ((ret = conn->ops->init(conn, err)) != 0) {
            return ret;
        }
    }

    if (servername != NULL) {
        conn->servername = H2GET_BUFSTR(servername);
    } else {
        conn->servername = url.raw.host;
    }

    ret = conn->ops->connect(conn);
    if (ret < 0) {
        *err = "Connection failed";
        return -1;
    }

    conn->url = url;
    conn->url.unparsed.buf = memdup(url_buf.buf, url_buf.len);
    conn->url.unparsed.len = url_buf.len;
    return 0;
}

static int parse_url(struct h2get_buf url_buf, struct h2get_url *url, enum h2get_transport *xprt, struct h2get_conn *conn, const char **err)
{
    *url = h2get_buf_parse_url(url_buf);
    if (url->parsed.parse_err) {
        *err = url->parsed.parse_err;
        return -1;
    }

    if (!url->raw.scheme.buf) {
        *xprt = H2GET_TRANSPORT_SSL;
    } else {
        if (!h2get_buf_cmp(&url->raw.scheme, &H2GET_BUFSTR("http"))) {
            *xprt = H2GET_TRANSPORT_PLAIN;
        } else if (!h2get_buf_cmp(&url->raw.scheme, &H2GET_BUFSTR("https"))) {
            *xprt = H2GET_TRANSPORT_SSL;
        } else if (!h2get_buf_cmp(&url->raw.scheme, &H2GET_BUFSTR("unix"))) {
            *xprt = H2GET_TRANSPORT_UNIX;
        } else {
            *err = "Unknown URL scheme";
            return -1;
        }
    }
    const char *default_port = NULL;
    if (!url->parsed.port) {
        if (*xprt == H2GET_TRANSPORT_SSL) {
            default_port = "443";
        } else if (*xprt == H2GET_TRANSPORT_PLAIN) {
            default_port = "80";
        }
    }

    if (*xprt == H2GET_TRANSPORT_PLAIN || *xprt == H2GET_TRANSPORT_SSL) {
        struct addrinfo hints;
        struct addrinfo *result, *rp;
        int sfd, s;
        const char *service = default_port ?: H2GET_TO_STR_ALLOCA(url->raw.port);
        char *host = H2GET_TO_STR_ALLOCA(url->raw.host);

        memset(&hints, 0, sizeof(struct addrinfo));
        hints.ai_family = AF_UNSPEC;     /* Allow IPv4 or IPv6 */
        hints.ai_socktype = SOCK_STREAM; /* Datagram socket */
        hints.ai_flags = AI_NUMERICSERV;
        hints.ai_protocol = 0;
        hints.ai_canonname = NULL;
        hints.ai_addr = NULL;
        hints.ai_next = NULL;

        s = getaddrinfo(host, service, &hints, &result);
        if (s != 0) {
            *err = "Cannot resolve host";
            return -1;
        }
        for (rp = result; rp != NULL; rp = rp->ai_next) {
            sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
            if (sfd == -1)
                continue;
            close(sfd);
            break;
        }
        if (!rp) {
            *err = "Connection failed";
            return -1;
        }
        conn->protocol = rp->ai_protocol;
        conn->socktype = rp->ai_socktype;
        conn->sa.sa = (void *)&conn->sa.sa_storage;
        memcpy(conn->sa.sa, rp->ai_addr, rp->ai_addrlen);
        conn->sa.len = rp->ai_addrlen;

        freeaddrinfo(result);
    }

    return 0;
}

int h2get_listen(struct h2get_ctx *ctx, struct h2get_buf url_buf, int backlog, const char **err)
{
    struct h2get_conn *listener = &ctx->server.listener;
    enum h2get_transport xprt;
    if (parse_url(url_buf, &listener->url, &xprt, listener, err) != 0)
        return -1;
    listener->url.unparsed.buf = memdup(url_buf.buf, url_buf.len);
    listener->url.unparsed.len = url_buf.len;

    listener->ops = h2get_ctx_get_ops(ctx, xprt);
    if (!listener->ops) {
        *err = "Transport not supported";
        return -1;
    }
    if (listener->ops->init) {
        int ret = 0;
        if ((ret = listener->ops->init(listener, err)) != 0) {
            return ret;
        }
    }

    listener->fd = socket(listener->sa.sa->sa_family, listener->socktype, listener->protocol);
    if (listener->fd < 0) {
        *err = strerror(errno);
        return -1;
    }

    if (bind(listener->fd, listener->sa.sa, listener->sa.len) < 0) {
        *err = strerror(errno);
        goto err;
    }
    if (listen(listener->fd, backlog) < 0) {
        *err = strerror(errno);
        goto err;
    }
    listener->state = H2GET_CONN_STATE_CONNECT;
    return 0;
err:
    close(listener->fd);
    return -1;
}

int h2get_accept(struct h2get_ctx *ctx, struct h2get_conn *conn, int timeout, const char **err)
{
    conn_init(ctx, conn);
    int ret;
    if ((ret = ctx->server.listener.ops->accept(&ctx->server.listener, conn, timeout)) != 0) {
        *err = "accept failed";
        return ret;
    }

    return 0;
}

int h2get_conn_send_prefix(struct h2get_conn *conn, const char **err)
{
    CHECK_CONN();
    int ret;

    if (conn->state < H2GET_CONN_STATE_CONNECT) {
        *err = "Not connected";
        return -1;
    }
    ret = conn->ops->write(conn, &H2GET_BUFSTR(H2GET_CONNECTION_PREFACE), 1);
    if (ret < 0) {
        *err = "Write failed";
        return -1;
    }

    return 0;
}

int h2get_conn_send_windows_update(struct h2get_conn *conn, uint32_t stream_id, uint32_t increment, const char **err)
{
    int ret;
    struct {
        struct h2get_h2_header h;
        struct h2get_h2_window_update wu;
    } __attribute__((packed)) wu = {{
        0,
    }};

    wu.h.len = sizetoh2len(sizeof(wu.wu));
    wu.h.type = H2GET_HEADERS_WINDOW_UPDATE;
    wu.h.stream_id = htonl(stream_id) >> 1;
    wu.wu.increment = htonl(increment);

    if (conn->state < H2GET_CONN_STATE_CONNECT) {
        *err = "Not connected";
        return -1;
    }
    ret = conn->ops->write(conn, &H2GET_BUF(&wu, sizeof(wu)), 1);
    if (ret < 0) {
        *err = "Write failed";
        return -1;
    }

    return 0;
}

int h2get_conn_send_priority(struct h2get_conn *conn, uint32_t stream_id, struct h2get_h2_priority *iprio, const char **err)
{
    CHECK_CONN();
    int ret;
    struct {
        struct h2get_h2_header h;
        struct h2get_h2_priority prio;
    } __attribute__((packed)) prio = {{
        0,
    }};

    prio.h.len = sizetoh2len(sizeof(prio.prio));
    prio.h.type = H2GET_HEADERS_PRIORITY;
    prio.h.stream_id = htonl(stream_id) >> 1;
    prio.prio = *iprio;

    if (conn->state < H2GET_CONN_STATE_CONNECT) {
        *err = "Not connected";
        return -1;
    }
    ret = conn->ops->write(conn, &H2GET_BUF(&prio, sizeof(prio)), 1);
    if (ret < 0) {
        *err = "Write failed";
        return -1;
    }
    return 0;
}

int h2get_conn_send_rst_stream(struct h2get_conn *conn, uint32_t stream_id, uint32_t error_code, int timeout, const char **err)
{
    CHECK_CONN();
    int ret;
    struct {
        struct h2get_h2_header header;
        uint32_t error_code;
    } __attribute__((packed)) rst_stream = {
        {0, H2GET_HEADERS_RST_STREAM, 0, 0, 0},
    };

    rst_stream.header.stream_id = htonl(stream_id) >> 1;
    rst_stream.header.len = sizetoh2len(sizeof(rst_stream.error_code));
    rst_stream.error_code = htonl(error_code);

    if (conn->state < H2GET_CONN_STATE_CONNECT) {
        *err = "Not connected";
        return -1;
    }
    ret = conn->ops->write(conn, &H2GET_BUF(&rst_stream, sizeof(rst_stream)), 1);
    if (ret < 0) {
        *err = "Write failed";
        return -1;
    }

    return 0;
}

int h2get_conn_send_ping(struct h2get_conn *conn, char *payload, const char **err)
{
    CHECK_CONN();
    int ret;
    struct {
        struct h2get_h2_header header;
        char payload[8];
    } ping_frame = {
        {0, H2GET_HEADERS_PING, 0, 0, 0},
    };

    ping_frame.header.len = sizetoh2len(sizeof(ping_frame.payload));
    if (payload) {
        ping_frame.header.flags = 1;
        memcpy(ping_frame.payload, payload, sizeof(ping_frame.payload));
    }

    if (conn->state < H2GET_CONN_STATE_CONNECT) {
        *err = "Not connected";
        return -1;
    }
    ret = conn->ops->write(conn, &H2GET_BUF(&ping_frame, sizeof(ping_frame)), 1);
    if (ret < 0) {
        *err = "Write failed";
        return -1;
    }

    return 0;
}

int h2get_conn_send_settings(struct h2get_conn *conn, struct h2get_h2_setting *settings, size_t nr_settings, const char **err)
{
    CHECK_CONN();
    int ret, i;
    struct h2get_h2_header default_settings_frame = {
        sizetoh2len(nr_settings * sizeof(*settings)), H2GET_HEADERS_SETTINGS, 0, 0, 0,
    };
    struct h2get_h2_setting to_send[nr_settings];
    struct h2get_buf bufs[2];

    for (i = 0; i < nr_settings; i++) {
        to_send[i].id = htons(settings[i].id);
        to_send[i].value = htonl(settings[i].value);
    }
    if (conn->state < H2GET_CONN_STATE_CONNECT) {
        *err = "Not connected";
        return -1;
    }
    bufs[0] = H2GET_BUF(&default_settings_frame, sizeof(default_settings_frame));
    bufs[1] = H2GET_BUF(to_send, sizeof(to_send));
    ret = conn->ops->write(conn, bufs, 2);
    if (ret < 0) {
        *err = "Write failed";
        return -1;
    }

    return 0;
}

int h2get_conn_send_data(struct h2get_conn *conn, struct h2get_buf data, uint32_t sid, int flags, const char **err)
{
    CHECK_CONN();
    int ret, i = 0;
    struct h2get_buf bufs[2];
    struct h2get_h2_header data_header = {
        0, H2GET_HEADERS_DATA, flags, 0, 0,
    };

    data_header.len = sizetoh2len(data.len);
    data_header.stream_id = htonl(sid) >> 1;
    bufs[i++] = H2GET_BUF(&data_header, sizeof(data_header));
    bufs[i++] = data;

    if (conn->state < H2GET_CONN_STATE_CONNECT) {
        *err = "Not connected";
        return -1;
    }

    ret = conn->ops->write(conn, bufs, i);
    if (ret < 0) {
        *err = "Write failed\n";
        return -1;
    }

    return 0;
}

int h2get_conn_send_headers(struct h2get_conn *conn, struct h2get_buf *headers, size_t nr_headers, uint32_t sid, int flags,
                       struct h2get_h2_priority *prio, int is_cont, const char **err)
{
    CHECK_CONN();
    int ret;
    size_t plen = 0;
    char *whead, *payload;
    struct h2get_buf *hp;
    int i;

    for (i = 0, hp = headers; i < nr_headers; i++, hp += 2) {
        struct h2get_buf *hname = hp, *hvalue = hp + 1;
        plen += h2get_hpack_get_encoded_header_size(hname, hvalue);
    }

    payload = alloca(plen);
    whead = payload;

    for (i = 0, hp = headers; i < nr_headers; i++, hp += 2) {
        struct h2get_buf *hname = hp, *hvalue = hp + 1;
        whead = h2get_hpack_add_header(hname, hvalue, whead);
    }

    struct h2get_h2_header header_get = {
        0, is_cont ? H2GET_HEADERS_CONTINUATION : H2GET_HEADERS_HEADERS, flags, 0, 0,
    };
    struct h2get_buf bufs[3];
    header_get.len = sizetoh2len(plen + (prio ? sizeof(*prio) : 0));
    header_get.stream_id = htonl(sid) >> 1;
    conn->max_open_sid_client = (sid + 2);
    i = 0;
    bufs[i++] = H2GET_BUF(&header_get, sizeof(header_get));
    if (prio) {
        bufs[i++] = H2GET_BUF(prio, sizeof(*prio));
    }
    bufs[i++] = H2GET_BUF(payload, plen);

    if (conn->state < H2GET_CONN_STATE_CONNECT) {
        *err = "Not connected";
        return -1;
    }

    ret = conn->ops->write(conn, bufs, i);
    if (ret < 0) {
        *err = "Write failed\n";
        return -1;
    }

    return 0;
}

int h2get_conn_send_goaway(struct h2get_conn *conn, uint32_t last_stream_id, uint32_t error_code, struct h2get_buf additional, const char **err)
{
    CHECK_CONN();
    int ret, i = 0;
    struct h2get_buf bufs[2];
    struct {
        struct h2get_h2_header header;
        struct h2get_h2_goaway goaway;
    } goaway_frame = {
        {0, H2GET_HEADERS_GOAWAY, 0, 0, 0},
    };

    goaway_frame.header.len = sizetoh2len(sizeof(goaway_frame.goaway) + additional.len);
    goaway_frame.goaway.last_stream_id = htonl(last_stream_id) >> 1;
    goaway_frame.goaway.error_code = htonl(error_code);
    bufs[i++] = H2GET_BUF(&goaway_frame, sizeof(goaway_frame));
    if (additional.buf)
        bufs[i++] = additional;

    if (conn->state < H2GET_CONN_STATE_CONNECT) {
        *err = "Not connected";
        return -1;
    }
    ret = conn->ops->write(conn, bufs, i);
    if (ret < 0) {
        *err = "Write failed";
        return -1;
    }

    return 0;
}

int h2get_conn_send_raw_frame(struct h2get_conn *conn, uint8_t type, int flags, uint32_t sid, struct h2get_buf data, const char **err)
{
    CHECK_CONN();
    int ret, i = 0;
    struct h2get_buf bufs[2];
    struct h2get_h2_header data_header = {
        0, type, flags, 0, 0,
    };

    data_header.len = sizetoh2len(data.len);
    data_header.stream_id = htonl(sid) >> 1;
    bufs[i++] = H2GET_BUF(&data_header, sizeof(data_header));
    bufs[i++] = data;

    ret = conn->ops->write(conn, bufs, i);
    if (ret < 0) {
        *err = "Write failed\n";
        return -1;
    }

    return 0;
}

int h2get_conn_getp(struct h2get_conn *conn, const char *path, uint32_t sid, struct h2get_h2_priority prio, const char **err)
{
    CHECK_CONN();
    int ret;
    size_t plen = 0;
    char *whead, *payload;

    plen += 1 + 1;                          /* GET and https */
    plen += h2get_hpack_get_encoded_header_size(&H2GET_BUFLIT(":authority"), &conn->url.raw.host);
    plen += h2get_hpack_get_encoded_header_size(&H2GET_BUFLIT(":path"), &H2GET_BUFSTR((char *)path));

    payload = alloca(plen);
    whead = payload;

    *whead++ = 0x82; /* GET */
    *whead++ = 0x87; /* https */
    whead = h2get_hpack_add_header(&H2GET_BUFLIT(":authority"), &conn->url.raw.host, whead);
    whead = h2get_hpack_add_header(&H2GET_BUFLIT(":path"), &H2GET_BUFSTR((char *)path), whead);

    struct h2get_h2_header header_get = {
        0, H2GET_HEADERS_HEADERS, H2GET_HEADERS_HEADERS_FLAG_PRIORITY | H2GET_HEADERS_HEADERS_FLAG_END_STREAM |
                                      H2GET_HEADERS_HEADERS_FLAG_END_HEADERS,
        0, 0,
    };
    struct h2get_buf bufs[3];
    header_get.len = sizetoh2len(plen + sizeof(prio));
    header_get.stream_id = htonl(sid) >> 1;
    conn->max_open_sid_client = (sid + 2);
    bufs[0] = H2GET_BUF(&header_get, sizeof(header_get));
    bufs[1] = H2GET_BUF(&prio, sizeof(prio));
    bufs[2] = H2GET_BUF(payload, plen);

    if (conn->state < H2GET_CONN_STATE_CONNECT) {
        *err = "Not connected";
        return -1;
    }
    ret = conn->ops->write(conn, bufs, 3);
    if (ret < 0) {
        *err = "Write failed\n";
        return -1;
    }

    return 0;
}

int h2get_conn_get(struct h2get_conn *conn, const char *path, const char **err)
{
    CHECK_CONN();
    int ret;
    size_t plen = 0;
    char *whead, *payload;

    plen += 1 + 1;                          /* GET and https */
    plen += h2get_hpack_get_encoded_header_size(&H2GET_BUFLIT(":authority"), &conn->url.raw.host);
    plen += h2get_hpack_get_encoded_header_size(&H2GET_BUFLIT(":path"), &H2GET_BUFSTR((char *)path));

    payload = alloca(plen);
    whead = payload;

    *whead++ = 0x82; /* GET */
    *whead++ = 0x87; /* https */
    whead = h2get_hpack_add_header(&H2GET_BUFLIT(":authority"), &conn->url.raw.host, whead);
    whead = h2get_hpack_add_header(&H2GET_BUFLIT(":path"), &H2GET_BUFSTR((char *)path), whead);

    struct h2get_h2_header header_get = {
        0, H2GET_HEADERS_HEADERS, H2GET_HEADERS_HEADERS_FLAG_END_STREAM | H2GET_HEADERS_HEADERS_FLAG_END_HEADERS, 0, 0,
    };
    int sid = conn->max_open_sid_client;
    struct h2get_buf bufs[2];
    header_get.len = sizetoh2len(plen);
    header_get.stream_id = htonl(sid) >> 1;
    conn->max_open_sid_client += 2;
    bufs[0] = H2GET_BUF(&header_get, sizeof(header_get));
    bufs[1] = H2GET_BUF(payload, plen);

    if (conn->state < H2GET_CONN_STATE_CONNECT) {
        *err = "Not connected";
        return -1;
    }
    ret = conn->ops->write(conn, bufs, 2);
    if (ret < 0) {
        *err = "Write failed\n";
        return -1;
    }

    return 0;
}

static void usage(void)
{
    fprintf(stderr, "Usage: h2g [filename.rb]\n");
    exit(EXIT_FAILURE);
}

int main(int argc, char **argv)
{
    int extra_args;

    signal(SIGPIPE, SIG_IGN);

    if (argc <= 1) {
        usage();
    }
    extra_args = (argc - 2) >= 0;
    run_mruby(argv[1], extra_args ? argc - 2 : 0, extra_args ? &argv[2] : NULL);

    exit(EXIT_SUCCESS);
}
/* vim: set expandtab ts=4 sw=4: */
