#include "h2get.h"
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <poll.h>

static const unsigned char h2_proto_list[] = {2, 'h', '2'};

static __attribute__((unused)) int on_alpn_select(SSL *ssl, const unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void *arg)
{
    const unsigned char *in_end = in + inlen;
    while (in != in_end) {
        size_t cand_len = *in++;
        if (in_end - in < cand_len) {
            return SSL_TLSEXT_ERR_NOACK;
        }
        #define H2 "h2"
        if (cand_len == strlen(H2) && memcmp(in, H2, strlen(H2)) == 0) {
            *out = (const unsigned char *)H2;
            *outlen = (unsigned char)strlen(H2);
            return SSL_TLSEXT_ERR_OK;
        }
        #undef H2
        in += cand_len;
    }
    return SSL_TLSEXT_ERR_NOACK;
}

static __attribute__((unused)) int npn_select_h2(SSL *s, unsigned char **out, unsigned char *outlen,
                                                 const unsigned char *in, unsigned int inlen,
                                                 void *arg)
{
    SSL_select_next_proto(out, outlen, in, inlen, h2_proto_list, sizeof(h2_proto_list));
    return SSL_TLSEXT_ERR_OK;
}

static void *ssl_init(struct h2get_ctx *h2get_ctx, const char **err)
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    OpenSSL_add_all_ciphers();

    bool is_server = h2get_ctx_is_server(h2get_ctx);
    method = is_server ? SSLv23_server_method() : SSLv23_client_method();
    ctx = SSL_CTX_new(method);
    if (is_server) {
        if (SSL_CTX_use_certificate_file(ctx, h2get_ctx->server.cert_path, SSL_FILETYPE_PEM) <= 0) {
            *err = "failed to read cert file";
            return NULL;
        }

        if (SSL_CTX_use_PrivateKey_file(ctx, h2get_ctx->server.key_path, SSL_FILETYPE_PEM) <= 0 ) {
            *err = "failed to read key file";
            return NULL;
        }
        SSL_CTX_set_alpn_select_cb(ctx, on_alpn_select, NULL);
    } else {
#if OPENSSL_VERSION_NUMBER >= 0x10002000L || defined(LIBRESSL_VERSION_NUMBER)
        if (SSL_CTX_set_alpn_protos(ctx, h2_proto_list, sizeof(h2_proto_list))) {
            *err = "failed to setup alpn protocols";
            return NULL;
        }
#else
        SSL_CTX_set_next_proto_select_cb(ssl_ctx, npn_select_h2, NULL);
#endif
    }

    return ctx;
}

static int wait_for_read(int fd, int tout)
{
    struct pollfd fds[1];
    fds[0].fd = fd;
    fds[0].events = POLLIN;
    return poll(fds, 1, tout);
}

static int wait_for_write(int fd, int tout)
{
    struct pollfd fds[1];
    fds[0].fd = fd;
    fds[0].events = POLLOUT;
    return poll(fds, 1, tout);
}

__attribute__((unused)) static char *ssl_err(void)
{
    unsigned long errdetail;
    static char errbuf[1024];

    errdetail = ERR_get_error();

    ERR_error_string_n(errdetail, errbuf, sizeof(errbuf));
    return errbuf;
}

static int ssl_connect(struct h2get_conn *conn, void *priv)
{
    int ret;
    int err;
    SSL *ssl;
    SSL_CTX *ssl_ctx = priv;
    long ctx_opts;
    char *servername;

    servername = H2GET_TO_STR_ALLOCA(conn->servername);
    conn->fd = socket(conn->sa.sa->sa_family, conn->socktype, conn->protocol);
    if (conn->fd < 0) {
        return -1;
    }

    ret = connect(conn->fd, conn->sa.sa, conn->sa.len);
    if (ret < 0) {
        goto err1;
    }

    ctx_opts = SSL_OP_ALL;
    SSL_CTX_set_options(ssl_ctx, ctx_opts);
    SSL_CTX_set_mode(ssl_ctx, SSL_MODE_AUTO_RETRY);

    ssl = SSL_new(ssl_ctx);
    if (!ssl) {
        goto err1;
    }
    ret = SSL_set_tlsext_host_name(ssl, servername);
    if (!ret) {
        goto err2;
    }

    SSL_set_connect_state(ssl);

    if (!SSL_set_fd(ssl, conn->fd)) {
        goto err2;
    }

retry_connect:
    ERR_clear_error();
    err = SSL_connect(ssl);
    if (err <= 0) {
        int ssle;
        ssle = SSL_get_error(ssl, err);
        if (ssle == SSL_ERROR_WANT_WRITE) {
            wait_for_write(conn->fd, -1);
            goto retry_connect;
        } else if (ssle == SSL_ERROR_WANT_READ) {
            wait_for_read(conn->fd, -1);
            goto retry_connect;
        }
        goto err2;
    }

    conn->state = H2GET_CONN_STATE_CONNECT;
    conn->priv = ssl;
    return 0;
err2:
    SSL_free(ssl);
err1:
    close(conn->fd);
    return -1;
}

static int ssl_accept(struct h2get_conn *listener, struct h2get_conn *conn, void *priv)
{
    int err;
    SSL *ssl;
    SSL_CTX *ssl_ctx = priv;

    long ctx_opts;

    if (listener->fd < 0) {
        return -1;
    }

    conn->sa.len = sizeof(conn->sa.sa_storage);
    conn->fd = accept(listener->fd, (void *)&conn->sa.sa_storage, &conn->sa.len);
    if (conn->fd < 0) {
        goto err1;
    }
    conn->sa.sa = (void *)&conn->sa.sa_storage;

    ctx_opts = SSL_OP_ALL;
    SSL_CTX_set_options(ssl_ctx, ctx_opts);
    SSL_CTX_set_mode(ssl_ctx, SSL_MODE_AUTO_RETRY);

    ssl = SSL_new(ssl_ctx);
    if (!ssl) {
        goto err1;
    }
    SSL_set_accept_state(ssl);

    if (!SSL_set_fd(ssl, conn->fd)) {
        goto err2;
    }

retry_connect:
    ERR_clear_error();
    err = SSL_accept(ssl);
    if (err <= 0) {
        int ssle;
        ssle = SSL_get_error(ssl, err);
        if (ssle == SSL_ERROR_WANT_WRITE) {
            wait_for_write(conn->fd, -1);
            goto retry_connect;
        } else if (ssle == SSL_ERROR_WANT_READ) {
            wait_for_read(conn->fd, -1);
            goto retry_connect;
        }
        goto err2;
    }

    conn->state = H2GET_CONN_STATE_CONNECT;
    conn->priv = ssl;
    return 0;
err2:
    SSL_free(ssl);
err1:
    close(conn->fd);
    conn->fd = -1;
    return -1;
}

static int ssl_write(struct h2get_conn *conn, struct h2get_buf *bufs, size_t nr_bufs)
{
    int ret;
    int i;
    for (i = 0; i < nr_bufs; i++) {
        int wlen = 0;
        do {
            ret = SSL_write(conn->priv, bufs[i].buf + wlen, bufs[i].len - wlen);
            if (ret < 0) {
                return -1;
            }
            wlen -= ret;
        } while (wlen > 0);
    }
    return 0;
}

static int ssl_read(struct h2get_conn *conn, struct h2get_buf *buf, int tout)
{
    int ret;
    int pending;

    assert(buf->len != 0);

    pending = SSL_pending(conn->priv);
    if (!pending && tout >= 0) {
        ret = wait_for_read(conn->fd, tout);
        if (ret <= 0) {
            return 0;
        }
    }
    ret = SSL_read(conn->priv, buf->buf, buf->len);
    if (ret <= 0) {
        return -1;
    }
    return ret;
}

static int ssl_close(struct h2get_conn *conn, void *priv)
{
    if (conn->state < H2GET_CONN_STATE_CONNECT) {
        return -1;
    }
    conn->state = H2GET_CONN_STATE_INIT;
    SSL_shutdown(priv);
    SSL_free(priv);
    return close(conn->fd);
}

static void ssl_fini(void *priv)
{
    SSL_CTX_free(priv);
    EVP_cleanup();
    return;
}

struct h2get_ops ssl_ops = {
    H2GET_TRANSPORT_SSL, ssl_init, ssl_connect, ssl_accept, ssl_write, ssl_read, ssl_close, ssl_fini,
};
/* vim: set expandtab ts=4 sw=4: */
