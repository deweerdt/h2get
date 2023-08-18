#include "h2get.h"
#include <errno.h>
#include <unistd.h>
#include <poll.h>

static int wait_for_read(int fd, int tout)
{
    struct pollfd fds[1];
    fds[0].fd = fd;
    fds[0].events = POLLIN;
    return poll(fds, 1, tout);
}

static int plain_accept(struct h2get_conn *listener, struct h2get_conn *conn, int tout)
{
    if (listener->fd < 0) {
        return -1;
    }

    int r;
    while ((r = wait_for_read(listener->fd, tout)) < 0 && errno == EINTR) {}
    if (r == 0) {
        return H2GET_ERROR_TIMEOUT;
    }

    conn->sa.len = sizeof(conn->sa.sa_storage);
    conn->fd = accept(listener->fd, (void *)&conn->sa.sa_storage, &conn->sa.len);
    if (conn->fd < 0) {
        return -1;
    }
    conn->sa.sa = (void *)&conn->sa.sa_storage;
    conn->ops = listener->ops;
    conn->state = H2GET_CONN_STATE_CONNECT;

    return 0;
}

static int plain_write(struct h2get_conn *conn, struct h2get_buf *bufs, size_t nr_bufs)
{
    int ret;
    size_t i;
    for (i = 0; i < nr_bufs; i++) {
        int wlen = 0;
        do {
            ret = write(conn->fd, bufs[i].buf + wlen, bufs[i].len - wlen);
            if (ret < 0) {
                return -1;
            }
            wlen -= ret;
        } while (wlen > 0);
    }
    return 0;
}

static int plain_read(struct h2get_conn *conn, struct h2get_buf *buf, int tout)
{
    int ret;

    assert(buf->len != 0);

    if (tout >= 0) {
        ret = wait_for_read(conn->fd, tout);
        if (ret <= 0) {
            return 0;
        }
    }
    ret = read(conn->fd, buf->buf, buf->len);
    if (ret != buf->len) {
        return -1;
    }
    return ret;
}

static int plain_connect(struct h2get_conn *conn)
{
    int ret;
    conn->fd = socket(conn->sa.sa->sa_family, conn->socktype, conn->protocol);
    if (conn->fd < 0) {
        return -1;
    }

    ret = connect(conn->fd, conn->sa.sa, conn->sa.len);
    if (ret < 0) {
        close(conn->fd);
        return -1;
    }

    conn->state = H2GET_CONN_STATE_CONNECT;
    return 0;
}

static int plain_close(struct h2get_conn *conn)
{
    if (conn->state < H2GET_CONN_STATE_CONNECT) {
        return -1;
    }
    conn->state = H2GET_CONN_STATE_INIT;
    return close(conn->fd);
}

struct h2get_ops plain_ops = {
    H2GET_TRANSPORT_PLAIN, NULL, plain_connect, plain_accept, plain_write, plain_read, plain_close,
};
/* vim: set expandtab ts=4 sw=4: */
