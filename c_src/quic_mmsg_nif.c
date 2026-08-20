/* sendmmsg(2) NIF: one syscall for a batch of datagrams to mixed
 * destinations, with optional per-message UDP_SEGMENT (GSO).
 *
 * The OTP socket module drives one sendmsg per call through
 * prim_socket; on sparse many-connection traffic (one small packet per
 * flow) that per-call overhead dominates the send path. This NIF is
 * optional: quic_mmsg falls back to per-batch sendmsg when it fails to
 * load.
 */

#define _GNU_SOURCE

#include <erl_nif.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/udp.h>

#ifndef UDP_SEGMENT
#define UDP_SEGMENT 103
#endif

#define MAX_MSGS 64
#define MAX_IOV 8

static ERL_NIF_TERM am_ok;
static ERL_NIF_TERM am_error;

static int
fill_sockaddr(ErlNifEnv *env, ERL_NIF_TERM addr, ERL_NIF_TERM port,
              struct sockaddr_storage *ss, socklen_t *len)
{
    int arity, p, i;
    const ERL_NIF_TERM *elem;

    if (!enif_get_int(env, port, &p) || p < 0 || p > 65535)
        return 0;
    if (!enif_get_tuple(env, addr, &arity, &elem))
        return 0;
    if (arity == 4) {
        struct sockaddr_in *sin = (struct sockaddr_in *)ss;
        unsigned char *b = (unsigned char *)&sin->sin_addr;
        memset(sin, 0, sizeof(*sin));
        sin->sin_family = AF_INET;
        sin->sin_port = htons((unsigned short)p);
        for (i = 0; i < 4; i++) {
            int v;
            if (!enif_get_int(env, elem[i], &v) || v < 0 || v > 255)
                return 0;
            b[i] = (unsigned char)v;
        }
        *len = sizeof(*sin);
        return 1;
    } else if (arity == 8) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ss;
        unsigned char *b = (unsigned char *)&sin6->sin6_addr;
        memset(sin6, 0, sizeof(*sin6));
        sin6->sin6_family = AF_INET6;
        sin6->sin6_port = htons((unsigned short)p);
        for (i = 0; i < 8; i++) {
            int v;
            if (!enif_get_int(env, elem[i], &v) || v < 0 || v > 0xffff)
                return 0;
            b[2 * i] = (unsigned char)(v >> 8);
            b[2 * i + 1] = (unsigned char)(v & 0xff);
        }
        *len = sizeof(*sin6);
        return 1;
    }
    return 0;
}

/* send_many(Fd, [{Addr, Port, PayloadIolist, SegSize}]) ->
 *   {ok, NSent} | {error, atom()} */
static ERL_NIF_TERM
send_many(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    int fd, n = 0, sent;
    ERL_NIF_TERM list, head, tail;
    static _Thread_local struct mmsghdr msgs[MAX_MSGS];
    static _Thread_local struct sockaddr_storage addrs[MAX_MSGS];
    static _Thread_local struct iovec iovs[MAX_MSGS];
    static _Thread_local ErlNifBinary bins[MAX_MSGS];
    static _Thread_local char cmsgbufs[MAX_MSGS]
        [CMSG_SPACE(sizeof(unsigned short))];

    if (argc != 2 || !enif_get_int(env, argv[0], &fd))
        return enif_make_badarg(env);

    list = argv[1];
    while (enif_get_list_cell(env, list, &head, &tail)) {
        int arity, seg;
        const ERL_NIF_TERM *e;
        socklen_t alen;

        if (n >= MAX_MSGS)
            return enif_make_badarg(env);
        if (!enif_get_tuple(env, head, &arity, &e) || arity != 4)
            return enif_make_badarg(env);
        if (!fill_sockaddr(env, e[0], e[1], &addrs[n], &alen))
            return enif_make_badarg(env);
        if (!enif_inspect_iolist_as_binary(env, e[2], &bins[n]))
            return enif_make_badarg(env);
        if (!enif_get_int(env, e[3], &seg) || seg < 0 || seg > 0xffff)
            return enif_make_badarg(env);

        iovs[n].iov_base = bins[n].data;
        iovs[n].iov_len = bins[n].size;

        memset(&msgs[n], 0, sizeof(msgs[n]));
        msgs[n].msg_hdr.msg_name = &addrs[n];
        msgs[n].msg_hdr.msg_namelen = alen;
        msgs[n].msg_hdr.msg_iov = &iovs[n];
        msgs[n].msg_hdr.msg_iovlen = 1;
        if (seg > 0) {
            struct cmsghdr *cm;
            msgs[n].msg_hdr.msg_control = cmsgbufs[n];
            msgs[n].msg_hdr.msg_controllen =
                CMSG_SPACE(sizeof(unsigned short));
            cm = CMSG_FIRSTHDR(&msgs[n].msg_hdr);
            cm->cmsg_level = SOL_UDP;
            cm->cmsg_type = UDP_SEGMENT;
            cm->cmsg_len = CMSG_LEN(sizeof(unsigned short));
            *(unsigned short *)CMSG_DATA(cm) = (unsigned short)seg;
        }
        n++;
        list = tail;
    }
    if (!enif_is_empty_list(env, list) || n == 0)
        return enif_make_badarg(env);

    do {
        sent = sendmmsg(fd, msgs, (unsigned int)n, 0);
    } while (sent < 0 && errno == EINTR);

    if (sent < 0)
        return enif_make_tuple2(env, am_error,
            enif_make_atom(env, sent == -1 && errno == EAGAIN
                ? "eagain" : "sendmmsg"));
    return enif_make_tuple2(env, am_ok, enif_make_int(env, sent));
}

static int
load(ErlNifEnv *env, void **priv, ERL_NIF_TERM info)
{
    (void)priv; (void)info;
    am_ok = enif_make_atom(env, "ok");
    am_error = enif_make_atom(env, "error");
    return 0;
}

static ErlNifFunc funcs[] = {
    {"send_many", 2, send_many, 0}
};

ERL_NIF_INIT(quic_mmsg, funcs, load, NULL, NULL, NULL)
