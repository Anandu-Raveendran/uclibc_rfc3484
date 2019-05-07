/*
 * This code is a combination of code from uclibc-0.9.33.2 and glibc-2.29
 * modified by Anandu
 * This code adds the rfc3484 capabilities to uclibc.
 */

/*
 * Copyright 1996 by Craig Metz
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 * Portions from the GNU C library,
 * Copyright (C) 2003, 2006 Free Software Foundation, Inc.
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

/* $USAGI: getaddrinfo.c,v 1.16 2001/10/04 09:52:03 sekiya Exp $ */

/* The Inner Net License, Version 2.00

   The author(s) grant permission for redistribution and use in source and
   binary forms, with or without modification, of the software and documentation
   provided that the following conditions are met:

   0. If you receive a version of the software that is specifically labelled
   as not being for redistribution (check the version message and/or README),
   you are not permitted to redistribute that version of the software in any
   way or form.
   1. All terms of the all other applicable copyrights and licenses must be
   followed.
   2. Redistributions of source code must retain the authors' copyright
   notice(s), this list of conditions, and the following disclaimer.
   3. Redistributions in binary form must reproduce the authors' copyright
   notice(s), this list of conditions, and the following disclaimer in the
   documentation and/or other materials provided with the distribution.
   4. All advertising materials mentioning features or use of this software
   must display the following acknowledgement with the name(s) of the
   authors as specified in the copyright notice(s) substituted where
indicated:

This product includes software developed by <name(s)>, The Inner
Net, and other contributors.

5. Neither the name(s) of the author(s) nor the names of its contributors
may be used to endorse or promote products derived from this software
without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY ITS AUTHORS AND CONTRIBUTORS ``AS IS'' AND ANY
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

If these license terms cause you a real problem, contact the author.  */

#define __FORCE_GLIBC
#include <features.h>
#include <assert.h>
#include <errno.h>
#include <netdb.h>
#ifdef __UCLIBC_HAS_TLS__
#include <tls.h>
#endif
#include <ctype.h>
#include <resolv.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/utsname.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <alloca.h>
#include "netlinkaccess.h"

#define GAIH_OKIFUNSPEC 0x0100
#define GAIH_EAI        ~(GAIH_OKIFUNSPEC)

#ifndef UNIX_PATH_MAX
#define UNIX_PATH_MAX  108
#endif

#ifdef __UCLIBC_HAS_LFS__
# define __libc_open                    open64
# define __fxstat64(vers, fd, buf)      fstat64(fd, buf)
#else
# define __libc_open                    open
# define __fxstat64(vers, fd, buf)      fstat(fd, buf)
# define stat64                         stat
#endif

#define AI_DEFAULT    (AI_V4MAPPED | AI_ADDRCONFIG)

#undef DEBUG
/* #define DEBUG */

#ifdef DEBUG
#define DPRINTF(X,args...) do { fprintf( stderr, "\n%s ", __func__); fprintf( stderr, X, ##args); } while(0)

char* print_sockaddr( struct sockaddr_in *sa){

	if(sa == NULL)
		printf("printf_sockaddr sa is NULL");
          char str[INET6_ADDRSTRLEN];
          inet_ntop(AF_INET, &sa->sin_addr, str, INET6_ADDRSTRLEN);
	  return str;
  }
char* print_sockaddr_in6( struct sockaddr_in6 *sa){

	if(sa == NULL)
		printf("printf_sockaddr sa is NULL");
          //print in6addrinfo in6ai
          char str[INET6_ADDRSTRLEN];
          inet_ntop(AF_INET6, &sa->sin6_addr, str, INET6_ADDRSTRLEN);
	  return str;
  }

void print_addrinfo(struct addrinfo* result)
{
	char addr[1024];
	struct addrinfo  *rp;
	int s;
	for (rp = result; rp != NULL; rp = rp->ai_next) {
		s = getnameinfo(rp->ai_addr, rp->ai_addrlen, addr, sizeof addr, NULL, 0, NI_NUMERICHOST);
		if (s != 0) {
			printf("getnameinfo error:%d\n", s);
			continue;
		}
		printf("addr: %s\n", addr);
	}
}

#else 	// No debug
#define DPRINTF(X,args...)
#endif

struct in6addrinfo
{
    enum {
        in6ai_deprecated = 1,
        in6ai_homeaddress = 2
    } flags:8;
    uint8_t prefixlen;
    uint16_t :16;
    uint32_t index;
    uint32_t addr[4];
};

#ifndef IFA_F_HOMEADDRESS
# define IFA_F_HOMEADDRESS 0
#endif
#ifndef IFA_F_OPTIMISTIC
# define IFA_F_OPTIMISTIC 0
#endif

struct cached_data
{
    uint32_t timestamp;
    uint32_t usecnt;
    bool seen_ipv4;
    bool seen_ipv6;
    size_t in6ailen;
    struct in6addrinfo in6ai[0];
};

static struct cached_data noai6ai_cached =
{
    .usecnt = 1,	/* Make sure we never try to delete this entry.  */
    .in6ailen = 0
};

static struct cached_data *cache;
__libc_lock_define_initialized (static, lock);


static uint32_t nl_timestamp;

uint32_t __bump_nl_timestamp (void)
{
	
    DPRINTF("");
    if (atomic_increment_val (&nl_timestamp) == 0)
        atomic_increment (&nl_timestamp);

    DPRINTF("End");
    return nl_timestamp;
}

static inline uint32_t get_nl_timestamp (void)
{
    return nl_timestamp;
}

static inline bool cache_valid_p (void)
{
    DPRINTF("");
    if (cache != NULL)
    {
        uint32_t timestamp = get_nl_timestamp ();
    DPRINTF("End %d", (timestamp != 0 && cache->timestamp == timestamp));
        return timestamp != 0 && cache->timestamp == timestamp;
    }
    DPRINTF("End false");
    return false;
}

void __free_in6ai (struct in6addrinfo *ai)
{
    DPRINTF("");
    if (ai != NULL)
    {
        struct cached_data *data =
            (struct cached_data *) ((char *) ai
                    - offsetof (struct cached_data, in6ai));

        if (atomic_add_zero (&data->usecnt, -1))
        {
            __libc_lock_lock (lock);

            if (data->usecnt == 0)
                /* Still unused.  */

    		DPRINTF("free cashed_data size %d", sizeof(data));
                free (data);

            __libc_lock_unlock (lock);
        }
    }
}

static struct cached_data * make_request (int fd, pid_t pid)
{
    struct cached_data *result = NULL;

    size_t result_len = 0;
    size_t result_cap = 32;

    DPRINTF(" fd %d, pid %d ", fd, pid);
    struct req
    {
        struct nlmsghdr nlh;
        struct rtgenmsg g;
        /* struct rtgenmsg consists of a single byte.  This means there
           are three bytes of padding included in the REQ definition.
           We make them explicit here.  */
        char pad[3];
    } req;
    struct sockaddr_nl nladdr;

    req.nlh.nlmsg_len = sizeof (req);
    req.nlh.nlmsg_type = RTM_GETADDR;
    req.nlh.nlmsg_flags = NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST;
    req.nlh.nlmsg_pid = 0;
    req.nlh.nlmsg_seq = time (NULL);
    req.g.rtgen_family = AF_UNSPEC;

    assert (sizeof (req) - offsetof (struct req, pad) == 3);
    memset (req.pad, '\0', sizeof (req.pad));

    memset (&nladdr, '\0', sizeof (nladdr));
    nladdr.nl_family = AF_NETLINK;

#ifdef PAGE_SIZE
    const size_t buf_size = PAGE_SIZE;
#else
    const size_t buf_size = 4096;
#endif
    char buf[buf_size];

    struct iovec iov = { buf, buf_size };

    if (TEMP_FAILURE_RETRY (sendto (fd, (void *) &req, sizeof (req), 0,
                    (struct sockaddr *) &nladdr,
                    sizeof (nladdr))) < 0)
        goto out_fail;

    bool done = false;
    bool seen_ipv6 = false;
    bool seen_ipv4 = false;

    do
    {
        struct msghdr msg =
        {
            .msg_name = (void *) &nladdr,
            .msg_namelen =  sizeof (nladdr),
            .msg_iov = &iov,
            .msg_iovlen = 1,
            .msg_control = NULL,
            .msg_controllen = 0,
            .msg_flags = 0
        };

        ssize_t read_len = TEMP_FAILURE_RETRY (recvmsg (fd, &msg, 0));
        /* __netlink_assert_response (fd, read_len); */
        if (read_len < 0)
            goto out_fail;
        if (msg.msg_flags & MSG_TRUNC)
            goto out_fail;
        struct nlmsghdr *nlmh;
        for (nlmh = (struct nlmsghdr *) buf;
                NLMSG_OK (nlmh, (size_t) read_len);
                nlmh = (struct nlmsghdr *) NLMSG_NEXT (nlmh, read_len))
        {
            if (nladdr.nl_pid != 0 || (pid_t) nlmh->nlmsg_pid != pid
                    || nlmh->nlmsg_seq != req.nlh.nlmsg_seq)
                continue;

            if (nlmh->nlmsg_type == RTM_NEWADDR)
            {
                struct ifaddrmsg *ifam = (struct ifaddrmsg *) NLMSG_DATA (nlmh);
                struct rtattr *rta = IFA_RTA (ifam);
                size_t len = nlmh->nlmsg_len - NLMSG_LENGTH (sizeof (*ifam));

                if (ifam->ifa_family != AF_INET
                        && ifam->ifa_family != AF_INET6)
                    continue;

                const void *local = NULL;
                const void *address = NULL;
                while (RTA_OK (rta, len))
                {
                    switch (rta->rta_type)
                    {
                        case IFA_LOCAL:
                            local = RTA_DATA (rta);
                            break;

                        case IFA_ADDRESS:
                            address = RTA_DATA (rta);
                            goto out;
                    }

                    rta = RTA_NEXT (rta, len);
                }

                if (local != NULL)
                {
                    address = local;
out:
                    if (ifam->ifa_family == AF_INET)
                    {
                        if (*(const in_addr_t *) address
                                != htonl (INADDR_LOOPBACK))
                            seen_ipv4 = true;
                    }
                    else
                    {
                        if (!IN6_IS_ADDR_LOOPBACK (address))
                            seen_ipv6 = true;
                    }
                }

                if (result_len == 0 || result_len == result_cap)
                {
                    result_cap = 2 * result_cap;
                    result = realloc (result, sizeof (*result)
                            + result_cap
                            * sizeof (struct in6addrinfo));
                }

                if (!result)
                    goto out_fail;

                struct in6addrinfo *info = &result->in6ai[result_len++];

                info->flags = (((ifam->ifa_flags
                                & (IFA_F_DEPRECATED | IFA_F_OPTIMISTIC))
                            ? in6ai_deprecated : 0)
                        | ((ifam->ifa_flags & IFA_F_HOMEADDRESS)
                            ? in6ai_homeaddress : 0));
                info->prefixlen = ifam->ifa_prefixlen;
                info->index = ifam->ifa_index;
                if (ifam->ifa_family == AF_INET)
                {
                    info->addr[0] = 0;
                    info->addr[1] = 0;
                    info->addr[2] = htonl (0xffff);
                    info->addr[3] = *(const in_addr_t *) address;
                }
                else
                    memcpy (info->addr, address, sizeof (info->addr));
            }
            else if (nlmh->nlmsg_type == NLMSG_DONE)
                /* We found the end, leave the loop.  */
                done = true;
        }
    }
    while (! done);

    if (seen_ipv6 && result != NULL)
    {
        result->timestamp = get_nl_timestamp ();
        result->usecnt = 2;
        result->seen_ipv4 = seen_ipv4;
        result->seen_ipv6 = true;
        result->in6ailen = result_len;
    }
    else
    {
        free (result);
        atomic_add (&noai6ai_cached.usecnt, 2);
        noai6ai_cached.seen_ipv4 = seen_ipv4;
        noai6ai_cached.seen_ipv6 = seen_ipv6;
        result = &noai6ai_cached;
    }

    DPRINTF("End");
    return result;

out_fail:

    DPRINTF("End out_fail");
    free (result);
    return NULL;
}


void attribute_hidden check_pf (bool *seen_ipv4, bool *seen_ipv6,
        struct in6addrinfo **in6ai, size_t *in6ailen)
{
    *in6ai = NULL;
    *in6ailen = 0;

    struct cached_data *olddata = NULL;
    struct cached_data *data = NULL;
    DPRINTF("");

    __libc_lock_lock (lock);

    if (cache_valid_p ())
    {
        data = cache;
        atomic_increment (&cache->usecnt);
    }
    else
    {
        int fd = socket (PF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);

        if ((fd >= 0))
        {
	    DPRINTF("socket opened");
            struct sockaddr_nl nladdr;
            memset (&nladdr, '\0', sizeof (nladdr));
            nladdr.nl_family = AF_NETLINK;

	    socklen_t addr_len = sizeof (nladdr);

            if (bind (fd, (struct sockaddr *) &nladdr, sizeof (nladdr)) == 0
                    && getsockname (fd, (struct sockaddr *) &nladdr,
                        &addr_len) == 0)
            { 

    		DPRINTF("bind success");
                data = make_request (fd, nladdr.nl_pid);
            }
            close (fd);
        }

        if (data != NULL)
        {
            olddata = cache;
            cache = data;
        }
    }

    __libc_lock_unlock (lock);

    if (data != NULL)
    {
        /* It worked.  */
        *seen_ipv4 = data->seen_ipv4;
        *seen_ipv6 = data->seen_ipv6;
        *in6ailen = data->in6ailen;
        *in6ai = data->in6ai;

        if (olddata != NULL && olddata->usecnt > 0
                && atomic_add_zero (&olddata->usecnt, -1))
            free (olddata);

	DPRINTF("End seen_ipv4 %d, seen_ipv6 %d", *seen_ipv4, *seen_ipv6);
        return;
    }

    /* We cannot determine what interfaces are available.  Be
       pessimistic.  */
    *seen_ipv4 = true;
    *seen_ipv6 = true;
   DPRINTF("End couldnt find so seen_ipv4 %d, seen_ipv6 %d", *seen_ipv4, *seen_ipv6);
}

/* Useful for having small structure members/global variables */
typedef int8_t socktype_t;
typedef int8_t family_t;
typedef int8_t protocol_t;
struct BUG_too_small {
    char BUG_socktype_t_too_small[(0
            | SOCK_STREAM
            | SOCK_DGRAM
            | SOCK_RAW
            ) <= 127 ? 1 : -1];
    char BUG_family_t_too_small[(0
            | AF_UNSPEC
            | AF_INET
            | AF_INET6
            ) <= 127 ? 1 : -1];
    char BUG_protocol_t_too_small[(0
            | IPPROTO_TCP
            | IPPROTO_UDP
            ) <= 127 ? 1 : -1];
};

struct gaih_service {
    const char *name;
    int num;
};

struct gaih_servtuple {
    struct gaih_servtuple *next;
    int socktype;
    int protocol;
    int port;
};

struct gaih_addrtuple {
    struct gaih_addrtuple *next;
    int family;
    char addr[16];
    uint32_t scopeid;
};

struct gaih_typeproto {
    socktype_t socktype;
    protocol_t protocol;
    int8_t protoflag;
    char name[4];
};
/* Values for `protoflag'.  */
#define GAI_PROTO_NOSERVICE 1
#define GAI_PROTO_PROTOANY  2

static const struct gaih_typeproto gaih_inet_typeproto[] = {
    { 0          , 0          , 0, ""    },
    { SOCK_STREAM, IPPROTO_TCP, 0, "tcp" },
    { SOCK_DGRAM , IPPROTO_UDP, 0, "udp" },
    { SOCK_RAW   , 0          , GAI_PROTO_PROTOANY|GAI_PROTO_NOSERVICE, "raw" },
    { 0          , 0          , 0, ""    },
};

struct gaih {
    int family;
    int (*gaih)(const char *name, const struct gaih_service *service,
            const struct addrinfo *req, struct addrinfo **pai);
};


static int in6aicmp (const void *p1, const void *p2)
{
    struct in6addrinfo *a1 = (struct in6addrinfo *) p1;
    struct in6addrinfo *a2 = (struct in6addrinfo *) p2;

    return memcmp (a1->addr, a2->addr, sizeof (a1->addr));
}


#define SEEN_IPV4 1
#define SEEN_IPV6 2

int get_br0_scopeid()
{

    struct ifaddrs *ifa;
    struct ifaddrs *runp;
    DPRINTF(" checking for br0");

    /* Get the interface list via getifaddrs.  */
    if (getifaddrs(&ifa) != 0) {
        /* We cannot determine what interfaces are available.
         * Be optimistic.  */
    }

    for (runp = ifa; runp != NULL; runp = runp->ifa_next) {
        if (runp->ifa_addr == NULL)
            continue;

        if (runp->ifa_addr->sa_family == PF_INET6)
        {

            char str[INET6_ADDRSTRLEN];
            struct sockaddr_in6 *sa = ((struct sockaddr_in6 * )runp->ifa_addr);
            inet_ntop(AF_INET6, &sa->sin6_addr, str, INET6_ADDRSTRLEN);

            if(strcmp(runp->ifa_name, "br0")==0)
            {
                if(IN6_IS_ADDR_LINKLOCAL(&sa->sin6_addr))
                {
    		    DPRINTF("End scope_id %d", sa->sin6_scope_id);
                    return sa->sin6_scope_id;
                }
            }
        }
    }
    freeifaddrs(ifa);
    DPRINTF("End return scope id 0");
    return 0;
}


static int gaih_inet_serv(const char *servicename, const struct gaih_typeproto *tp,
        const struct addrinfo *req, struct gaih_servtuple *st)
{
    struct servent *s;
    size_t tmpbuflen = 1024;
    struct servent ts;
    char *tmpbuf;
    int r;

    DPRINTF("service %s", servicename);
    while (1) {
        tmpbuf = alloca(tmpbuflen);
        r = getservbyname_r(servicename, tp->name, &ts, tmpbuf, tmpbuflen, &s);
        if (r == 0 && s != NULL)
            break;
        if (r != ERANGE)
            return (GAIH_OKIFUNSPEC | -EAI_SERVICE);
        tmpbuflen *= 2;
    }
    st->next = NULL;
    st->socktype = tp->socktype;
    st->protocol = ((tp->protoflag & GAI_PROTO_PROTOANY) ? req->ai_protocol : tp->protocol);
    st->port = s->s_port;
    DPRINTF("End return 0");
    return 0;
}

/* NB: also uses h,pat,rc,no_data variables */
#define gethosts(_family, _type)						\
{										\
    int i, herrno;								\
    size_t tmpbuflen;							        \
    struct hostent th;                                                          \
    char *tmpbuf;								\
    \
    DPRINTF("gethosts");  								\
    tmpbuflen = 512;							        \
    no_data = 0;								\
    do {									\
        tmpbuflen *= 2;							        \
        tmpbuf = alloca(tmpbuflen);					        \
        rc = gethostbyname2_r(name, _family, &th, tmpbuf,tmpbuflen, &h, &herrno);		\
    } while (rc == ERANGE && herrno == NETDB_INTERNAL);			        \
    if (rc != 0) {								\
        if (herrno == NETDB_INTERNAL) {					        \
            __set_h_errno(herrno);					        \
            return -EAI_SYSTEM;					                \
        }								        \
        if (herrno == TRY_AGAIN)					        \
        no_data = EAI_AGAIN;					                \
        else								        \
        no_data = (herrno == NO_DATA);				                \
    } else if (h != NULL) {							\
        for (i = 0; h->h_addr_list[i] &&  h->h_addr_list[i] != NULL ; i++) {    \
            if (*pat == NULL) {					                \
                *pat = alloca(sizeof(struct gaih_addrtuple));	                \
                (*pat)->scopeid = 0;				                \
            }							                \
            (*pat)->next = NULL;					        \
            (*pat)->family = _family;				                \
            memcpy((*pat)->addr, h->h_addr_list[i], sizeof(_type));	        \
            pat = &((*pat)->next);					        \
        }								        \
    }									        \
	DPRINTF("End gethosts"); 						\
}

static int gaih_inet(const char *name, const struct gaih_service *service,
        const struct addrinfo *req, bool seen_ipv4, bool seen_ipv6, struct addrinfo **pai, unsigned int *naddrs )
{
    struct gaih_servtuple nullserv;

    const struct gaih_typeproto *tp;
    struct gaih_servtuple *st;
    struct gaih_addrtuple *at;
    int rc;
    int v4mapped = (req->ai_family == PF_UNSPEC || req->ai_family == PF_INET6)
        && (req->ai_flags & AI_V4MAPPED);

    DPRINTF("name %s", name);
    memset(&nullserv, 0, sizeof(nullserv));

    tp = gaih_inet_typeproto;
    if (req->ai_protocol || req->ai_socktype) {
        ++tp;
        while (tp->name[0]) {
            if ((req->ai_socktype == 0 || req->ai_socktype == tp->socktype)
                    && (req->ai_protocol == 0 || req->ai_protocol == tp->protocol || (tp->protoflag & GAI_PROTO_PROTOANY))
               ) {
                goto found;
            }
            ++tp;
        }
        if (req->ai_socktype)
            return (GAIH_OKIFUNSPEC | -EAI_SOCKTYPE);
        return (GAIH_OKIFUNSPEC | -EAI_SERVICE);
found: ;
    }

    st = &nullserv;
    if (service != NULL) {
        if ((tp->protoflag & GAI_PROTO_NOSERVICE) != 0)
            return (GAIH_OKIFUNSPEC | -EAI_SERVICE);

        if (service->num < 0) {
            if (tp->name[0]) {
                st = alloca(sizeof(struct gaih_servtuple));
                rc = gaih_inet_serv(service->name, tp, req, st);
                if (rc)
                    return rc;
            } else {
                struct gaih_servtuple **pst = &st;
                for (tp++; tp->name[0]; tp++) {
                    struct gaih_servtuple *newp;

                    if ((tp->protoflag & GAI_PROTO_NOSERVICE) != 0)
                        continue;

                    if (req->ai_socktype != 0 && req->ai_socktype != tp->socktype)
                        continue;
                    if (req->ai_protocol != 0
                            && !(tp->protoflag & GAI_PROTO_PROTOANY)
                            && req->ai_protocol != tp->protocol)
                        continue;

                    newp = alloca(sizeof(struct gaih_servtuple));
                    rc = gaih_inet_serv(service->name, tp, req, newp);
                    if (rc) {
                        if (rc & GAIH_OKIFUNSPEC)
                            continue;
                        return rc;
                    }

                    *pst = newp;
                    pst = &(newp->next);
                }
                if (st == &nullserv)
                    return (GAIH_OKIFUNSPEC | -EAI_SERVICE);
            }
        } else {
            st = alloca(sizeof(struct gaih_servtuple));
            st->next = NULL;
            st->socktype = tp->socktype;
            st->protocol = ((tp->protoflag & GAI_PROTO_PROTOANY)
                    ? req->ai_protocol : tp->protocol);
            st->port = htons(service->num);
        }
    } else if (req->ai_socktype || req->ai_protocol) {
        st = alloca(sizeof(struct gaih_servtuple));
        st->next = NULL;
        st->socktype = tp->socktype;
        st->protocol = ((tp->protoflag & GAI_PROTO_PROTOANY)
                ? req->ai_protocol : tp->protocol);
        st->port = 0;
    } else {
        /*
         * Neither socket type nor protocol is set.  Return all socket types
         * we know about.
         */
        struct gaih_servtuple **lastp = &st;
        for (++tp; tp->name[0]; ++tp) {
            struct gaih_servtuple *newp;

            newp = alloca(sizeof(struct gaih_servtuple));
            newp->next = NULL;
            newp->socktype = tp->socktype;
            newp->protocol = tp->protocol;
            newp->port = 0;

            *lastp = newp;
            lastp = &newp->next;
        }
    }

    at = NULL;
    if (name != NULL) {
        at = alloca(sizeof(struct gaih_addrtuple));
        at->family = AF_UNSPEC;
        at->scopeid = 0;
        at->next = NULL;

        if (inet_pton(AF_INET, name, at->addr) > 0) {
            if (req->ai_family != AF_UNSPEC && req->ai_family != AF_INET && !v4mapped)
                return -EAI_FAMILY;
            at->family = AF_INET;
        }

#if defined __UCLIBC_HAS_IPV6__
        if (at->family == AF_UNSPEC) {
            char *namebuf = strdupa(name);
            char *scope_delim;

            scope_delim = strchr(namebuf, SCOPE_DELIMITER);
            if (scope_delim != NULL)
                *scope_delim = '\0';

            if (inet_pton(AF_INET6, namebuf, at->addr) > 0) {
                if (req->ai_family != AF_UNSPEC && req->ai_family != AF_INET6)
                    return -EAI_FAMILY;

                at->family = AF_INET6;
                if (scope_delim != NULL) {
                    int try_numericscope = 0;
                    uint32_t *a32 = (uint32_t*)at->addr;
                    if (IN6_IS_ADDR_LINKLOCAL(a32) || IN6_IS_ADDR_MC_LINKLOCAL(at->addr)) {
                        at->scopeid = if_nametoindex(scope_delim + 1);
                        if (at->scopeid == 0)
                            try_numericscope = 1;
                    } else
                        try_numericscope = 1;

                    if (try_numericscope != 0) {
                        char *end;
                        assert(sizeof(uint32_t) <= sizeof(unsigned long));
                        at->scopeid = (uint32_t)strtoul(scope_delim + 1, &end, 10);
                        if (*end != '\0')
                            return (GAIH_OKIFUNSPEC | -EAI_NONAME);
                    }
                }
            }
        }
#endif

        if (at->family == AF_UNSPEC && !(req->ai_flags & AI_NUMERICHOST)) {
            struct hostent *h;
            struct gaih_addrtuple **pat = &at;
            int no_data = 0;
            int no_inet6_data;

            /*
             * If we are looking for both IPv4 and IPv6 address we don't want
             * the lookup functions to automatically promote IPv4 addresses to
             * IPv6 addresses.
             */
#if defined __UCLIBC_HAS_IPV6__
            if (req->ai_family == AF_UNSPEC || req->ai_family == AF_INET6)
                if (!(req->ai_flags & AI_ADDRCONFIG) || (seen_ipv6))
                    gethosts(AF_INET6, struct in6_addr);
#endif
            no_inet6_data = no_data;

            if (req->ai_family == AF_INET
                    || (!v4mapped && req->ai_family == AF_UNSPEC)
                    || (v4mapped && (no_inet6_data != 0 || (req->ai_flags & AI_ALL)))
               ) {
                if (!(req->ai_flags & AI_ADDRCONFIG) || (seen_ipv4))
                    gethosts(AF_INET, struct in_addr);
            }

            if (no_data != 0 && no_inet6_data != 0) {
                /* If both requests timed out report this. */
                if (no_data == EAI_AGAIN && no_inet6_data == EAI_AGAIN)
                    return -EAI_AGAIN;
                /*
                 * We made requests but they turned out no data.
                 * The name is known, though.
                 */
                return (GAIH_OKIFUNSPEC | -EAI_AGAIN);
            }
        }

        if (at->family == AF_UNSPEC)
            return (GAIH_OKIFUNSPEC | -EAI_NONAME);
    } else {
        struct gaih_addrtuple *atr;

        atr = at = alloca(sizeof(struct gaih_addrtuple));
        memset(at, '\0', sizeof(struct gaih_addrtuple));
        if (req->ai_family == 0) {
            at->next = alloca(sizeof(struct gaih_addrtuple));
            memset(at->next, '\0', sizeof(struct gaih_addrtuple));
        }
#if defined __UCLIBC_HAS_IPV6__
        if (req->ai_family == 0 || req->ai_family == AF_INET6) {
            at->family = AF_INET6;
            if ((req->ai_flags & AI_PASSIVE) == 0)
                memcpy(at->addr, &in6addr_loopback, sizeof(struct in6_addr));
            atr = at->next;
        }
#endif
        if (req->ai_family == 0 || req->ai_family == AF_INET) {
            atr->family = AF_INET;
            if ((req->ai_flags & AI_PASSIVE) == 0) {
                uint32_t *a = (uint32_t*)atr->addr;
                *a = htonl(INADDR_LOOPBACK);
            }
        }
    }

    if (pai == NULL)
    {
	    DPRINTF("pai is NULL");
	    return 0;
    }
    {
        const char *c = NULL;
        struct gaih_servtuple *st2;
        struct gaih_addrtuple *at2 = at;
        size_t socklen, namelen;
        sa_family_t family;

        /*
         * buffer is the size of an unformatted IPv6 address in
         * printable format.
         */
        char buffer[sizeof("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255")];

        while (at2 != NULL) {
            c = inet_ntop(at2->family, at2->addr, buffer, sizeof(buffer));
            if (c) {
                namelen = strlen(c) + 1;
            } else if (req->ai_flags & AI_CANONNAME) {
                struct hostent *h = NULL;
                int herrno;
                struct hostent th;
                size_t tmpbuflen = 512;
                char *tmpbuf;

                /* Hint says numeric, but address is not */
                if (req->ai_flags & AI_NUMERICHOST)
                    return -EAI_NONAME;

                do {
                    tmpbuflen *= 2;
                    tmpbuf = alloca(tmpbuflen);
                    rc = gethostbyaddr_r(at2->addr,
#ifdef __UCLIBC_HAS_IPV6__
                            ((at2->family == AF_INET6)
                             ? sizeof(struct in6_addr)
                             : sizeof(struct in_addr)),
#else
                            sizeof(struct in_addr),
#endif
                            at2->family,
                            &th, tmpbuf, tmpbuflen,
                            &h, &herrno);
                } while (rc == ERANGE && herrno == NETDB_INTERNAL);

                if (rc != 0 && herrno == NETDB_INTERNAL) {
                    __set_h_errno(herrno);
                    return -EAI_SYSTEM;
                }

                if (h != NULL)
                    c = h->h_name;

                if (c == NULL)
                    return (GAIH_OKIFUNSPEC | -EAI_NONAME);

                namelen = strlen(c) + 1;
            } else
                namelen = 0;

#if defined __UCLIBC_HAS_IPV6__
            if (at2->family == AF_INET6 || v4mapped) {
                family = AF_INET6;
                socklen = sizeof(struct sockaddr_in6);
            }
#endif
#if defined __UCLIBC_HAS_IPV4__ && defined __UCLIBC_HAS_IPV6__
            else
#endif
#if defined __UCLIBC_HAS_IPV4__
            {
                family = AF_INET;
                socklen = sizeof(struct sockaddr_in);
            }
#endif
            for (st2 = st; st2 != NULL; st2 = st2->next) {
                if (req->ai_flags & AI_ADDRCONFIG) {
                    if (family == AF_INET && !(seen_ipv4))
                        break;
#if defined __UCLIBC_HAS_IPV6__
                    else if (family == AF_INET6 && !(seen_ipv6))
                        break;
#endif
                }
                *pai = malloc(sizeof(struct addrinfo) + socklen + namelen);
                if (*pai == NULL)
                    return -EAI_MEMORY;

                (*pai)->ai_flags = req->ai_flags;
                (*pai)->ai_family = family;
                (*pai)->ai_socktype = st2->socktype;
                (*pai)->ai_protocol = st2->protocol;
                (*pai)->ai_addrlen = socklen;
                (*pai)->ai_addr = (void *) (*pai) + sizeof(struct addrinfo);
#if defined SALEN
                (*pai)->ai_addr->sa_len = socklen;
#endif
                (*pai)->ai_addr->sa_family = family;

#if defined __UCLIBC_HAS_IPV6__
                if (family == AF_INET6)	{
                    struct sockaddr_in6 *sin6p = (struct sockaddr_in6 *) (*pai)->ai_addr;

                    sin6p->sin6_flowinfo = 0;
                    if (at2->family == AF_INET6) {
                        memcpy(&sin6p->sin6_addr,
                                at2->addr, sizeof(struct in6_addr));
                    } else {
                        sin6p->sin6_addr.s6_addr32[0] = 0;
                        sin6p->sin6_addr.s6_addr32[1] = 0;
                        sin6p->sin6_addr.s6_addr32[2] = htonl(0x0000ffff);
                        memcpy(&sin6p->sin6_addr.s6_addr32[3],
                                at2->addr, sizeof(sin6p->sin6_addr.s6_addr32[3]));
                    }
                    sin6p->sin6_port = st2->port;
                    sin6p->sin6_scope_id = at2->scopeid;
#ifdef DEBUG
		    print_sockaddr_in6(&sin6p);
#endif
                }
#endif
#if defined __UCLIBC_HAS_IPV4__ && defined __UCLIBC_HAS_IPV6__
                else
#endif
#if defined __UCLIBC_HAS_IPV4__
                {
                    struct sockaddr_in *sinp = (struct sockaddr_in *) (*pai)->ai_addr;

                    memcpy(&sinp->sin_addr, at2->addr, sizeof(struct in_addr));
                    sinp->sin_port = st2->port;
                    memset(sinp->sin_zero, '\0', sizeof(sinp->sin_zero));
#ifdef DEBUG
		    print_sockaddr(&sinp);
#endif
                }
#endif
                if (c) {
                    (*pai)->ai_canonname = ((void *) (*pai) +
                            sizeof(struct addrinfo) + socklen);
                    strcpy((*pai)->ai_canonname, c);
                } else {
                    (*pai)->ai_canonname = NULL;
                }
                (*pai)->ai_next = NULL;
                pai = &((*pai)->ai_next);
            }
            ++*naddrs;
            at2 = at2->next;
        }
    }
    DPRINTF("End return naddrs %d", naddrs);
    return 0;
}


struct sort_result
{
    struct addrinfo *dest_addr;
    /* Using sockaddr_storage is for now overkill.  We only support IPv4
     * and IPv6 so far.  If this changes at some point we can adjust the
     * type here.  */
    struct sockaddr_in6 source_addr;
    uint8_t source_addr_len;
    bool got_source_addr;
    uint8_t source_addr_flags;
    uint8_t prefixlen;
    uint32_t index;
    int32_t native;
};

struct sort_result_combo
{
    struct sort_result *results;
    int nresults;
};


#if __BYTE_ORDER == __BIG_ENDIAN
# define htonl_c(n) n
#else
# define htonl_c(n) __bswap_constant_32 (n)
#endif

static const struct scopeentry
{
    union
    {
        char addr[4];
        uint32_t addr32;
    };
    uint32_t netmask;
    int32_t scope;
} default_scopes[] =
{
    /* Link-local addresses: scope 2.  */
    { { { 169, 254, 0, 0 } }, htonl_c (0xffff0000), 2 },
    { { { 127, 0, 0, 0 } }, htonl_c (0xff000000), 2 },
    /* Site-local addresses: scope 5.  */
    { { { 10, 0, 0, 0 } }, htonl_c (0xff000000), 5 },
    { { { 172, 16, 0, 0 } }, htonl_c (0xfff00000), 5 },
    { { { 192, 168, 0, 0 } }, htonl_c (0xffff0000), 5 },
    /* Default: scope 14.  */
    { { { 0, 0, 0, 0 } }, htonl_c (0x00000000), 14 }
};

/* The label table.  */
static const struct scopeentry *scopes;

static int get_scope (const struct sockaddr_in6 *in6)
{
    int scope;
#ifdef DEBUG
    DPRINTF("in6 %s", print_sockaddr_in6(in6));
#endif
    if (in6->sin6_family == PF_INET6)
    {
	DPRINTF("in6 family");
        if (! IN6_IS_ADDR_MULTICAST (&in6->sin6_addr))
        {
		DPRINTF("multicast");
            if (IN6_IS_ADDR_LINKLOCAL (&in6->sin6_addr)
                    /* RFC 4291 2.5.3 says that the loopback address is to be
                     * treated like a link-local address.  */
                    || IN6_IS_ADDR_LOOPBACK (&in6->sin6_addr))
                scope = 2;
            else if (IN6_IS_ADDR_SITELOCAL (&in6->sin6_addr))
                scope = 5;
            else
                /* XXX Is this the correct default behavior?  */
                scope = 14;
        }
        else
            scope = in6->sin6_addr.s6_addr[1] & 0xf;
    }
    else if (in6->sin6_family == AF_INET)
    {
        const struct sockaddr_in *in = (const struct sockaddr_in *) in6;

#ifdef DEBUG
	DPRINTF("ipv4 family %s", print_sockaddr(in));
#endif
        size_t cnt = 0;
        while (1)
        {
            if (in->sin_addr.s_addr == NULL)
		    DPRINTF("sin_addr is null");
            
	DPRINTF("while cnt %d netmask %d ", cnt, scopes[cnt].netmask);
	    if( (in->sin_addr.s_addr == NULL)||(scopes[cnt].netmask == NULL)||(scopes[cnt].addr32 == NULL))
	    {
		    DPRINTF("scope values are NULL");
		    return 14;
	    }
DPRINTF("null chesk done");
            if ((in->sin_addr.s_addr & scopes[cnt].netmask)
                    == scopes[cnt].addr32)
	    {
		    DPRINTF("End return scope %d", scopes[cnt].scope);
		    return scopes[cnt].scope;
	    }
		
            ++cnt;
        }
        /* NOTREACHED */
    }
    else
        /* XXX What is a good default?  */
        scope = 15;

    DPRINTF("End return scope %d", scope);
    return scope;
}

struct prefixentry
{
    struct in6_addr prefix;
    unsigned int bits;
    int val;
};

/* The label table.  */
static const struct prefixentry *labels;

/* Default labels.  */
static const struct prefixentry default_labels[] =
{
    /* See RFC 3484 for the details.  */
    { { .__in6_u
          = { .__u6_addr8 = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 } }
      }, 128, 0 },
    { { .__in6_u
          = { .__u6_addr8 = { 0x20, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } }
      }, 16, 2 },
    { { .__in6_u
          = { .__u6_addr8 = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } }
      }, 96, 3 },
    { { .__in6_u
          = { .__u6_addr8 = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00 } }
      }, 96, 4 },
    /* The next two entries differ from RFC 3484.  We need to treat
     * IPv6 site-local addresses special because they are never NATed,
     * unlike site-locale IPv4 addresses.  If this would not happen, on
     * machines which have only IPv4 and IPv6 site-local addresses, the
     * sorting would prefer the IPv6 site-local addresses, causing
     * unnecessary delays when trying to connect to a global IPv6 address
     * through a site-local IPv6 address.  */
    { { .__in6_u
          = { .__u6_addr8 = { 0xfe, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } }
      }, 10, 5 },
    { { .__in6_u
          = { .__u6_addr8 = { 0xfc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } }
      }, 7, 6 },
    /* Additional rule for Teredo tunnels.  */
    { { .__in6_u
          = { .__u6_addr8 = { 0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } }
      }, 32, 7 },
    { { .__in6_u
          = { .__u6_addr8 = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } }
      }, 0, 1 }
};

/* The precedence table.  */
static const struct prefixentry *precedence;

/* The default precedences.  */
static const struct prefixentry default_precedence[] =
{
    /* See RFC 3484 for the details.  */
    { { .__in6_u
          = { .__u6_addr8 = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 } }
      }, 128, 50 },
    { { .__in6_u
          = { .__u6_addr8 = { 0x20, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } }
      }, 16, 30 },
    { { .__in6_u
          = { .__u6_addr8 = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } }
      }, 96, 20 },
    { { .__in6_u
          = { .__u6_addr8 = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00 } }
      }, 96, 10 },
    { { .__in6_u
          = { .__u6_addr8 = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } }
      }, 0, 40 }
};

static int match_prefix (const struct sockaddr_in6 *in6,
        const struct prefixentry *list, int default_val)
{
    int idx;
    struct sockaddr_in6 in6_mem;

    DPRINTF("");
    if (in6->sin6_family == PF_INET)
    {
        const struct sockaddr_in *in = (const struct sockaddr_in *) in6;

        /* Construct a V4-to-6 mapped address.  */
        in6_mem.sin6_family = PF_INET6;
        in6_mem.sin6_port = in->sin_port;
        in6_mem.sin6_flowinfo = 0;
        memset (&in6_mem.sin6_addr, '\0', sizeof (in6_mem.sin6_addr));
        in6_mem.sin6_addr.s6_addr16[5] = 0xffff;
        in6_mem.sin6_addr.s6_addr32[3] = in->sin_addr.s_addr;
        in6_mem.sin6_scope_id = 0;

        in6 = &in6_mem;
    }
    else if (in6->sin6_family != PF_INET6)
        return default_val;

    for (idx = 0; ; ++idx)
    {
        unsigned int bits = list[idx].bits;
        const uint8_t *mask = list[idx].prefix.s6_addr;
        const uint8_t *val = in6->sin6_addr.s6_addr;

        while (bits >= 8)
        {
            if (*mask != *val)
                break;

            ++mask;
            ++val;
            bits -= 8;
        }

        if (bits < 8)
        {
            if ((*mask & (0xff00 >> bits)) == (*val & (0xff00 >> bits)))
                /* Match!  */
                break;
        }
    }

    DPRINTF("End return %d", list[idx].val);
    return list[idx].val;
}

static int get_label (const struct sockaddr_in6 *in6)
{
    /* XXX What is a good default value?  */
    return match_prefix (in6, labels, INT_MAX);
}


static int get_precedence (const struct sockaddr_in6 *in6)
{
    /* XXX What is a good default value?  */
    return match_prefix (in6, precedence, 0);
}


/* Find last bit set in a word.  */
static int fls (uint32_t a)
{
    uint32_t mask;
    int n;
    for (n = 0, mask = 1 << 31; n < 32; mask >>= 1, ++n)
        if ((a & mask) != 0)
            break;
    return n;
}


static int rfc3484_sort (const void *p1, const void *p2, void *arg)
{
    const size_t idx1 = *(const size_t *) p1;
    const size_t idx2 = *(const size_t *) p2;
    struct sort_result_combo *src = (struct sort_result_combo *) arg;
    struct sort_result *a1 = &src->results[idx1];
    struct sort_result *a2 = &src->results[idx2];
#ifdef DEBUG
    DPRINTF("idx1=%d idx2=%d a1=%s a2=%s", idx1, idx2, print_sockaddr_in6(a1->dest_addr->ai_addr), print_sockaddr_in6(a2->dest_addr->ai_addr));
#endif

    DPRINTF(" Rule 1: Avoid unusable destinations");
    /* Rule 1: Avoid unusable destinations.
     * We have the got_source_addr flag set if the destination is reachable.  */
    if (a1->got_source_addr && ! a2->got_source_addr)
        return -1;
    if (! a1->got_source_addr && a2->got_source_addr)
        return 1;


    DPRINTF("Rule 2: Prefer matching scope.");
    /* Rule 2: Prefer matching scope.  Only interesting if both
     * destination addresses are IPv6.  */
    int a1_dst_scope
        = get_scope ((struct sockaddr_in6 *) a1->dest_addr->ai_addr);

    int a2_dst_scope
        = get_scope ((struct sockaddr_in6 *) a2->dest_addr->ai_addr);

    if (a1->got_source_addr)
    {
        int a1_src_scope = get_scope (&a1->source_addr);
        int a2_src_scope = get_scope (&a2->source_addr);

        if (a1_dst_scope == a1_src_scope && a2_dst_scope != a2_src_scope)
            return -1;
        if (a1_dst_scope != a1_src_scope && a2_dst_scope == a2_src_scope)
            return 1;
    }


    DPRINTF("Rule 3: Avoid deprecated addresses.");
    /* Rule 3: Avoid deprecated addresses.  */
    if (a1->got_source_addr)
    {
        if (!(a1->source_addr_flags & in6ai_deprecated)
                && (a2->source_addr_flags & in6ai_deprecated))
            return -1;
        if ((a1->source_addr_flags & in6ai_deprecated)
                && !(a2->source_addr_flags & in6ai_deprecated))
            return 1;
    }
    DPRINTF("Rule 4: Prefer home address");
    /* Rule 4: Prefer home addresses. */ 
    if (a1->got_source_addr)
    {
        if (!(a1->source_addr_flags & in6ai_homeaddress)
                && (a2->source_addr_flags & in6ai_homeaddress))
            return 1;
        if ((a1->source_addr_flags & in6ai_homeaddress)
                && !(a2->source_addr_flags & in6ai_homeaddress))
            return -1;
    }

    DPRINTF("Rule 5: Prefer matching label");
    /* Rule 5: Prefer matching label.  */
    if (a1->got_source_addr)
    {
        int a1_dst_label
            = get_label ((struct sockaddr_in6 *) a1->dest_addr->ai_addr);
        int a1_src_label = get_label (&a1->source_addr);

        int a2_dst_label
            = get_label ((struct sockaddr_in6 *) a2->dest_addr->ai_addr);
        int a2_src_label = get_label (&a2->source_addr);

        if (a1_dst_label == a1_src_label && a2_dst_label != a2_src_label)
            return -1;
        if (a1_dst_label != a1_src_label && a2_dst_label == a2_src_label)
            return 1;
    }


    DPRINTF("Rule 6: prefer higher precedence");
    /* Rule 6: Prefer higher precedence.  */
    int a1_prec
        = get_precedence ((struct sockaddr_in6 *) a1->dest_addr->ai_addr);
    int a2_prec
        = get_precedence ((struct sockaddr_in6 *) a2->dest_addr->ai_addr);
    if (a1_prec > a2_prec)
        return -1;
    if (a1_prec < a2_prec)
        return 1;


    DPRINTF("Rule 7: prefer native support");
    /* Rule 7: Prefer native transport.  */
    if (a1->got_source_addr)
    {
        /* The same interface index means the same interface which means
         * there is no difference in transport.  This should catch many
         * (most?) cases.  */
        if (a1->index != a2->index)
        {
            int a1_native = a1->native;
            int a2_native = a2->native;

            if (a1_native == -1 || a2_native == -1)
            {
                uint32_t a1_index;
                if (a1_native == -1)
                {
                    /* If we do not have the information use 'native' as
                     * the default.  */
                    a1_native = 0;
                    a1_index = a1->index;
                }
                else
                    a1_index = 0xffffffffu;

                uint32_t a2_index;
                if (a2_native == -1)
                {
                    /* If we do not have the information use 'native' as
                     * the default.  */
                    a2_native = 0;
                    a2_index = a2->index;
                }
                else
                    a2_index = 0xffffffffu;

                /* Check native is not implemented completely */
                /* __check_native (a1_index, &a1_native, a2_index, &a2_native); */

                /* Fill in the results in all the records.  */
                for (int i = 0; i < src->nresults; ++i)
                    if (src->results[i].index == a1_index)
                    {
                        assert (src->results[i].native == -1
                                || src->results[i].native == a1_native);
                        src->results[i].native = a1_native;
                    }
                    else if (src->results[i].index == a2_index)
                    {
                        assert (src->results[i].native == -1
                                || src->results[i].native == a2_native);
                        src->results[i].native = a2_native;
                    }
            }
            if (a1_native && !a2_native)
                return -1;
        }
    }


    DPRINTF("Rule 8: Prefer smaller scope");
    /* Rule 8: Prefer smaller scope.  */
    if (a1_dst_scope < a2_dst_scope)
        return -1;
    if (a1_dst_scope > a2_dst_scope)
        return 1;

    DPRINTF("Rule 9 use longest matching prefix");
    /* Rule 9: Use longest matching prefix.  */
    if (a1->got_source_addr
            && a1->dest_addr->ai_family == a2->dest_addr->ai_family)
    {
        int bit1 = 0;
        int bit2 = 0;


        if (a1->dest_addr->ai_family == PF_INET)
        {
            assert (a1->source_addr.sin6_family == PF_INET);
            assert (a2->source_addr.sin6_family == PF_INET);

            /* Outside of subnets, as defined by the network masks,
             * common address prefixes for IPv4 addresses make no sense.
             * So, define a non-zero value only if source and
             * destination address are on the same subnet.  */
            struct sockaddr_in *in1_dst
                = (struct sockaddr_in *) a1->dest_addr->ai_addr;
            in_addr_t in1_dst_addr = ntohl (in1_dst->sin_addr.s_addr);
            struct sockaddr_in *in1_src
                = (struct sockaddr_in *) &a1->source_addr;
            in_addr_t in1_src_addr = ntohl (in1_src->sin_addr.s_addr);
            in_addr_t netmask1 = 0xffffffffu << (32 - a1->prefixlen);

            if ((in1_src_addr & netmask1) == (in1_dst_addr & netmask1))
                bit1 = fls (in1_dst_addr ^ in1_src_addr);

            struct sockaddr_in *in2_dst
                = (struct sockaddr_in *) a2->dest_addr->ai_addr;
            in_addr_t in2_dst_addr = ntohl (in2_dst->sin_addr.s_addr);
            struct sockaddr_in *in2_src
                = (struct sockaddr_in *) &a2->source_addr;
            in_addr_t in2_src_addr = ntohl (in2_src->sin_addr.s_addr);
            in_addr_t netmask2 = 0xffffffffu << (32 - a2->prefixlen);

            if ((in2_src_addr & netmask2) == (in2_dst_addr & netmask2))
                bit2 = fls (in2_dst_addr ^ in2_src_addr);
        }
        else if (a1->dest_addr->ai_family == PF_INET6)
        {
            assert (a1->source_addr.sin6_family == PF_INET6);
            assert (a2->source_addr.sin6_family == PF_INET6);

            struct sockaddr_in6 *in1_dst;
            struct sockaddr_in6 *in1_src;
            struct sockaddr_in6 *in2_dst;
            struct sockaddr_in6 *in2_src;

            in1_dst = (struct sockaddr_in6 *) a1->dest_addr->ai_addr;
            in1_src = (struct sockaddr_in6 *) &a1->source_addr;
            in2_dst = (struct sockaddr_in6 *) a2->dest_addr->ai_addr;
            in2_src = (struct sockaddr_in6 *) &a2->source_addr;

            int i;
            for (i = 0; i < 4; ++i)
                if (in1_dst->sin6_addr.s6_addr32[i]
                        != in1_src->sin6_addr.s6_addr32[i]
                        || (in2_dst->sin6_addr.s6_addr32[i]
                            != in2_src->sin6_addr.s6_addr32[i]))
                    break;

            if (i < 4)
            {
                bit1 = fls (ntohl (in1_dst->sin6_addr.s6_addr32[i]
                            ^ in1_src->sin6_addr.s6_addr32[i]));
                bit2 = fls (ntohl (in2_dst->sin6_addr.s6_addr32[i]
                            ^ in2_src->sin6_addr.s6_addr32[i]));
            }
        }

        if (bit1 > bit2)
            return -1;
        if (bit1 < bit2)
            return 1;
    }


    /* Rule 10: Otherwise, leave the order unchanged.  To ensure this
     * compare with the value indicating the order in which the entries
     * have been received from the services.  NB: no two entries can have
     * the same order so the test will never return zero.  */
    return idx1 < idx2 ? -1 : 1;
}


/* Name of the config file for RFC 3484 sorting (for now).  */
#define GAICONF_FNAME "/etc/gai.conf"

/* Non-zero if we are supposed to reload the config file automatically
 *    whenever it changed.  */
static int gaiconf_reload_flag;

/* Non-zero if gaiconf_reload_flag was ever set to true.  */
static int gaiconf_reload_flag_ever_set;

/* Last modification time.  */
#ifdef _STATBUF_ST_NSEC

static struct timespec gaiconf_mtime;

static inline void save_gaiconf_mtime (const struct stat64 *st)
{
    gaiconf_mtime = st->st_mtim;
}

static inline bool check_gaiconf_mtime (const struct stat64 *st)
{
    return (st->st_mtim.tv_sec == gaiconf_mtime.tv_sec
            && st->st_mtim.tv_nsec == gaiconf_mtime.tv_nsec);
}

#else

static time_t gaiconf_mtime;

static inline void save_gaiconf_mtime (const struct stat64 *st)
{
    gaiconf_mtime = st->st_mtime;
}

static inline bool check_gaiconf_mtime (const struct stat64 *st)
{
    return st->st_mtime == gaiconf_mtime;
}

#endif


libc_freeres_fn(fini)
{
    DPRINTF("");
    if (cache)
        __free_in6ai (cache->in6ai);
    if (labels != default_labels)
    {
        const struct prefixentry *old = labels;
        labels = default_labels;
        free ((void *) old);
    }

    if (precedence != default_precedence)
    {
        const struct prefixentry *old = precedence;
        precedence = default_precedence;
        free ((void *) old);
    }

    if (scopes != default_scopes)
    {
        const struct scopeentry *old = scopes;
        scopes = default_scopes;
        free ((void *) old);
    }
    DPRINTF("End");
}


struct prefixlist
{
    struct prefixentry entry;
    struct prefixlist *next;
};


struct scopelist
{
    struct scopeentry entry;
    struct scopelist *next;
};


static void free_prefixlist (struct prefixlist *list)
{
    DPRINTF("");
    while (list != NULL)
    {
        struct prefixlist *oldp = list;
        list = list->next;
        free (oldp);
    }
    DPRINTF("End");
}


static void free_scopelist (struct scopelist *list)
{
    DPRINTF("");
    while (list != NULL)
    {
        struct scopelist *oldp = list;
        list = list->next;
        free (oldp);
    }
    DPRINTF("End");
}


static int prefixcmp (const void *p1, const void *p2)
{
    const struct prefixentry *e1 = (const struct prefixentry *) p1;
    const struct prefixentry *e2 = (const struct prefixentry *) p2;

    if (e1->bits < e2->bits)
        return 1;
    if (e1->bits == e2->bits)
        return 0;
    return -1;
}


static int scopecmp (const void *p1, const void *p2)
{
    const struct scopeentry *e1 = (const struct scopeentry *) p1;
    const struct scopeentry *e2 = (const struct scopeentry *) p2;

    if (e1->netmask > e2->netmask)
        return -1;
    if (e1->netmask == e2->netmask)
        return 0;
    return 1;
}


static void gaiconf_init (void)
{
    struct prefixlist *labellist = NULL;
    size_t nlabellist = 0;
    bool labellist_nullbits = false;
    struct prefixlist *precedencelist = NULL;
    size_t nprecedencelist = 0;
    bool precedencelist_nullbits = false;
    struct scopelist *scopelist =  NULL;
    size_t nscopelist = 0;
    bool scopelist_nullbits = false;

    FILE *fp = fopen (GAICONF_FNAME, "rce");
    DPRINTF("");
    if (fp != NULL)
    {
        struct stat64 st;
        if (__fxstat64 (_STAT_VER, fileno (fp), &st) != 0)
        {
            fclose (fp);
            goto no_file;
        }

        char *line = NULL;
        size_t linelen = 0;

        __fsetlocking (fp, FSETLOCKING_BYCALLER);

        while (!feof_unlocked (fp))
        {
            ssize_t n = getline (&line, &linelen, fp);
            if (n <= 0)
                break;

            /* Handle comments.  No escaping possible so this is easy.  */
            char *cp = strchr (line, '#');
            if (cp != NULL)
                *cp = '\0';

            cp = line;
            while (isspace (*cp))
                ++cp;

            char *cmd = cp;
            while (*cp != '\0' && !isspace (*cp))
                ++cp;
            size_t cmdlen = cp - cmd;

            if (*cp != '\0')
                *cp++ = '\0';
            while (isspace (*cp))
                ++cp;

            char *val1 = cp;
            while (*cp != '\0' && !isspace (*cp))
                ++cp;
            size_t val1len = cp - cmd;

            /* We always need at least two values.  */
            if (val1len == 0)
                continue;

            if (*cp != '\0')
                *cp++ = '\0';
            while (isspace (*cp))
                ++cp;

            char *val2 = cp;
            while (*cp != '\0' && !isspace (*cp))
                ++cp;

            /*  Ignore the rest of the line.  */
            *cp = '\0';

            struct prefixlist **listp;
            size_t *lenp;
            bool *nullbitsp;
            switch (cmdlen)
            {
                case 5:
                    if (strcmp (cmd, "label") == 0)
                    {
                        struct in6_addr prefix;
                        unsigned long int bits;
                        unsigned long int val;
                        char *endp;

                        listp = &labellist;
                        lenp = &nlabellist;
                        nullbitsp = &labellist_nullbits;

new_elem:
                        bits = 128;
                        __set_errno (0);
                        cp = strchr (val1, '/');
                        if (cp != NULL)
                            *cp++ = '\0';
                        if (inet_pton (AF_INET6, val1, &prefix)
                                && (cp == NULL
                                    || (bits = strtoul (cp, &endp, 10)) != ULONG_MAX
                                    || errno != ERANGE)
                                && *endp == '\0'
                                && bits <= 128
                                && ((val = strtoul (val2, &endp, 10)) != ULONG_MAX
                                    || errno != ERANGE)
                                && *endp == '\0'
                                && val <= INT_MAX)
                        {
                            struct prefixlist *newp = malloc (sizeof (*newp));
                            if (newp == NULL)
                            {
                                free (line);
                                fclose (fp);
                                goto no_file;
                            }

                            memcpy (&newp->entry.prefix, &prefix, sizeof (prefix));
                            newp->entry.bits = bits;
                            newp->entry.val = val;
                            newp->next = *listp;
                            *listp = newp;
                            ++*lenp;
                            *nullbitsp |= bits == 0;
                        }
                    }
                    break;

                case 6:
                    if (strcmp (cmd, "reload") == 0)
                    {
                        gaiconf_reload_flag = strcmp (val1, "yes") == 0;
                        if (gaiconf_reload_flag)
                            gaiconf_reload_flag_ever_set = 1;
                    }
                    break;

                case 7:
                    if (strcmp (cmd, "scopev4") == 0)
                    {
                        struct in6_addr prefix;
                        unsigned long int bits;
                        unsigned long int val;
                        char *endp;

                        bits = 32;
                        __set_errno (0);
                        cp = strchr (val1, '/');
                        if (cp != NULL)
                            *cp++ = '\0';
                        if (inet_pton (AF_INET6, val1, &prefix))
                        {
                            bits = 128;
                            if (IN6_IS_ADDR_V4MAPPED (&prefix)
                                    && (cp == NULL
                                        || (bits = strtoul (cp, &endp, 10)) != ULONG_MAX
                                        || errno != ERANGE)
                                    && *endp == '\0'
                                    && bits >= 96
                                    && bits <= 128
                                    && ((val = strtoul (val2, &endp, 10)) != ULONG_MAX
                                        || errno != ERANGE)
                                    && *endp == '\0'
                                    && val <= INT_MAX)
                            {
                                struct scopelist *newp;
new_scope:
                                newp = malloc (sizeof (*newp));
                                if (newp == NULL)
                                {
                                    free (line);
                                    fclose (fp);
                                    goto no_file;
                                }

                                newp->entry.netmask = htonl (bits != 96
                                        ? (0xffffffff
                                            << (128 - bits))
                                        : 0);
                                newp->entry.addr32 = (prefix.s6_addr32[3]
                                        & newp->entry.netmask);
                                newp->entry.scope = val;
                                newp->next = scopelist;
                                scopelist = newp;
                                ++nscopelist;
                                scopelist_nullbits |= bits == 96;
				DPRINTF("scopelist_nullbits set");
                            }
                        }
                        else if (inet_pton (AF_INET, val1, &prefix.s6_addr32[3])
                                && (cp == NULL
                                    || (bits = strtoul (cp, &endp, 10)) != ULONG_MAX
                                    || errno != ERANGE)
                                && *endp == '\0'
                                && bits <= 32
                                && ((val = strtoul (val2, &endp, 10)) != ULONG_MAX
                                    || errno != ERANGE)
                                && *endp == '\0'
                                && val <= INT_MAX)
                        {
                            bits += 96;
                            goto new_scope;
                        }
                    }
                    break;

                case 10:
                    if (strcmp (cmd, "precedence") == 0)
                    {
                        listp = &precedencelist;
                        lenp = &nprecedencelist;
                        nullbitsp = &precedencelist_nullbits;
                        goto new_elem;
                    }
                    break;
            }
        }

        free (line);

        fclose (fp);

	DPRINTF("End of file read nlabellist %d", nlabellist);
        /* Create the array for the labels.  */
        struct prefixentry *new_labels;
        if (nlabellist > 0)
        {
            if (!labellist_nullbits)
                ++nlabellist;
            new_labels = malloc (nlabellist * sizeof (*new_labels));
            if (new_labels == NULL)
                goto no_file;

            int i = nlabellist;
            if (!labellist_nullbits)
            {
                --i;
                memset (&new_labels[i].prefix, '\0', sizeof (struct in6_addr));
                new_labels[i].bits = 0;
                new_labels[i].val = 1;
            }

            struct prefixlist *l = labellist;
            while (i-- > 0)
            {
                new_labels[i] = l->entry;
                l = l->next;
            }
            free_prefixlist (labellist);

            /* Sort the entries so that the most specific ones are at
             *         the beginning.  */
            qsort (new_labels, nlabellist, sizeof (*new_labels), prefixcmp);
        }
        else
            new_labels = (struct prefixentry *) default_labels;

	DPRINTF("prefix done, nprecedencelist %d", nprecedencelist);
        struct prefixentry *new_precedence;
        if (nprecedencelist > 0)
        {
            if (!precedencelist_nullbits)
                ++nprecedencelist;
            new_precedence = malloc (nprecedencelist * sizeof (*new_precedence));
            if (new_precedence == NULL)
            {
                if (new_labels != default_labels)
                    free (new_labels);
                goto no_file;
            }

            int i = nprecedencelist;
            if (!precedencelist_nullbits)
            {
                --i;
                memset (&new_precedence[i].prefix, '\0',
                        sizeof (struct in6_addr));
                new_precedence[i].bits = 0;
                new_precedence[i].val = 40;
            }

            struct prefixlist *l = precedencelist;
            while (i-- > 0)
            {
                new_precedence[i] = l->entry;
                l = l->next;
            }
            free_prefixlist (precedencelist);

            /* Sort the entries so that the most specific ones are at
             * beginning.  */

            qsort (new_precedence, nprecedencelist, sizeof (*new_precedence),
                    prefixcmp);
        }
        else
            new_precedence = (struct prefixentry *) default_precedence;

	DPRINTF("precedence done, nscopelist %d", nscopelist);
        struct scopeentry *new_scopes;
        if (nscopelist > 0)
        {
            if (!scopelist_nullbits)
                ++nscopelist;
            new_scopes = malloc (nscopelist * sizeof (*new_scopes));
            if (new_scopes == NULL)
            {
                if (new_labels != default_labels)
                    free (new_labels);
                if (new_precedence != default_precedence)
                    free (new_precedence);
                goto no_file;
            }

            int i = nscopelist;
            if (!scopelist_nullbits)
            {
                --i;
                new_scopes[i].addr32 = 0;
                new_scopes[i].netmask = 0;
                new_scopes[i].scope = 14;
		DPRINTF("new scope list initialised");
            }

            struct scopelist *l = scopelist;
            while (i-- > 0)
            {
                new_scopes[i] = l->entry;
                l = l->next;
            }
            free_scopelist (scopelist);

            /* Sort the entries so that the most specific ones are at
             * the beginning.  */
            qsort (new_scopes, nscopelist, sizeof (*new_scopes),
                    scopecmp);
        }
        else
            new_scopes = (struct scopeentry *) default_scopes;

        /* Now we are ready to replace the values.  */
        const struct prefixentry *old = labels;
        labels = new_labels;
        if (old != default_labels)
            free ((void *) old);

        old = precedence;
        precedence = new_precedence;
        if (old != default_precedence)
            free ((void *) old);

	DPRINTF("copying scope");
        const struct scopeentry *oldscope = scopes;
        scopes = new_scopes;
        if (oldscope != default_scopes)
            free ((void *) oldscope);

        save_gaiconf_mtime (&st);
	DPRINTF("End");
    }
    else
    {
no_file:
        free_prefixlist (labellist);
        free_prefixlist (precedencelist);
        free_scopelist (scopelist);

        /* If we previously read the file but it is gone now, free the
         * old data and use the builtin one.  Leave the reload flag
         * alone.  */
        /* fini (); */
	DPRINTF("End no file nlabellist %d, nprecedencelist %d, nscopelist %d", nlabellist, nprecedencelist, nscopelist);
    }
}

static void gaiconf_reload (void)
{
    DPRINTF("");
    struct stat64 st;
    /* if (__xstat64 (_STAT_VER, GAICONF_FNAME, &st) != 0   || !check_gaiconf_mtime (&st)) */
    gaiconf_init ();
}


static const struct addrinfo default_hints =                  
{
    .ai_flags = AI_DEFAULT,                                   
    .ai_family = PF_UNSPEC,                                   
    .ai_socktype = 0,
    .ai_protocol = 0,                                         
    .ai_addrlen = 0,
    .ai_addr = NULL,                                          
    .ai_canonname = NULL,                                     
    .ai_next = NULL 
};

/* In This file rfc3484 is impemented. */
/* Code compiled from uclibc and glibc getaddrinfo */
int getaddrinfo (const char *name, const char *service,
        const struct addrinfo *hints, struct addrinfo **pai)
{
    int i = 0, last_i = 0;
    int nresults = 0;
    struct addrinfo *p = NULL;
    struct gaih_service gaih_service, *pservice;
    struct addrinfo local_hints;
    printf("\n%s name:%s\n", __func__, name);

    if (service != NULL && service[0] == '*' && service[1] == 0)
        service = NULL;

    if (name == NULL && service == NULL)
        return EAI_NONAME;

    if (hints == NULL)
        hints = &default_hints;

    if (hints->ai_flags
            & ~(AI_PASSIVE|AI_CANONNAME|AI_NUMERICHOST|AI_ADDRCONFIG|AI_V4MAPPED
                |AI_IDN|AI_CANONIDN
                |AI_NUMERICSERV|AI_ALL))
        return EAI_BADFLAGS;

    if ((hints->ai_flags & AI_CANONNAME) && name == NULL)
        return EAI_BADFLAGS;

    struct in6addrinfo *in6ai = NULL;
    size_t in6ailen = 0;
    bool seen_ipv4 = false;
    bool seen_ipv6 = false;
    bool check_pf_called = false;

    if (hints->ai_flags & AI_ADDRCONFIG)
    {
        /* We might need information about what interfaces are available.
         * Also determine whether we have IPv4 or IPv6 interfaces or both.  We
         * cannot cache the results since new interfaces could be added at
         * any time.  */
        check_pf (&seen_ipv4, &seen_ipv6, &in6ai, &in6ailen);
        check_pf_called = true;
        /* Now make a decision on what we return, if anything.  */
        if (hints->ai_family == PF_UNSPEC && (seen_ipv4 || seen_ipv6))
        {
            /* If we haven't seen both IPv4 and IPv6 interfaces we can
             * narrow down the search.  */
            if ((! seen_ipv4 || ! seen_ipv6) && (seen_ipv4 || seen_ipv6))
            {
                local_hints = *hints;
                local_hints.ai_family = seen_ipv4 ? PF_INET : PF_INET6;
                hints = &local_hints;
            }
        }
        else if ((hints->ai_family == PF_INET && ! seen_ipv4)
                || (hints->ai_family == PF_INET6 && ! seen_ipv6))
        {
            /* We cannot possibly return a valid answer.  */
            __free_in6ai (in6ai);
            return EAI_NONAME;
        }
    }

    if (service && service[0])
    {
        char *c;
        gaih_service.name = service;
        gaih_service.num = strtoul (gaih_service.name, &c, 10);
        if (*c != '\0')
        {
            if (hints->ai_flags & AI_NUMERICSERV)
            {
                __free_in6ai (in6ai);
                return EAI_NONAME;
            }

            gaih_service.num = -1;
        }

        pservice = &gaih_service;
    }
    else
        pservice = NULL;

    struct addrinfo **end = &p;

    unsigned int naddrs = 0;

    if (hints->ai_family == AF_UNSPEC || hints->ai_family == AF_INET
            || hints->ai_family == AF_INET6)
    {
        last_i = gaih_inet (name, pservice, hints, seen_ipv4, seen_ipv6, end, &naddrs);
        if (last_i != 0)
        {

            if (!(hints->ai_family == AF_UNSPEC && (i & GAIH_OKIFUNSPEC)))
            {
                freeaddrinfo (p);
                __free_in6ai (in6ai);

                return -last_i;
            }
        }
        while (*end)
        {
            end = &((*end)->ai_next);
            ++nresults;
        }
    }
    else
    {
        __free_in6ai (in6ai);
        return EAI_FAMILY;
    }

    if (naddrs > 1)
    {
    	DPRINTF("naddrs %d", naddrs);
        /* Read the config file.  */
        __libc_once_define (static, once);
        __typeof (once) old_once = once;
        __libc_once (once, gaiconf_init);
        /* Sort results according to RFC 3484.  */
        struct sort_result *results;
        size_t *order;
        struct addrinfo *q;
        struct addrinfo *last = NULL;
        char *canonname = NULL;
        bool malloc_results;
        size_t alloc_size = nresults * (sizeof (*results) + sizeof (size_t));

        malloc_results
            = !alloca (alloc_size);
        if (malloc_results)
        {
            results = malloc (alloc_size);
            if (results == NULL)
            {
                __free_in6ai (in6ai);
                return EAI_MEMORY;
            }
        }
        else
            results = alloca (alloc_size);
        order = (size_t *) (results + nresults);

        /* Now we definitely need the interface information.  */
        if (! check_pf_called)
        {
            check_pf (&seen_ipv4, &seen_ipv6, &in6ai, &in6ailen);
        }

        /* If we have information about deprecated and temporary addresses
         * sort the array now.  */
        if (in6ai != NULL)
        {
            qsort (in6ai, in6ailen, sizeof (*in6ai), in6aicmp);
        }
        int fd = -1;
        int af = AF_UNSPEC;

        for (i = 0, q = p; q != NULL; ++i, last = q, q = q->ai_next)
        {
            results[i].dest_addr = q;
            results[i].native = -1;
            order[i] = i;

            /* If we just looked up the address for a different
             *              protocol, reuse the result.  */
            if (last != NULL && last->ai_addrlen == q->ai_addrlen
                    && memcmp (last->ai_addr, q->ai_addr, q->ai_addrlen) == 0)
            {
                memcpy (&results[i].source_addr, &results[i - 1].source_addr,
                        results[i - 1].source_addr_len);
                results[i].source_addr_len = results[i - 1].source_addr_len;
                results[i].got_source_addr = results[i - 1].got_source_addr;
                results[i].source_addr_flags = results[i - 1].source_addr_flags;
                results[i].prefixlen = results[i - 1].prefixlen;
                results[i].index = results[i - 1].index;
            }
            else
            {
                results[i].got_source_addr = false;
                results[i].source_addr_flags = 0;
                results[i].prefixlen = 0;
                results[i].index = 0xffffffffu;

    		DPRINTF("Reachability init");
                /* We overwrite the type with SOCK_DGRAM since we do not
                 * want connect() to connect to the other side.  If we
                 * cannot determine the source address remember this
                 * fact.  */
                if (fd == -1 || (af == AF_INET && q->ai_family == AF_INET6))
                {
                    if (fd != -1)
                        close_retry:
                            close (fd);
                    af = q->ai_family;
                    fd = socket (af, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_IP);
                }
                else
                {
                    /* Reset the connection.  */
                    struct sockaddr sa = { .sa_family = AF_UNSPEC };
                    connect (fd, &sa, sizeof (sa));
                }

                socklen_t sl = sizeof (results[i].source_addr);

                /* If link local IP then add interface scope to connect socket */
                int link_local_scope_original=0;
                struct sockaddr_in6* sa = (struct sockaddr_in6*)q->ai_addr;
    if (sa->sin6_family == AF_INET6 && IN6_IS_ADDR_LINKLOCAL (&sa->sin6_addr)&& !IN6_IS_ADDR_LOOPBACK(&sa->sin6_addr))
                {
			printf("get br0 scope");
                    link_local_scope_original = sa->sin6_scope_id;
                    sa->sin6_scope_id = get_br0_scopeid();
                }


                if (fd != -1 
                        && connect (fd, q->ai_addr, q->ai_addrlen) == 0 
                        && getsockname (fd,(struct sockaddr *) &results[i].source_addr, &sl) == 0)
                {
			printf("connected");
                    /* if link local scope was changed then change back since connect is done */
                    if(link_local_scope_original != sa->sin6_scope_id)
                    {
                        sa->sin6_scope_id = link_local_scope_original;
                    }
                    results[i].source_addr_len = sl;
                    results[i].got_source_addr = true;

                    if (in6ai != NULL)
                    {
                        /* See whether the source address is on the list of
                         * deprecated or temporary addresses.  */
                        struct in6addrinfo tmp;
                        if (q->ai_family == AF_INET && af == AF_INET)
                        {
                            struct sockaddr_in *sinp
                                = (struct sockaddr_in *) &results[i].source_addr;
                            tmp.addr[0] = 0;
                            tmp.addr[1] = 0;
                            tmp.addr[2] = htonl (0xffff);
                            /* Special case for lo interface, the source address
                             * being possibly different than the interface
                             * address. */
                            if ((ntohl(sinp->sin_addr.s_addr) & 0xff000000)
                                    == 0x7f000000)
                                tmp.addr[3] = htonl(0x7f000001);
                            else
                                tmp.addr[3] = sinp->sin_addr.s_addr;
#ifdef DEBUG
		    	     DPRINTF("source from getsockname %s", print_sockaddr(&results[i].source_addr));
#endif
                        }
                        else
                        {
                            struct sockaddr_in6 *sin6p
                                = (struct sockaddr_in6 *) &results[i].source_addr;

#ifdef DEBUG
		    	     DPRINTF("source from getsockname %s", print_sockaddr_in6(&results[i].source_addr));
#endif
                            memcpy (tmp.addr, &sin6p->sin6_addr, IN6ADDRSZ);
                        }

                        struct in6addrinfo *found
                            = bsearch (&tmp, in6ai, in6ailen, sizeof (*in6ai),
                                    in6aicmp);
                        if (found != NULL)
                        {
                            results[i].source_addr_flags = found->flags;
                            results[i].prefixlen = found->prefixlen;
                            results[i].index = found->index;
                        }
                    }

                    if (q->ai_family == AF_INET && af == AF_INET6)
                    {
                        /* We have to convert the address.  The socket is
                         * IPv6 and the request is for IPv4.  */
                        struct sockaddr_in6 *sin6
                            = (struct sockaddr_in6 *) &results[i].source_addr;
#ifdef DEBUG
			print_sockaddr_in6(sin6);
#endif
                        struct sockaddr_in *sin
                            = (struct sockaddr_in *) &results[i].source_addr;
#ifdef DEBUG
			print_sockaddr(sin);
#endif
			
                        assert (IN6_IS_ADDR_V4MAPPED (sin6->sin6_addr.s6_addr32));
                        sin->sin_family = AF_INET;
                        /* We do not have to initialize sin_port since this
                         * fields has the same position and size in the IPv6
                         * structure.  */

                        assert (offsetof (struct sockaddr_in, sin_port)
                                == offsetof (struct sockaddr_in6, sin6_port));
                        assert (sizeof (sin->sin_port)
                                == sizeof (sin6->sin6_port));
                        memcpy (&sin->sin_addr,
                                &sin6->sin6_addr.s6_addr32[3], INADDRSZ);
                        results[i].source_addr_len = sizeof (struct sockaddr_in);
                    }
                }
                else if (errno == EAFNOSUPPORT && af == AF_INET6       && q->ai_family == AF_INET)
                {   /* This could mean IPv6 sockets are IPv6-only.  */
                    goto close_retry;
                }else 
                {   
                    /* Just make sure that if we have to process the same
                     * address again we do not copy any memory.  */
                    results[i].source_addr_len = 0;
                }
            }

            /* Remember the canonical name.  */
            if (q->ai_canonname != NULL)
            {
                assert (canonname == NULL);
                canonname = q->ai_canonname;
                q->ai_canonname = NULL;
            }
        }

        if (fd != -1)
            close (fd);

        /* We got all the source addresses we can get, now sort using
         * the information.  */
        struct sort_result_combo src
            = { .results = results, .nresults = nresults };

        if ((gaiconf_reload_flag_ever_set))
        {
            __libc_lock_define_initialized (static, lock);

            __libc_lock_lock (lock);
            /* if (__libc_once_get (old_once) && gaiconf_reload_flag) */
            gaiconf_reload ();
            qsort_r (order, nresults, sizeof (order[0]), rfc3484_sort, &src);
            __libc_lock_unlock (lock);
        }
        else{
            qsort_r (order, nresults, sizeof (order[0]), rfc3484_sort, &src);
        }
        /* Queue the results up as they come out of sorting.  */
        q = p = results[order[0]].dest_addr;
        for (i = 1; i < nresults; ++i)
            q = q->ai_next = results[order[i]].dest_addr;
        q->ai_next = NULL;

        /* Fill in the canonical name into the new first entry.  */
        p->ai_canonname = canonname;

        if (malloc_results)
            free (results);
    }

    __free_in6ai (in6ai);

    DPRINTF("End");
    if (p)
    {
        *pai = p;
        return 0;
    }
    return last_i ? -last_i : EAI_NONAME;
}

libc_hidden_def(getaddrinfo)

void freeaddrinfo (struct addrinfo *ai)
{
    DPRINTF("");
    struct addrinfo *p;

    while (ai != NULL)
    {
        p = ai;
        ai = ai->ai_next;
        free (p->ai_canonname);
        free (p);
    }
    DPRINTF("End");
}
libc_hidden_def (freeaddrinfo)
