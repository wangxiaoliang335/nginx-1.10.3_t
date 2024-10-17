
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_INET_H_INCLUDED_
#define _NGX_INET_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


/*
 * TODO: autoconfigure NGX_SOCKADDRLEN and NGX_SOCKADDR_STRLEN as
 *       sizeof(struct sockaddr_storage)
 *       sizeof(struct sockaddr_un)
 *       sizeof(struct sockaddr_in6)
 *       sizeof(struct sockaddr_in)
 */

#define NGX_INET_ADDRSTRLEN   (sizeof("255.255.255.255") - 1)
#define NGX_INET6_ADDRSTRLEN                                                 \
    (sizeof("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255") - 1)
#define NGX_UNIX_ADDRSTRLEN                                                  \
    (sizeof(struct sockaddr_un) - offsetof(struct sockaddr_un, sun_path))

#if (NGX_HAVE_UNIX_DOMAIN)
#define NGX_SOCKADDR_STRLEN   (sizeof("unix:") - 1 + NGX_UNIX_ADDRSTRLEN)
#else
#define NGX_SOCKADDR_STRLEN   (NGX_INET6_ADDRSTRLEN + sizeof("[]:65535") - 1)
#endif

#if (NGX_HAVE_UNIX_DOMAIN)
#define NGX_SOCKADDRLEN       sizeof(struct sockaddr_un)
#else
#define NGX_SOCKADDRLEN       512
#endif


typedef struct {
    in_addr_t                 addr;
    in_addr_t                 mask;
} ngx_in_cidr_t;


#if (NGX_HAVE_INET6)

typedef struct {
    struct in6_addr           addr;
    struct in6_addr           mask;
} ngx_in6_cidr_t;

#endif


typedef struct {
    ngx_uint_t                family;
    union {
        ngx_in_cidr_t         in;
#if (NGX_HAVE_INET6)
        ngx_in6_cidr_t        in6;
#endif
    } u;
} ngx_cidr_t;


typedef struct {
    struct sockaddr          *sockaddr;
    socklen_t                 socklen;
    ngx_str_t                 name;
} ngx_addr_t;


typedef struct {
    ngx_str_t                 url;   //该url的字符串表示形式
    ngx_str_t                 host;
    ngx_str_t                 port_text;    //端口的字符串表示形式
    ngx_str_t                 uri;      //uri标识，一般为url中最后一个/后的内容。

    in_port_t                 port;     //网络字节序表示的端口
    in_port_t                 default_port;  //如果在配置中端口没有指定的话，会采用系统所指定的一个默认端口。
    int                       family;       //所指定的协议类型(IPv4/IPv6/Unix domain)

    //是否需要建立监听socket。针对有一些配置可能需要建立，而另外一些如events模块中的debug_connection指令，则不需要建立专门的监听socket。
    unsigned                  listen:1;     
    unsigned                  uri_part:1;   //是否具有uri部分
    unsigned                  no_resolve:1;  //需不需要进行DNS解析
    unsigned                  one_addr:1;  /* compatibility */  //本字段暂时未使用

    unsigned                  no_port:1;     //表明当前url中是否配置了端口（如果没有配置，且需要端口的话，则会采用默认端口）
    unsigned                  wildcard:1;    //是否为一个通配地址

    socklen_t                 socklen;       //所对应的socket长度

    //存放socket地址的内存空间（此地址存放的一般是选作为默认的socket地址，请参看如下字段）
    u_char                    sockaddr[NGX_SOCKADDRLEN];

    //存放所有socket的地址的数组空间（有时配置是一个通配地址，或者是一个域名地址，在完成DNS解析后可能会解析出多个地址）
    ngx_addr_t               *addrs;

    //上面addrs数组元素的个数
    ngx_uint_t                naddrs;

    //用于存放对应的错误信息字符串
    char                     *err;
} ngx_url_t;


in_addr_t ngx_inet_addr(u_char *text, size_t len);
#if (NGX_HAVE_INET6)
ngx_int_t ngx_inet6_addr(u_char *p, size_t len, u_char *addr);
size_t ngx_inet6_ntop(u_char *p, u_char *text, size_t len);
#endif
size_t ngx_sock_ntop(struct sockaddr *sa, socklen_t socklen, u_char *text,
    size_t len, ngx_uint_t port);
size_t ngx_inet_ntop(int family, void *addr, u_char *text, size_t len);
ngx_int_t ngx_ptocidr(ngx_str_t *text, ngx_cidr_t *cidr);
ngx_int_t ngx_parse_addr(ngx_pool_t *pool, ngx_addr_t *addr, u_char *text,
    size_t len);
ngx_int_t ngx_parse_url(ngx_pool_t *pool, ngx_url_t *u);
ngx_int_t ngx_inet_resolve_host(ngx_pool_t *pool, ngx_url_t *u);
ngx_int_t ngx_cmp_sockaddr(struct sockaddr *sa1, socklen_t slen1,
    struct sockaddr *sa2, socklen_t slen2, ngx_uint_t cmp_port);


#endif /* _NGX_INET_H_INCLUDED_ */
