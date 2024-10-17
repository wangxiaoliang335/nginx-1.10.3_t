
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_BUF_H_INCLUDED_
#define _NGX_BUF_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef void *            ngx_buf_tag_t;

typedef struct ngx_buf_s  ngx_buf_t;

// ngx_buf_t 就是ngx_chain_t链表每个节点的实际数据，
// 缓冲区ngx_buf_t是nginx处理大数据的关键数据结构，它既可以应用于内存也可以用于磁盘数据
struct ngx_buf_s {
    // pos指向的是这段数据在内存中的开始位置
    u_char          *pos;
    // last指向的是这段数据在内存中的结束位置
    u_char          *last;
    // file_pos指向这段数据的开始位置在文件中的偏移量
    off_t            file_pos;
    // file_last指向这段数据的结束位置在文件中的偏移量
    off_t            file_last;
    // 如果ngx_buf_t 缓冲区用于内存，那么start指向这段内存的起始地址
    u_char          *start;         /* start of buffer */
    // 如果ngx_buf_t 缓冲区用于内存，那么end指向这段内存的结束地址
    u_char          *end;           /* end of buffer */

    // 实际上就是一个void *类型的指针。使用者可以关联任何对象上去
    // 由哪个模块使用就执行哪个模块的ngx_module_t结构
    ngx_buf_tag_t    tag;
    // 当buf所包含的内容在文件中时，file字段指向对应的文件对象上去
    ngx_file_t      *file;

    // 当这个buf完整copy了另外一个buf的所有字段的时候，那么这个两个buf指向的实际上是同一块内存，或者是
    // 同一个文件的同一部分，此时这两个buf的shadow字段指向对方的。释放的时候特别注意。
    ngx_buf_t       *shadow;


    /* the buf's content could be changed */
    // 为1表示该buf所包含的内容是一个用户创建的内存块中，并且可以被在filter处理的过程中进行变更，
    // 不会造成问题
    unsigned         temporary:1;

    /*
     * the buf's content is in a memory cache or in a read only memory
     * and must not be changed
     */
    //为1表示该buf所包含的内容是在内存中，但是这些内容却不能被进行处理的filter进行变更
    unsigned         memory:1;

    /* the buf's content is mmap()ed and must not be changed */
    // 为1表示该buf所包含的内容是在内存中，是通过mmap使用内存映射从文件中映射到内存中的，
    // 这些内容不能进行变更
    unsigned         mmap:1;
    // 可以回收，也就是这个buf是可以释放的
    unsigned         recycled:1;
    // 为1时表示该buf所包含的内容是在文件中
    unsigned         in_file:1;

    // 遇到有flush字段被设置为1的buf的chain，则该chain的数据即便不是最后结束的数据，也会输出 ？？
    unsigned         flush:1;

    /* 对于操作这块缓冲区是否使用同步方式,需要谨慎考虑，这可能会阻塞nginx进程，nginx中所有的操作
     * 几乎都是异步的，这是它支持高并发的关键。
     */
    unsigned         sync:1;

    // 数据被多个chain传递给过滤器，此字段为1表明这是最后一个buf
    unsigned         last_buf:1;

    // 在当前的chain里面，此buf是最后一个
    unsigned         last_in_chain:1;
    // 在创建一个buf的shadow的时候，通常将新创建的一个buf的last_shadow置为1
    unsigned         last_shadow:1;
    // 由于内存使用的限制，有时候一些buf的内容需要被写到磁盘上的临时文件中去，这个时候就设置次标志
    unsigned         temp_file:1;

    /* STUB */ int   num;
};

// 这个就是链表的形式，还是把ngx_buf_t串起来，
// 主要作用就是接受nginx服务器的http请求包头、包体、以及响应客户端的应答包头、包体
// 都会放在chain链表缓冲区
struct ngx_chain_s {
    ngx_buf_t    *buf;  //指向当前ngx_buf_t缓冲区
    ngx_chain_t  *next; //指向下一个ngx_chain_t结构
};

// ngx_bufs_t起到了一个管理作用，用于说明当前使用的bufs的数量和每个buf的存储空间
// 在ngx_create_chain_of_bufs可以看到怎么使用
typedef struct {
    ngx_int_t    num;  //缓冲区个数
    size_t       size;  //缓冲区大小
} ngx_bufs_t;


typedef struct ngx_output_chain_ctx_s  ngx_output_chain_ctx_t;

typedef ngx_int_t (*ngx_output_chain_filter_pt)(void *ctx, ngx_chain_t *in);

#if (NGX_HAVE_FILE_AIO)
typedef void (*ngx_output_chain_aio_pt)(ngx_output_chain_ctx_t *ctx,
    ngx_file_t *file);
#endif

struct ngx_output_chain_ctx_s {
    ngx_buf_t                   *buf;
    ngx_chain_t                 *in;
    ngx_chain_t                 *free;
    ngx_chain_t                 *busy;

    unsigned                     sendfile:1;
    unsigned                     directio:1;
#if (NGX_HAVE_ALIGNED_DIRECTIO)
    unsigned                     unaligned:1;
#endif
    unsigned                     need_in_memory:1;
    unsigned                     need_in_temp:1;
#if (NGX_HAVE_FILE_AIO || NGX_THREADS)
    unsigned                     aio:1;
#endif

#if (NGX_HAVE_FILE_AIO)
    ngx_output_chain_aio_pt      aio_handler;
#if (NGX_HAVE_AIO_SENDFILE)
    ssize_t                    (*aio_preload)(ngx_buf_t *file);
#endif
#endif

#if (NGX_THREADS)
    ngx_int_t                  (*thread_handler)(ngx_thread_task_t *task,
                                                 ngx_file_t *file);
    ngx_thread_task_t           *thread_task;
#endif

    off_t                        alignment;

    ngx_pool_t                  *pool;
    ngx_int_t                    allocated;
    ngx_bufs_t                   bufs;
    ngx_buf_tag_t                tag;

    ngx_output_chain_filter_pt   output_filter;
    void                        *filter_ctx;
};


typedef struct {
    ngx_chain_t                 *out;
    ngx_chain_t                **last;
    ngx_connection_t            *connection;
    ngx_pool_t                  *pool;
    off_t                        limit;
} ngx_chain_writer_ctx_t;


#define NGX_CHAIN_ERROR     (ngx_chain_t *) NGX_ERROR

// 返回这个buf里面的内容是否在内存里
#define ngx_buf_in_memory(b)        (b->temporary || b->memory || b->mmap)
// 返回这个buf里面的内容是否仅仅在内存里，并且没有在文件里
#define ngx_buf_in_memory_only(b)   (ngx_buf_in_memory(b) && !b->in_file)
// 返回这个buf是否是一个特殊的buf，只含有特殊的标志和没有包含真正的数据
#define ngx_buf_special(b)                                                   \
    ((b->flush || b->last_buf || b->sync)                                    \
     && !ngx_buf_in_memory(b) && !b->in_file)

// 返回这个buf是否是一个之包含sync标志而不包含真正数据的特殊buf
#define ngx_buf_sync_only(b)                                                 \
    (b->sync                                                                 \
     && !ngx_buf_in_memory(b) && !b->in_file && !b->flush && !b->last_buf)

// 返回该buf所包含数据的大小，不管这个数据是在文件里还是内存里
#define ngx_buf_size(b)                                                      \
    (ngx_buf_in_memory(b) ? (off_t) (b->last - b->pos):                      \
                            (b->file_last - b->file_pos))

// 对于创建temporary字段为1的buf（内容可以被后续的filter模块进行修改），直接用ngx_create_temp_buf个函数创建
// 其中pool分配该buf和buf使用的内存，size是该buf使用的内存大小
ngx_buf_t *ngx_create_temp_buf(ngx_pool_t *pool, size_t size);
ngx_chain_t *ngx_create_chain_of_bufs(ngx_pool_t *pool, ngx_bufs_t *bufs);


#define ngx_alloc_buf(pool)  ngx_palloc(pool, sizeof(ngx_buf_t))
#define ngx_calloc_buf(pool) ngx_pcalloc(pool, sizeof(ngx_buf_t))

// 该函数创建一个ngx_chain_t对象，并返回指向对象的指针，失败返回NULL
ngx_chain_t *ngx_alloc_chain_link(ngx_pool_t *pool);

// 该函数释放一个ngx_chain_t的对象，如果要释放整个chain，则迭代此链表
// 对ngx_chain_t的释放，并不是真正的释放，而是把这个对象挂在pool对象一个叫chain的
// 字段对应的chain上，以供下次可以快速取到
#define ngx_free_chain(pool, cl)                                             \
    cl->next = pool->chain;                                                  \
    pool->chain = cl



ngx_int_t ngx_output_chain(ngx_output_chain_ctx_t *ctx, ngx_chain_t *in);
ngx_int_t ngx_chain_writer(void *ctx, ngx_chain_t *in);

ngx_int_t ngx_chain_add_copy(ngx_pool_t *pool, ngx_chain_t **chain,
    ngx_chain_t *in);
ngx_chain_t *ngx_chain_get_free_buf(ngx_pool_t *p, ngx_chain_t **free);
void ngx_chain_update_chains(ngx_pool_t *p, ngx_chain_t **free,
    ngx_chain_t **busy, ngx_chain_t **out, ngx_buf_tag_t tag);

off_t ngx_chain_coalesce_file(ngx_chain_t **in, off_t limit);

ngx_chain_t *ngx_chain_update_sent(ngx_chain_t *in, off_t sent);

#endif /* _NGX_BUF_H_INCLUDED_ */
