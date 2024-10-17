
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>

// 用ngx_create_temp_buf函数在内存池上创建一个临时缓冲区
ngx_buf_t *
ngx_create_temp_buf(ngx_pool_t *pool, size_t size)
{
    ngx_buf_t *b;

    b = ngx_calloc_buf(pool);  // 从内存池pool中创建一个ngx_buf_t的大小的内存，在ngx_buf.h中宏定义了
    if (b == NULL) {
        return NULL;
    }

    b->start = ngx_palloc(pool, size);  // 开辟缓冲区空间
    if (b->start == NULL) {
        return NULL;
    }

    /*
     * set by ngx_calloc_buf():
     *
     *     b->file_pos = 0;
     *     b->file_last = 0;
     *     b->file = NULL;
     *     b->shadow = NULL;
     *     b->tag = 0;
     *     and flags
     */
    // 起始位置pos和start
    b->pos = b->start;
    b->last = b->start;
    b->end = b->last + size;  // end为缓冲区末尾
    b->temporary = 1;         // 临时缓冲区，内存可以被修改

    return b;
}

// 创建缓冲区链表，如果有直接拿，么有从pool请求一段空间
ngx_chain_t *
ngx_alloc_chain_link(ngx_pool_t *pool)
{
    ngx_chain_t  *cl;

    cl = pool->chain;

    if (cl) {
        //因为c1将会被使用，所以指向c1的下一个
        pool->chain = cl->next;
        return cl;
    }

    cl = ngx_palloc(pool, sizeof(ngx_chain_t));
    if (cl == NULL) {
        return NULL;
    }

    return cl;
}


// ngx_create_temp_buf只是创建了单个缓冲区空间。如果要创建一片连续的缓冲区，
// 就由链表统一管理，则需要使用ngx_create_chain_of_bus函数
// 从内存池pool中创建一个bufs->num长度的buf->size大小的链表，返回ngx_chain_t链表头节点
ngx_chain_t *
ngx_create_chain_of_bufs(ngx_pool_t *pool, ngx_bufs_t *bufs)
{
    u_char       *p;
    ngx_int_t     i;
    ngx_buf_t    *b;
    ngx_chain_t  *chain, *cl, **ll;

    p = ngx_palloc(pool, bufs->num * bufs->size);  // 上面描述了
    if (p == NULL) {
        return NULL;
    }
    // 这里用一个二级指针保存第一个节点指针地址，同样也保存了后面节点指针地址，这么做
    // 少了一次循环内的判断，否则我们需要判断出第一次循环，并给chain赋值
    ll = &chain;

    for (i = 0; i < bufs->num; i++) {

        b = ngx_calloc_buf(pool);  // 在内存池中创建ngx_buf_t对象，在ngx_buf.h头文件宏定义了
        if (b == NULL) {
            return NULL;
        }

        /*
         * set by ngx_calloc_buf():
         *
         *     b->file_pos = 0;
         *     b->file_last = 0;
         *     b->file = NULL;
         *     b->shadow = NULL;
         *     b->tag = 0;
         *     and flags
         *
         */
        // 初始化每个buf缓冲区的起始位置
        b->pos = p;
        b->last = p;
        b->temporary = 1;

        b->start = p;
        // 此时p会指向下一个缓冲区
        p += bufs->size;
        b->end = p;

        // 创建一个ngx_chain_t节点
        cl = ngx_alloc_chain_link(pool);
        if (cl == NULL) {
            return NULL;
        }
        // 将ngx_chain_t与buf关联起来
        cl->buf = b;
        // ll保存的上一个节点指针的指针，赋值相当于给上一个节点next指针赋值
        *ll = cl;
        // 取本节点next指针地址，用于下次循环使用
        ll = &cl->next;
    }

    *ll = NULL;
    // 返回ngx_chain_t链表的头节点
    return chain;
}

// 将其他缓冲区拷贝到已有缓冲区末尾，也就是in链表插入到chain链表末尾
ngx_int_t
ngx_chain_add_copy(ngx_pool_t *pool, ngx_chain_t **chain, ngx_chain_t *in)
{
    ngx_chain_t  *cl, **ll;

    ll = chain;
    // 找到chain链表的结尾，然后给ll
    for (cl = *chain; cl; cl = cl->next) {
        ll = &cl->next;
    }
    // 遍历in，并且创建分配chain的基本节点，并将其buf指向in的部分
    while (in) {
        cl = ngx_alloc_chain_link(pool);
        if (cl == NULL) {
            return NGX_ERROR;
        }

        cl->buf = in->buf; // 开始复制
        *ll = cl;           // 将next指向c1
        ll = &cl->next;     // 将ll指针移向c1的next
        in = in->next;      // in向下移动
    }

    *ll = NULL;             // 最后一个节点指向NULL

    return NGX_OK;
}

// 获取一个可用的ngx_chain_t节点，上面需要有一个可用的ngx_buf_t
ngx_chain_t *
ngx_chain_get_free_buf(ngx_pool_t *p, ngx_chain_t **free)
{
    ngx_chain_t  *cl;
    // 若有空闲链表中有节点，直接返回
    if (*free) {
        cl = *free;
        *free = cl->next;   // 不太明白为什么再移动指针
        cl->next = NULL;
        return cl;
    }
    // 程序移动到这里表示free是个空指针，需要申请空间
    cl = ngx_alloc_chain_link(p);
    if (cl == NULL) {
        return NULL;
    }

    cl->buf = ngx_calloc_buf(p);    // 申请新的buf空间
    if (cl->buf == NULL) {
        return NULL;
    }

    cl->next = NULL;

    return cl;
}


// ngx_chain_update_chains函数会将busy链表中的空闲节点回收到free链表中
// 将out链表插入到busy链表尾部，同时将合并后的链表从头开始的所有没有使用的节点，插入到空闲链表
// 合并链表后，out为NULL
void
ngx_chain_update_chains(ngx_pool_t *p, ngx_chain_t **free, ngx_chain_t **busy,
    ngx_chain_t **out, ngx_buf_tag_t tag)
{
    ngx_chain_t  *cl;

    if (*busy == NULL) {
        *busy = *out;

    } else {
        for (cl = *busy; cl->next; cl = cl->next) { /* void */ }

        cl->next = *out;
    }

    *out = NULL;

    while (*busy) {
        cl = *busy;
        // 这个节点内存占有，不满足条件，直接退出
        if (ngx_buf_size(cl->buf) != 0) {
            break;
        }
        //  缓冲区类型不为void *，直接释放，在循环开始
        if (cl->buf->tag != tag) {
            *busy = cl->next;
            ngx_free_chain(p, cl);
            continue;
        }
        // 重置缓冲区所有空间都可用
        cl->buf->pos = cl->buf->start;
        cl->buf->last = cl->buf->start;
        // 将该空闲区加入到free链表表头
        *busy = cl->next;
        cl->next = *free;
        *free = cl;
    }
}


off_t
ngx_chain_coalesce_file(ngx_chain_t **in, off_t limit)
{
    off_t         total, size, aligned, fprev;
    ngx_fd_t      fd;
    ngx_chain_t  *cl;

    total = 0;

    cl = *in;
    fd = cl->buf->file->fd;

    do {
        size = cl->buf->file_last - cl->buf->file_pos;

        if (size > limit - total) {
            size = limit - total;

            aligned = (cl->buf->file_pos + size + ngx_pagesize - 1)
                       & ~((off_t) ngx_pagesize - 1);

            if (aligned <= cl->buf->file_last) {
                size = aligned - cl->buf->file_pos;
            }

            total += size;
            break;
        }

        total += size;
        fprev = cl->buf->file_pos + size;
        cl = cl->next;

    } while (cl
             && cl->buf->in_file
             && total < limit
             && fd == cl->buf->file->fd
             && fprev == cl->buf->file_pos);

    *in = cl;

    return total;
}


ngx_chain_t *
ngx_chain_update_sent(ngx_chain_t *in, off_t sent)
{
    off_t  size;

    for ( /* void */ ; in; in = in->next) {

        if (ngx_buf_special(in->buf)) {
            continue;
        }

        if (sent == 0) {
            break;
        }

        size = ngx_buf_size(in->buf);

        if (sent >= size) {
            sent -= size;

            if (ngx_buf_in_memory(in->buf)) {
                in->buf->pos = in->buf->last;
            }

            if (in->buf->in_file) {
                in->buf->file_pos = in->buf->file_last;
            }

            continue;
        }

        if (ngx_buf_in_memory(in->buf)) {
            in->buf->pos += (size_t) sent;
        }

        if (in->buf->in_file) {
            in->buf->file_pos += sent;
        }

        break;
    }

    return in;
}
