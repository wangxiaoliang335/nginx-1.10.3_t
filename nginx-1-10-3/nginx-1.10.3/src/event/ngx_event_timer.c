
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


ngx_rbtree_t              ngx_event_timer_rbtree;
static ngx_rbtree_node_t  ngx_event_timer_sentinel;

/*
 * the event timer rbtree may contain the duplicate keys, however,
 * it should not be a problem, because we use the rbtree to find
 * a minimum timer value only
 */

ngx_int_t
ngx_event_timer_init(ngx_log_t *log)
{
    ngx_rbtree_init(&ngx_event_timer_rbtree, &ngx_event_timer_sentinel,
                    ngx_rbtree_insert_timer_value);

    return NGX_OK;
}


ngx_msec_t
ngx_event_find_timer(void)
{
    ngx_msec_int_t      timer;
    ngx_rbtree_node_t  *node, *root, *sentinel;

    if (ngx_event_timer_rbtree.root == &ngx_event_timer_sentinel) {
        return NGX_TIMER_INFINITE;
    }

    root = ngx_event_timer_rbtree.root;
    sentinel = ngx_event_timer_rbtree.sentinel;

    node = ngx_rbtree_min(root, sentinel);

    timer = (ngx_msec_int_t) (node->key - ngx_current_msec);

    return (ngx_msec_t) (timer > 0 ? timer : 0);
}

//定时器事件处理函数
//主要是从红黑树中找出超时的事件进行处理，循环从树中找出最左边的节点和当前时间的差，比当前小说明已经超时开始处理
void
ngx_event_expire_timers(void)
{
    ngx_event_t        *ev;
    ngx_rbtree_node_t  *node, *root, *sentinel;

    sentinel = ngx_event_timer_rbtree.sentinel;
    /* 循环检查 */
    for ( ;; ) {
        root = ngx_event_timer_rbtree.root;
        /* 若定时器红黑树为空，则直接返回，不做任何处理 */
        if (root == sentinel) {
            return;
        }
        /* 找出定时器红黑树最左边的节点，即最小的节点，同时也是最有可能超时的事件对象 */
        node = ngx_rbtree_min(root, sentinel);

        /* node->key > ngx_current_time */

        if ((ngx_msec_int_t) (node->key - ngx_current_msec) > 0) {
            return;
        }
        /* 若检查到的当前事件已超时 */
        /* 获取超时的具体事件 */
        ev = (ngx_event_t *) ((char *) node - offsetof(ngx_event_t, timer));

        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                       "event timer del: %d: %M",
                       ngx_event_ident(ev->data), ev->timer.key);
        /* 将已超时事件对象从现有定时器红黑树中移除 */
        ngx_rbtree_delete(&ngx_event_timer_rbtree, &ev->timer);

#if (NGX_DEBUG)
        ev->timer.left = NULL;
        ev->timer.right = NULL;
        ev->timer.parent = NULL;
#endif
        /* 设置事件的在定时器红黑树中的监控标志位 */
        ev->timer_set = 0;  /* 0表示不受监控 */
        /* 设置事件的超时标志位 */
        ev->timedout = 1;   /* 1表示已经超时 */
        /* 调用已超时事件的处理函数对该事件进行处理 */

        ngx_log_error(NGX_LOG_ERR, ev->log, 0, " ngx_event_expire_timers Entry handler ev:%p", ev);
        ev->handler(ev);
    }
}


void
ngx_event_cancel_timers(void)
{
    ngx_event_t        *ev;
    ngx_rbtree_node_t  *node, *root, *sentinel;

    sentinel = ngx_event_timer_rbtree.sentinel;

    for ( ;; ) {
        root = ngx_event_timer_rbtree.root;

        if (root == sentinel) {
            return;
        }

        node = ngx_rbtree_min(root, sentinel);

        ev = (ngx_event_t *) ((char *) node - offsetof(ngx_event_t, timer));

        if (!ev->cancelable) {
            return;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                       "event timer cancel: %d: %M",
                       ngx_event_ident(ev->data), ev->timer.key);

        ngx_rbtree_delete(&ngx_event_timer_rbtree, &ev->timer);

#if (NGX_DEBUG)
        ev->timer.left = NULL;
        ev->timer.right = NULL;
        ev->timer.parent = NULL;
#endif

        ev->timer_set = 0;

        ngx_log_error(NGX_LOG_ERR, ev->log, 0, " ngx_event_cancel_timers Entry handler ev:%p", ev);
        ev->handler(ev);
    }
}
