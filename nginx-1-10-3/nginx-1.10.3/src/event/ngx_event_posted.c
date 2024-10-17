
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


ngx_queue_t  ngx_posted_accept_events;
ngx_queue_t  ngx_posted_events;

//post事件处理函数
/* 函数主要逻辑是从队列中*/
void
ngx_event_process_posted(ngx_cycle_t *cycle, ngx_queue_t *posted)
{
    ngx_queue_t  *q;
    ngx_event_t  *ev;
    /* 判断队列是否为null */
    while (!ngx_queue_empty(posted)) {

        q = ngx_queue_head(posted);
        ev = ngx_queue_data(q, ngx_event_t, queue);

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                      "posted event %p", ev);
        /* 将对当前事件从队列中删除 */
        ngx_delete_posted_event(ev);
        /* 处理当前事件的handler逻辑 */

        ngx_log_error(NGX_LOG_ERR, ev->log, 0, " ngx_event_process_posted Entry handler ev:%p", ev);
        ev->handler(ev);
    }
}
