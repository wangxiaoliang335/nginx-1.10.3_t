
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_PROCESS_H_INCLUDED_
#define _NGX_PROCESS_H_INCLUDED_


#include <ngx_setaffinity.h>
#include <ngx_setproctitle.h>


typedef pid_t       ngx_pid_t;

#define NGX_INVALID_PID  -1

typedef void (*ngx_spawn_proc_pt) (ngx_cycle_t *cycle, void *data);

// nginx master与worker进程之间使用unix套接字进行通信： 
// nginx在创建worker进程前先调用socketpair(int channel[2])，
// 然后将channel[0-1]设置为异步读写方式，并注册event事件，父进程使用channel[0]，子进程使用channel[1]实现双方的通信。

// respawn用于标记进程挂了要不要重启，启动的worker进程都是设置respawn=1的
// （不管ngx_start_worker_processes()用NGX_PROCESS_RESPAWN 还是 NGX_PROCESS_JUST_RESPAWN)。
// 如果worker进程的退出返回值是2，即fatal error的话，则不重启了：
typedef struct {
    ngx_pid_t           pid;            //代表该进程PID
    int                 status;         //用于保存子进程的退出状态
    ngx_socket_t        channel[2];     //进程的channel，通过socketpair来创建

    ngx_spawn_proc_pt   proc;           //进程的初始化函数，在每次创建完worker进程时调用
    void               *data;           //向进程初始化函数传递的参数
    char               *name;           //进程名称

    unsigned            respawn:1;      //对这些标示，我们下面会做详细介绍
    unsigned            just_spawn:1;
    unsigned            detached:1;
    unsigned            exiting:1;      //表明该进程处于正在退出状态
    unsigned            exited:1;       //表明该进程已经退出了
} ngx_process_t;


typedef struct {
    char         *path;     //用于传递可执行文件路径
    char         *name;     //用于传递要创建的进程的名称
    char *const  *argv;     //用于传递相关参数
    char *const  *envp;     //用于传递相关环境变量
} ngx_exec_ctx_t;


#define NGX_MAX_PROCESSES         1024      //定义最多可拥有的进程数目

//子进程退出时，父进程不会再次创建，该标记用在创建”cache loader process”。
#define NGX_PROCESS_NORESPAWN     -1

// 当nginx -s reload时，如果还有未加载的proxy_cache_path，
// 则需要再次创建”cache loader process”加载，
// 并用NGX_PROCESS_JUST_SPAWN给这个进程做记号。
// 防止nginx master向老的worker进程、老的cache manager进程、老的cache loader进程（如果存在）发送NGX_CMD_QUIT或SIGQUIT时，
// 误以为我们新创建的”cache loader process”是原来老旧的，而将其错误的杀掉。
#define NGX_PROCESS_JUST_SPAWN    -2

//子进程异常退出时，master会重新创建它，如当worker或cache manager process异常退出时，父进程会重新创建它。
#define NGX_PROCESS_RESPAWN       -3

// 当nginx -s reload时，master会向老的worker进程，老的cache manager process，
// 老的cache loader process(如果存在)发送ngx_write_channel(NGX_CMD_QUIT)(如果失败则发送SIGQUIT信号）。
// NGX_PROCESS_JUST_RESPAWN用来标记进程数组中哪些是新创建的子进程，而其他的就是属于老的子进程。
#define NGX_PROCESS_JUST_RESPAWN  -4

//热代码替换(这里通过exec函数族替换当前进程)。
#define NGX_PROCESS_DETACHED      -5


#define ngx_getpid   getpid

#ifndef ngx_log_pid
#define ngx_log_pid  ngx_pid
#endif


ngx_pid_t ngx_spawn_process(ngx_cycle_t *cycle,
    ngx_spawn_proc_pt proc, void *data, char *name, ngx_int_t respawn);
ngx_pid_t ngx_execute(ngx_cycle_t *cycle, ngx_exec_ctx_t *ctx);
ngx_int_t ngx_init_signals(ngx_log_t *log);
void ngx_debug_point(void);


#if (NGX_HAVE_SCHED_YIELD)
#define ngx_sched_yield()  sched_yield()
#else
#define ngx_sched_yield()  usleep(1)
#endif


extern int            ngx_argc;
extern char         **ngx_argv;
extern char         **ngx_os_argv;

extern ngx_pid_t      ngx_pid;
extern ngx_socket_t   ngx_channel;
extern ngx_int_t      ngx_process_slot;
extern ngx_int_t      ngx_last_process;
extern ngx_process_t  ngx_processes[NGX_MAX_PROCESSES];


#endif /* _NGX_PROCESS_H_INCLUDED_ */
