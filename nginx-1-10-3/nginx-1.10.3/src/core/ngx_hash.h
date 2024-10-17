
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HASH_H_INCLUDED_
#define _NGX_HASH_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

// ngx_hash是nginx中的hash表结构，具有以下特点：

// 静态结构，hash表创建后无法动态添加/删除KV。
// 采用连续存储方式解决碰撞问题。即出现碰撞的KV存放在连续地址。
// 支持前缀和后缀通配符匹配。
// 以上特点决定了其高效性与功能局限性。

// 1.1 如何解决碰撞问题
// 通常有两个简单的解决方法：分离链接法和开放寻址法。

// 分离链接法，就是把散列到同一个槽中的所有元素都放在散列表外的一个链表中，这样查询元素时，在找到这个槽后，还得遍
// 历链表才能找到正确的元素，以此来解决碰撞问题。

// 开放寻址法，即所有元素都存放在散列表中，当查找一个元素时，要检查规则内的所有表项（例如，连续的非空槽或者整个空
// 间内符合散列方法的所有槽），直到找到所需的元素，或者最终发现元素不在表中。开放寻址法中没有链表，也没有元素存放
// 在散列表外。

// Nginx 的散列表使用的是开放寻址法。
// 开放寻址法有许多种实现方法，Nginx 使用的是连续非空槽存储碰撞元素的方法。例如，当插入一个元素时，可以按照散列方
// 法找到指定槽，如果该槽非空且其存储的元素与待插入元素并非同一个元素，则依次检查其后连续的槽，直到找到一个空槽来
// 放置这个元素为止。查询元素时也是使用类似的方法，即从散列方法指定的位置起检查连续的非空槽中的元素。

// 每一个散列表槽都由 1 个 ngx_hash_elt_t 结构体表示，当然，这个槽的大小与 ngx_hash_elt_t 结构体的大小（即
// sizeof(ngx_hash_elt_t)）是不相等的，这是因为 name 成员只用于指出关键字的首地址，而关键字的长度是可变的。一个槽
// 占用多大的空间是在初始化散列表时决定的。
typedef struct {
    /* 指向用户自定义元素数据的指针，如果当前 ngx_hash_elt_t 槽为空，则 value 的值为 0 */
    void             *value;
    /* 元素关键字的长度 */
    u_short           len;
    /* 元素关键字的首地址 */
    u_char            name[1];
} ngx_hash_elt_t;


typedef struct {
    //hash表分多个桶，每个桶内存放hash(key)碰撞的元素
    ngx_hash_elt_t  **buckets;   /* 指向散列表的首地址，也是第 1 个槽的地址 */
    ngx_uint_t        size;      /* 散列表中槽的总数 */
} ngx_hash_t;


typedef struct {
    /* 基本散列表 */
    ngx_hash_t        hash;
    /* 当使用这个ngx_hash_wildcard_t通配符散列表作为某个容器的元素时，可以使用这个value  
     * 指针指向用户数据 */
    void             *value;
} ngx_hash_wildcard_t;


typedef struct {
    /* 元素关键字 */
    ngx_str_t         key;
    /* 由散列方法算出来的关键码 */
    ngx_uint_t        key_hash;
    /* 指向实际的用户数据 */
    void             *value;
} ngx_hash_key_t;


typedef ngx_uint_t (*ngx_hash_key_pt) (u_char *data, size_t len);

// nginx支持3种形式的通配符匹配。

// .example.com可以匹配example.com和www.example.com
// *.example.com 只可以匹配www.example.com不能匹配example.com
// www.example.*可以匹配www.example.com
// 内部是使用3张hash表分别保存精确匹配、头部统配、尾部统配。再查找是也区分精确查找、头部统配查找、尾部统配查找。

// 注：前置通配符散列表中元素的关键字，在把 * 通配符去掉后，会按照 "." 符号分隔，并以倒序的
// 方式作为关键字来存储元素。相应地，在查询元素时也是做相同处理。
typedef struct {
    /* 用于精确匹配的基本散列表 */
    ngx_hash_t            hash;
    /* 用于查询前置通配符的散列表 */
    ngx_hash_wildcard_t  *wc_head;
    /* 用于查询后置通配符的散列表 */
    ngx_hash_wildcard_t  *wc_tail;
} ngx_hash_combined_t;


typedef struct {
    ngx_hash_t       *hash;     /* 指向普通的完全匹配散列表 */
    ngx_hash_key_pt   key;      /* 用于初始化添加元素的散列方法 */

    ngx_uint_t        max_size; /* 散列表中槽的最大数目 */
    ngx_uint_t        bucket_size;  /* 散列表中一个槽的大小，它限制了每个散列表元素关键字的最大长度 */

    char             *name;     /* 散列表的名称 */
    ngx_pool_t       *pool;     /* 内存池，用于分配散列表（最多3个，包括1个普通散列表、1个前置通配符散列表、1个后置通配符散列表）
     * 中的所有槽 */
    ngx_pool_t       *temp_pool; /* 临时内存池，仅存在于初始化散列表之前。它主要用于分配一些临时的动态数组，
     * 带通配符的元素在初始化时需要用到这些数组 */
} ngx_hash_init_t;


#define NGX_HASH_SMALL            1
#define NGX_HASH_LARGE            2

#define NGX_HASH_LARGE_ASIZE      16384
#define NGX_HASH_LARGE_HSIZE      10007

#define NGX_HASH_WILDCARD_KEY     1
#define NGX_HASH_READONLY_KEY     2


typedef struct {
    /* 下面的keys_hash、dns_wc_head_hash、dns_wc_tail_hash都是简易散列表，而hsize指明了  
     * 散列表中槽的个数，其简易散列方法也需要对hsize求余 */
    ngx_uint_t        hsize;       //简易hash表的桶数量

    /* 内存池，用于分配永久性内存 */
    ngx_pool_t       *pool;
    /* 临时内存池，下面的动态数组需要的内存都由temp_pool内存池分配 */
    ngx_pool_t       *temp_pool;

    /* 用动态数组以ngx_hash_key_t结构体保存着不含有通配符关键字的元素 */
    ngx_array_t       keys;        //精确匹配的key列表

    /* 一个极其简易的散列表，它以数组的形式保存着hsize个元素，每个元素都是ngx_array_t  
     * 动态数组。在用户添加的元素过程中，会根据关键码将用户的ngx_str_t类型的关键字添加
     * 到ngx_array_t动态数组中。这里所有的用户元素的关键字都不可以带通配符，表示精确
     * 匹配 */
    ngx_array_t      *keys_hash;   //使用二维数组构造的简易hash表，用于检查key是否重复。

    /* 用动态数组以ngx_hash_key_t结构体保存着含有前置通配符关键字的元素生成的中间关键字 */
    ngx_array_t       dns_wc_head;

    /* 一个极其简易的散列表，它以数组的形式保存着hsize个元素，每个元素都是ngx_array_t  
     * 动态数组。在用户添加的元素过程中，会根据关键码将用户的ngx_str_t类型的关键字添加
     * 到ngx_array_t动态数组中。这里所有的用户元素的关键字都带前置通配符 */
    ngx_array_t      *dns_wc_head_hash;

    /* 用动态数组以ngx_hash_key_t结构体保存着含有后置通配符关键字的元素生成的中间关键字 */
    ngx_array_t       dns_wc_tail;

    /* 一个极其简易的散列表，它以数组的形式保存着hsize个元素，每个元素都是ngx_array_t  
     * 动态数组。在用户添加的元素过程中，会根据关键码将用户的ngx_str_t类型的关键字添加
     * 到ngx_array_t动态数组中。这里所有的用户元素的关键字都带后置通配符 */
    ngx_array_t      *dns_wc_tail_hash;
} ngx_hash_keys_arrays_t;


typedef struct {
    ngx_uint_t        hash;
    ngx_str_t         key;
    ngx_str_t         value;
    u_char           *lowcase_key;
} ngx_table_elt_t;


void *ngx_hash_find(ngx_hash_t *hash, ngx_uint_t key, u_char *name, size_t len);
void *ngx_hash_find_wc_head(ngx_hash_wildcard_t *hwc, u_char *name, size_t len);
void *ngx_hash_find_wc_tail(ngx_hash_wildcard_t *hwc, u_char *name, size_t len);
void *ngx_hash_find_combined(ngx_hash_combined_t *hash, ngx_uint_t key,
    u_char *name, size_t len);

//ngx_hash_key_t *names和ngx_uint_t nelts组成一组key不重复的KV集合。
//nginx提供了另外一组函数ngx_hash_keys_array_init()和ngx_hash_add_key()用于创造不重复的KV集合列表。
ngx_int_t ngx_hash_init(ngx_hash_init_t *hinit, ngx_hash_key_t *names,
    ngx_uint_t nelts);
ngx_int_t ngx_hash_wildcard_init(ngx_hash_init_t *hinit, ngx_hash_key_t *names,
    ngx_uint_t nelts);

#define ngx_hash(key, c)   ((ngx_uint_t) key * 31 + c)
ngx_uint_t ngx_hash_key(u_char *data, size_t len);
ngx_uint_t ngx_hash_key_lc(u_char *data, size_t len);
ngx_uint_t ngx_hash_strlow(u_char *dst, u_char *src, size_t n);


ngx_int_t ngx_hash_keys_array_init(ngx_hash_keys_arrays_t *ha, ngx_uint_t type);
ngx_int_t ngx_hash_add_key(ngx_hash_keys_arrays_t *ha, ngx_str_t *key,
    void *value, ngx_uint_t flags);


#endif /* _NGX_HASH_H_INCLUDED_ */
