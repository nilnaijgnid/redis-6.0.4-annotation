#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <limits.h>
#include "sds.h"
#include "sdsalloc.h"

const char *SDS_NOINIT = "SDS_NOINIT";

// 根据sds类型得到header大小
static inline int sdsHdrSize(char type)
{
    switch (type & SDS_TYPE_MASK)
    {
    case SDS_TYPE_5:
        return sizeof(struct sdshdr5);
    case SDS_TYPE_8:
        return sizeof(struct sdshdr8);
    case SDS_TYPE_16:
        return sizeof(struct sdshdr16);
    case SDS_TYPE_32:
        return sizeof(struct sdshdr32);
    case SDS_TYPE_64:
        return sizeof(struct sdshdr64);
    }
    return 0;
}

// 根据字符串长度计算与之相匹配的SDS类型
static inline char sdsReqType(size_t string_size)
{
    if (string_size < 1 << 5)
        return SDS_TYPE_5; //32
    if (string_size < 1 << 8)
        return SDS_TYPE_8; //256
    if (string_size < 1 << 16)
        return SDS_TYPE_16; //65535
#if (LONG_MAX == LLONG_MAX)
    if (string_size < 1ll << 32)
        return SDS_TYPE_32; //4294967296
    return SDS_TYPE_64;
#else
    return SDS_TYPE_32;
#endif
}

/* 创建一个新的sds字符串，初始内容被设置为init指针指向的内容，长度设置为参数initlen的值。
 * 如果初始内容为NULL，那么sds将为0字节，如果内容为SDS_NOINIT，那么buffer将不会被初始化
 * 该sds一直都是以Null结尾的，所以，即便你使用以下语句创建一个sds字符串
 * mystring = sdsnewlen("abc",3);
 * 你可以使用printf()函数来打印字符串，而且sds字符串是二进制安全的，允许'\0'出现在sds字符串
 * 的中间位置，因为sds的长度保存在了sds header中。*/
sds sdsnewlen(const void *init, size_t initlen)
{
    void *sh;
    sds s;
    // 选择sds类型
    char type = sdsReqType(initlen);
    // 空字符串一般用作追加来使用，这里优化了下，使用SDS_TYPE_8
    if (type == SDS_TYPE_5 && initlen == 0)
        type = SDS_TYPE_8;
    // 获取header的长度
    int hdrlen = sdsHdrSize(type);
    unsigned char *fp; /* flags pointer. */

    // 申请内存，header长度+初始长度+1（结束位\0）
    sh = s_malloc(hdrlen + initlen + 1);
    if (sh == NULL)
        return NULL;
    if (init == SDS_NOINIT)
        init = NULL;
    else if (!init)
        memset(sh, 0, hdrlen + initlen + 1);
    s = (char *)sh + hdrlen;
    fp = ((unsigned char *)s) - 1;
    switch (type)
    {
    case SDS_TYPE_5:
    {
        *fp = type | (initlen << SDS_TYPE_BITS);
        break;
    }
    case SDS_TYPE_8:
    {
        SDS_HDR_VAR(8, s);
        sh->len = initlen;
        sh->alloc = initlen;
        *fp = type;
        break;
    }
    case SDS_TYPE_16:
    {
        SDS_HDR_VAR(16, s);
        sh->len = initlen;
        sh->alloc = initlen;
        *fp = type;
        break;
    }
    case SDS_TYPE_32:
    {
        SDS_HDR_VAR(32, s);
        sh->len = initlen;
        sh->alloc = initlen;
        *fp = type;
        break;
    }
    case SDS_TYPE_64:
    {
        SDS_HDR_VAR(64, s);
        sh->len = initlen;
        sh->alloc = initlen;
        *fp = type;
        break;
    }
    }
    if (initlen && init)
        memcpy(s, init, initlen);
    s[initlen] = '\0';
    return s;
}

/* 创建一个长度为0的空sds */
sds sdsempty(void)
{
    return sdsnewlen("", 0);
}

/* 以一个null结尾的c字符串创建一个sds字符串  */
sds sdsnew(const char *init)
{
    size_t initlen = (init == NULL) ? 0 : strlen(init);
    return sdsnewlen(init, initlen);
}

/* 复制sds字符串 */
sds sdsdup(const sds s)
{
    return sdsnewlen(s, sdslen(s));
}

/* 释放一个sds字符串，如果s为空则不操作 */
void sdsfree(sds s)
{
    if (s == NULL)
        return;
    s_free((char *)s - sdsHdrSize(s[-1]));
}

/* 设置sds长度为通过strlen()函数获取到的结果，所以只考虑到第一个空字符截止。
 * 当以某种方式手动方式修改sds字符串时，此函数非常有用，如下例所示：
 * 
 * s = sdsnew("foobar");
 * s[2] = '\0';
 * sdsupdatelen(s);
 * printf("%d\n", sdslen(s));
 * 
 * 输出的结果是2，但是如果注释了sdsupdatelen()函数的调用，那么输出的结果是6
 * 相当于字符串被修改了，但是长度还是6字节
 * */
void sdsupdatelen(sds s)
{
    size_t reallen = strlen(s);
    sdssetlen(s, reallen);
}

/* 修改sds字符串使其为空（长度为0）。但是，不会丢弃所有现有缓冲区，
 * 而是将其设置为可用空间，以便下一个追加操作不需要分配以前可用的字节数 */
void sdsclear(sds s)
{
    sdssetlen(s, 0);
    s[0] = '\0';
}

/* 在sds字符串之后扩大可用空间，保证该sds可以再写入addlen长度的字符串，另外加上一个空字节 */
sds sdsMakeRoomFor(sds s, size_t addlen)
{
    void *sh, *newsh;
    // 计算剩余可用字节
    size_t avail = sdsavail(s);
    size_t len, newlen;
    char type, oldtype = s[-1] & SDS_TYPE_MASK;
    int hdrlen;

    /* 如果有足够的空间，尽快返回 */
    if (avail >= addlen)
        return s;

    len = sdslen(s);
    sh = (char *)s - sdsHdrSize(oldtype);
    newlen = (len + addlen);
    if (newlen < SDS_MAX_PREALLOC)
        newlen *= 2;
    else
        newlen += SDS_MAX_PREALLOC;

    type = sdsReqType(newlen);

    if (type == SDS_TYPE_5)
        type = SDS_TYPE_8;

    hdrlen = sdsHdrSize(type);
    if (oldtype == type)
    {
        newsh = s_realloc(sh, hdrlen + newlen + 1);
        if (newsh == NULL)
            return NULL;
        s = (char *)newsh + hdrlen;
    }
    else
    {
        /* Since the header size changes, need to move the string forward,
         * and can't use realloc */
        newsh = s_malloc(hdrlen + newlen + 1);
        if (newsh == NULL)
            return NULL;
        memcpy((char *)newsh + hdrlen, s, len + 1);
        s_free(sh);
        s = (char *)newsh + hdrlen;
        s[-1] = type;
        sdssetlen(s, len);
    }
    sdssetalloc(s, newlen);
    return s;
}

/* 重新分配sds字符串，使其末端没有可用空间。包含的字符串保持不变，但下一个连接操作将需要重新分配。
 * 调用之后，传递的sds字符串不再有效，所有引用都必须替换为调用返回的新指针。 */
sds sdsRemoveFreeSpace(sds s)
{
    void *sh, *newsh;
    char type, oldtype = s[-1] & SDS_TYPE_MASK;
    int hdrlen, oldhdrlen = sdsHdrSize(oldtype);
    size_t len = sdslen(s);
    size_t avail = sdsavail(s);
    sh = (char *)s - oldhdrlen;

    /* 如果没有剩余空间，尽快返回 */
    if (avail == 0)
        return s;

    /* 计算最合适存储当前长度的sds类型 */
    type = sdsReqType(len);
    hdrlen = sdsHdrSize(type);

    /* 如果类型相同，或者至少仍然需要一个足够大的类型，我们只需调用realloc()函数，
     * 让分配器仅在真正需要时执行复制。否则，如果更改很大，我们将手动重新分配字符串
     * 以使用不同的头类型。 */
    if (oldtype == type || type > SDS_TYPE_8)
    {
        newsh = s_realloc(sh, oldhdrlen + len + 1);
        if (newsh == NULL)
            return NULL;
        s = (char *)newsh + oldhdrlen;
    }
    else
    {
        newsh = s_malloc(hdrlen + len + 1);
        if (newsh == NULL)
            return NULL;
        memcpy((char *)newsh + hdrlen, s, len + 1);
        s_free(sh);
        s = (char *)newsh + hdrlen;
        s[-1] = type;
        sdssetlen(s, len);
    }
    sdssetalloc(s, len);
    return s;
}

/* 返回sds占用的空间大小（headerSize + len + avaliable + '\0') */
size_t sdsAllocSize(sds s)
{
    size_t alloc = sdsalloc(s);
    return sdsHdrSize(s[-1]) + alloc + 1;
}

/* 返回sds的指针，通常为sds的buffer开头的位置 */
void *sdsAllocPtr(sds s)
{
    return (void *)(s - sdsHdrSize(s[-1]));
}

/* 增加sds的长度，并根据'incr'减少sds之后剩余空间，并且在新的字符串之后设置'\0'
 * 这个函数用于在用户调用sdsMakeRoomFor()函数在当前字符串的基础上新增内容之后
 * 修复字符串的长度。*/
void sdsIncrLen(sds s, ssize_t incr)
{
    unsigned char flags = s[-1];
    size_t len;
    switch (flags & SDS_TYPE_MASK)
    {
    case SDS_TYPE_5:
    {
        unsigned char *fp = ((unsigned char *)s) - 1;
        unsigned char oldlen = SDS_TYPE_5_LEN(flags);
        assert((incr > 0 && oldlen + incr < 32) || (incr < 0 && oldlen >= (unsigned int)(-incr)));
        *fp = SDS_TYPE_5 | ((oldlen + incr) << SDS_TYPE_BITS);
        len = oldlen + incr;
        break;
    }
    case SDS_TYPE_8:
    {
        SDS_HDR_VAR(8, s);
        assert((incr >= 0 && sh->alloc - sh->len >= incr) || (incr < 0 && sh->len >= (unsigned int)(-incr)));
        len = (sh->len += incr);
        break;
    }
    case SDS_TYPE_16:
    {
        SDS_HDR_VAR(16, s);
        assert((incr >= 0 && sh->alloc - sh->len >= incr) || (incr < 0 && sh->len >= (unsigned int)(-incr)));
        len = (sh->len += incr);
        break;
    }
    case SDS_TYPE_32:
    {
        SDS_HDR_VAR(32, s);
        assert((incr >= 0 && sh->alloc - sh->len >= (unsigned int)incr) || (incr < 0 && sh->len >= (unsigned int)(-incr)));
        len = (sh->len += incr);
        break;
    }
    case SDS_TYPE_64:
    {
        SDS_HDR_VAR(64, s);
        assert((incr >= 0 && sh->alloc - sh->len >= (uint64_t)incr) || (incr < 0 && sh->len >= (uint64_t)(-incr)));
        len = (sh->len += incr);
        break;
    }
    default:
        len = 0; /* Just to avoid compilation warnings. */
    }
    s[len] = '\0';
}

// 调用sdsMakeRoomFor()函数，将sds的容量扩展到长度为len，新增的空间设置为'\0'
sds sdsgrowzero(sds s, size_t len)
{
    size_t curlen = sdslen(s);

    if (len <= curlen)
        return s;
    s = sdsMakeRoomFor(s, len - curlen);
    if (s == NULL)
        return NULL;

    memset(s + curlen, 0, (len - curlen + 1));
    sdssetlen(s, len);
    return s;
}

// 将t所指向的字符串追加到sds之后
sds sdscatlen(sds s, const void *t, size_t len)
{
    size_t curlen = sdslen(s);

    s = sdsMakeRoomFor(s, len);
    if (s == NULL)
        return NULL;
    memcpy(s + curlen, t, len);
    sdssetlen(s, curlen + len);
    s[curlen + len] = '\0';
    return s;
}

// 添加一个以null结尾的c字符串到sds后
sds sdscat(sds s, const char *t)
{
    return sdscatlen(s, t, strlen(t));
}

// 添加一个sds到另一个sds之后
sds sdscatsds(sds s, const sds t)
{
    return sdscatlen(s, t, sdslen(t));
}

// 破坏性地修改sds字符串s，用来存储二进制安全的长度为len的字符串t
sds sdscpylen(sds s, const char *t, size_t len)
{
    if (sdsalloc(s) < len)
    {
        s = sdsMakeRoomFor(s, len - sdslen(s));
        if (s == NULL)
            return NULL;
    }
    memcpy(s, t, len);
    s[len] = '\0';
    sdssetlen(s, len);
    return s;
}

// 与sdscpylen功能相似，但是t必须为以null结尾的字符串
sds sdscpy(sds s, const char *t)
{
    return sdscpylen(s, t, strlen(t));
}

#define SDS_LLSTR_SIZE 21
/* long long转换成str */
int sdsll2str(char *s, long long value)
{
    char *p, aux;
    unsigned long long v;
    size_t l;

    /* Generate the string representation, this method produces
     * an reversed string. */
    v = (value < 0) ? -value : value;
    p = s;
    do
    {
        *p++ = '0' + (v % 10);
        v /= 10;
    } while (v);
    if (value < 0)
        *p++ = '-';

    /* Compute length and add null term. */
    l = p - s;
    *p = '\0';

    /* Reverse the string. */
    p--;
    while (s < p)
    {
        aux = *s;
        *s = *p;
        *p = aux;
        s++;
        p--;
    }
    return l;
}

/* 和sdsll2str()函数完全相同，只不过适用于无符号的long long类型 */
int sdsull2str(char *s, unsigned long long v)
{
    char *p, aux;
    size_t l;

    /* Generate the string representation, this method produces
     * an reversed string. */
    p = s;
    do
    {
        *p++ = '0' + (v % 10);
        v /= 10;
    } while (v);

    /* Compute length and add null term. */
    l = p - s;
    *p = '\0';

    /* Reverse the string. */
    p--;
    while (s < p)
    {
        aux = *s;
        *s = *p;
        *p = aux;
        s++;
        p--;
    }
    return l;
}

/* 从一个long long类型的值创建一个sds字符串，比下面的方式快很多：
 * sdscatprintf(sdsempty(),"%lld\n", value);
 * */
sds sdsfromlonglong(long long value)
{
    char buf[SDS_LLSTR_SIZE];
    int len = sdsll2str(buf, value);

    return sdsnewlen(buf, len);
}

/* Like sdscatprintf() but gets va_list instead of being variadic. */
sds sdscatvprintf(sds s, const char *fmt, va_list ap)
{
    va_list cpy;
    char staticbuf[1024], *buf = staticbuf, *t;
    size_t buflen = strlen(fmt) * 2;

    /* We try to start using a static buffer for speed.
     * If not possible we revert to heap allocation. */
    if (buflen > sizeof(staticbuf))
    {
        buf = s_malloc(buflen);
        if (buf == NULL)
            return NULL;
    }
    else
    {
        buflen = sizeof(staticbuf);
    }

    /* Try with buffers two times bigger every time we fail to
     * fit the string in the current buffer size. */
    while (1)
    {
        buf[buflen - 2] = '\0';
        va_copy(cpy, ap);
        vsnprintf(buf, buflen, fmt, cpy);
        va_end(cpy);
        if (buf[buflen - 2] != '\0')
        {
            if (buf != staticbuf)
                s_free(buf);
            buflen *= 2;
            buf = s_malloc(buflen);
            if (buf == NULL)
                return NULL;
            continue;
        }
        break;
    }

    /* Finally concat the obtained string to the SDS string and return it. */
    t = sdscat(s, buf);
    if (buf != staticbuf)
        s_free(buf);
    return t;
}

/* 通过printf的格式将字符串追加到sds中 */
sds sdscatprintf(sds s, const char *fmt, ...)
{
    va_list ap;
    char *t;
    va_start(ap, fmt);
    t = sdscatvprintf(s, fmt, ap);
    va_end(ap);
    return t;
}

/* This function is similar to sdscatprintf, but much faster as it does
 * not rely on sprintf() family functions implemented by the libc that
 * are often very slow. Moreover directly handling the sds string as
 * new data is concatenated provides a performance improvement.
 *
 * However this function only handles an incompatible subset of printf-alike
 * format specifiers:
 *
 * %s - C String
 * %S - SDS string
 * %i - signed int
 * %I - 64 bit signed integer (long long, int64_t)
 * %u - unsigned int
 * %U - 64 bit unsigned integer (unsigned long long, uint64_t)
 * %% - Verbatim "%" character.
 */
sds sdscatfmt(sds s, char const *fmt, ...)
{
    size_t initlen = sdslen(s);
    const char *f = fmt;
    long i;
    va_list ap;

    /* To avoid continuous reallocations, let's start with a buffer that
     * can hold at least two times the format string itself. It's not the
     * best heuristic but seems to work in practice. */
    s = sdsMakeRoomFor(s, initlen + strlen(fmt) * 2);
    va_start(ap, fmt);
    f = fmt;     /* Next format specifier byte to process. */
    i = initlen; /* Position of the next byte to write to dest str. */
    while (*f)
    {
        char next, *str;
        size_t l;
        long long num;
        unsigned long long unum;

        /* Make sure there is always space for at least 1 char. */
        if (sdsavail(s) == 0)
        {
            s = sdsMakeRoomFor(s, 1);
        }

        switch (*f)
        {
        case '%':
            next = *(f + 1);
            f++;
            switch (next)
            {
            case 's':
            case 'S':
                str = va_arg(ap, char *);
                l = (next == 's') ? strlen(str) : sdslen(str);
                if (sdsavail(s) < l)
                {
                    s = sdsMakeRoomFor(s, l);
                }
                memcpy(s + i, str, l);
                sdsinclen(s, l);
                i += l;
                break;
            case 'i':
            case 'I':
                if (next == 'i')
                    num = va_arg(ap, int);
                else
                    num = va_arg(ap, long long);
                {
                    char buf[SDS_LLSTR_SIZE];
                    l = sdsll2str(buf, num);
                    if (sdsavail(s) < l)
                    {
                        s = sdsMakeRoomFor(s, l);
                    }
                    memcpy(s + i, buf, l);
                    sdsinclen(s, l);
                    i += l;
                }
                break;
            case 'u':
            case 'U':
                if (next == 'u')
                    unum = va_arg(ap, unsigned int);
                else
                    unum = va_arg(ap, unsigned long long);
                {
                    char buf[SDS_LLSTR_SIZE];
                    l = sdsull2str(buf, unum);
                    if (sdsavail(s) < l)
                    {
                        s = sdsMakeRoomFor(s, l);
                    }
                    memcpy(s + i, buf, l);
                    sdsinclen(s, l);
                    i += l;
                }
                break;
            default: /* Handle %% and generally %<unknown>. */
                s[i++] = next;
                sdsinclen(s, 1);
                break;
            }
            break;
        default:
            s[i++] = *f;
            sdsinclen(s, 1);
            break;
        }
        f++;
    }
    va_end(ap);

    /* Add null-term */
    s[i] = '\0';
    return s;
}

/* 在sds中从左向右匹配'cset'中的字符并移除
 * 例如：
 * 
 * s = sdsnew("AA...AA.a.aa.aHelloWorld     :::");
 * s = sdstrim(s,"Aa. :");
 * printf("%s\n", s); 
 * 
 * 将只会输出“HelloWorld” */

sds sdstrim(sds s, const char *cset)
{
    char *start, *end, *sp, *ep;
    size_t len;

    sp = start = s;
    ep = end = s + sdslen(s) - 1;
    while (sp <= end && strchr(cset, *sp))
        sp++;
    while (ep > sp && strchr(cset, *ep))
        ep--;
    len = (sp > ep) ? 0 : ((ep - sp) + 1);
    if (s != sp)
        memmove(s, sp, len);
    s[len] = '\0';
    sdssetlen(s, len);
    return s;
}

/* 将字符串截取为一个更短或者相等长度的子字符串，范围为索引start和end的位置
 * start和end可以为负数，-1代表最后一个字符串，-2代表倒数第二个字符串，以此类推
 * 区间是包含的，因此start和end索引位置的字符将是结果字符串的一部分。
 * 例如：
* s = sdsnew("Hello World");
 * sdsrange(s,1,-1); => "ello World"
 */
void sdsrange(sds s, ssize_t start, ssize_t end)
{
    size_t newlen, len = sdslen(s);

    if (len == 0)
        return;
    if (start < 0)
    {
        start = len + start;
        if (start < 0)
            start = 0;
    }
    if (end < 0)
    {
        end = len + end;
        if (end < 0)
            end = 0;
    }
    newlen = (start > end) ? 0 : (end - start) + 1;
    if (newlen != 0)
    {
        if (start >= (ssize_t)len)
        {
            newlen = 0;
        }
        else if (end >= (ssize_t)len)
        {
            end = len - 1;
            newlen = (start > end) ? 0 : (end - start) + 1;
        }
    }
    else
    {
        start = 0;
    }
    if (start && newlen)
        memmove(s, s + start, newlen);
    s[newlen] = 0;
    sdssetlen(s, newlen);
}

/* 将sds中的每个字符转换成小写字母 */
void sdstolower(sds s)
{
    size_t len = sdslen(s), j;

    for (j = 0; j < len; j++)
        s[j] = tolower(s[j]);
}

/* 将sds中的每个字符转换成大写字母 */
void sdstoupper(sds s)
{
    size_t len = sdslen(s), j;

    for (j = 0; j < len; j++)
        s[j] = toupper(s[j]);
}

/* 使用memcmp()函数比较sds字符串，s1和s2
 * 返回值：
 *      如果s1 > s2则返回正数
 *      如果s1 < s2则返回负数
 *      如果s1和s2这两个二进制字符串完全相等则返回0
 * 如果两个字符串前一部分完全相同，那么则认为较长的的字符串比较短的字符串大 */
int sdscmp(const sds s1, const sds s2)
{
    size_t l1, l2, minlen;
    int cmp;

    l1 = sdslen(s1);
    l2 = sdslen(s2);
    minlen = (l1 < l2) ? l1 : l2;
    cmp = memcmp(s1, s2, minlen);
    if (cmp == 0)
        return l1 > l2 ? 1 : (l1 < l2 ? -1 : 0);
    return cmp;
}

/*使用’sep‘中的分隔符拆分字符串’s‘，返回sds字符串数组。
 * 这个版本的函数是二进制安全的，但是需要一个长度的参数，
 * sdssplit()函数适用于以0结尾的字符串 */
sds *sdssplitlen(const char *s, ssize_t len, const char *sep, int seplen, int *count)
{
    int elements = 0, slots = 5;
    long start = 0, j;
    sds *tokens;

    if (seplen < 1 || len < 0)
        return NULL;

    tokens = s_malloc(sizeof(sds) * slots);
    if (tokens == NULL)
        return NULL;

    if (len == 0)
    {
        *count = 0;
        return tokens;
    }
    for (j = 0; j < (len - (seplen - 1)); j++)
    {
        /* make sure there is room for the next element and the final one */
        if (slots < elements + 2)
        {
            sds *newtokens;

            slots *= 2;
            newtokens = s_realloc(tokens, sizeof(sds) * slots);
            if (newtokens == NULL)
                goto cleanup;
            tokens = newtokens;
        }
        /* search the separator */
        if ((seplen == 1 && *(s + j) == sep[0]) || (memcmp(s + j, sep, seplen) == 0))
        {
            tokens[elements] = sdsnewlen(s + start, j - start);
            if (tokens[elements] == NULL)
                goto cleanup;
            elements++;
            start = j + seplen;
            j = j + seplen - 1; /* skip the separator */
        }
    }
    /* Add the final element. We are sure there is room in the tokens array. */
    tokens[elements] = sdsnewlen(s + start, len - start);
    if (tokens[elements] == NULL)
        goto cleanup;
    elements++;
    *count = elements;
    return tokens;

cleanup:
{
    int i;
    for (i = 0; i < elements; i++)
        sdsfree(tokens[i]);
    s_free(tokens);
    *count = 0;
    return NULL;
}
}

/* 释放sdssplitlen函数的返回结果 */
void sdsfreesplitres(sds *tokens, int count)
{
    if (!tokens)
        return;
    while (count--)
        sdsfree(tokens[count]);
    s_free(tokens);
}

/* 在sds字符串“s”后面附加一个转义字符串表达式，其中所有不可打印的字符
 *（使用isprint()函数测试）都将转换为“\n\r\a…”或“\x<hex number>”
 * 形式的转义符。调用之后，修改后的sds字符串不再有效，所有引用都必须替换
 * 为调用返回的新指针。 */
sds sdscatrepr(sds s, const char *p, size_t len)
{
    s = sdscatlen(s, "\"", 1);
    while (len--)
    {
        switch (*p)
        {
        case '\\':
        case '"':
            s = sdscatprintf(s, "\\%c", *p);
            break;
        case '\n':
            s = sdscatlen(s, "\\n", 2);
            break;
        case '\r':
            s = sdscatlen(s, "\\r", 2);
            break;
        case '\t':
            s = sdscatlen(s, "\\t", 2);
            break;
        case '\a':
            s = sdscatlen(s, "\\a", 2);
            break;
        case '\b':
            s = sdscatlen(s, "\\b", 2);
            break;
        default:
            if (isprint(*p))
                s = sdscatprintf(s, "%c", *p);
            else
                s = sdscatprintf(s, "\\x%02x", (unsigned char)*p);
            break;
        }
        p++;
    }
    return sdscatlen(s, "\"", 1);
}

/* sdssplitargs()函数的帮助函数，如果是合法的十六进制字符则返回非零 */
int is_hex_digit(char c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
           (c >= 'A' && c <= 'F');
}

/* sdssplitargs()函数的帮助函数，将一个十六进制的字符装换为0-15的数字 */
int hex_digit_to_int(char c)
{
    switch (c)
    {
    case '0':
        return 0;
    case '1':
        return 1;
    case '2':
        return 2;
    case '3':
        return 3;
    case '4':
        return 4;
    case '5':
        return 5;
    case '6':
        return 6;
    case '7':
        return 7;
    case '8':
        return 8;
    case '9':
        return 9;
    case 'a':
    case 'A':
        return 10;
    case 'b':
    case 'B':
        return 11;
    case 'c':
    case 'C':
        return 12;
    case 'd':
    case 'D':
        return 13;
    case 'e':
    case 'E':
        return 14;
    case 'f':
    case 'F':
        return 15;
    default:
        return 0;
    }
}

/* 将一行拆分为参数，其中每个参数都可以采用以下编程语言格式：
 * foo bar "newline are supported\n" and "\xff\x00otherstuff"
 * 参数的数量保存到*argc中，返回一个sds的数组
 * 调用者应该使用sdsfreesplitres()函数释放sds数组的返回结果
 * 注意，sdscatrepr()函数能够将字符串转换回sdssplitargs()函数能够解析的格式相同的带引号的字符串。*/
sds *sdssplitargs(const char *line, int *argc)
{
    const char *p = line;
    char *current = NULL;
    char **vector = NULL;

    *argc = 0;
    while (1)
    {
        /* 跳过空白 */
        while (*p && isspace(*p))
            p++;
        if (*p)
        {
            /* get a token */
            int inq = 0;  /* set to 1 if we are in "quotes" */
            int insq = 0; /* set to 1 if we are in 'single quotes' */
            int done = 0;

            if (current == NULL)
                current = sdsempty();
            while (!done)
            {
                if (inq)
                {
                    if (*p == '\\' && *(p + 1) == 'x' &&
                        is_hex_digit(*(p + 2)) &&
                        is_hex_digit(*(p + 3)))
                    {
                        unsigned char byte;

                        byte = (hex_digit_to_int(*(p + 2)) * 16) +
                               hex_digit_to_int(*(p + 3));
                        current = sdscatlen(current, (char *)&byte, 1);
                        p += 3;
                    }
                    else if (*p == '\\' && *(p + 1))
                    {
                        char c;

                        p++;
                        switch (*p)
                        {
                        case 'n':
                            c = '\n';
                            break;
                        case 'r':
                            c = '\r';
                            break;
                        case 't':
                            c = '\t';
                            break;
                        case 'b':
                            c = '\b';
                            break;
                        case 'a':
                            c = '\a';
                            break;
                        default:
                            c = *p;
                            break;
                        }
                        current = sdscatlen(current, &c, 1);
                    }
                    else if (*p == '"')
                    {
                        /* closing quote must be followed by a space or
                         * nothing at all. */
                        if (*(p + 1) && !isspace(*(p + 1)))
                            goto err;
                        done = 1;
                    }
                    else if (!*p)
                    {
                        /* unterminated quotes */
                        goto err;
                    }
                    else
                    {
                        current = sdscatlen(current, p, 1);
                    }
                }
                else if (insq)
                {
                    if (*p == '\\' && *(p + 1) == '\'')
                    {
                        p++;
                        current = sdscatlen(current, "'", 1);
                    }
                    else if (*p == '\'')
                    {
                        /* closing quote must be followed by a space or
                         * nothing at all. */
                        if (*(p + 1) && !isspace(*(p + 1)))
                            goto err;
                        done = 1;
                    }
                    else if (!*p)
                    {
                        /* unterminated quotes */
                        goto err;
                    }
                    else
                    {
                        current = sdscatlen(current, p, 1);
                    }
                }
                else
                {
                    switch (*p)
                    {
                    case ' ':
                    case '\n':
                    case '\r':
                    case '\t':
                    case '\0':
                        done = 1;
                        break;
                    case '"':
                        inq = 1;
                        break;
                    case '\'':
                        insq = 1;
                        break;
                    default:
                        current = sdscatlen(current, p, 1);
                        break;
                    }
                }
                if (*p)
                    p++;
            }
            /* add the token to the vector */
            vector = s_realloc(vector, ((*argc) + 1) * sizeof(char *));
            vector[*argc] = current;
            (*argc)++;
            current = NULL;
        }
        else
        {
            /* Even on empty input string return something not NULL. */
            if (vector == NULL)
                vector = s_malloc(sizeof(void *));
            return vector;
        }
    }

err:
    while ((*argc)--)
        sdsfree(vector[*argc]);
    s_free(vector);
    if (current)
        sdsfree(current);
    *argc = 0;
    return NULL;
}

/* 修改字符串，将“from”字符串中指定的字符集的所有匹配项替换为“to”数组中的相应字符。
 * 举例：sdsmapchars(mystring, "ho", "01", 2)
 * "hello"字符串将转换成"0ell1"
 * 这个函数将返回sds字符串指针，该指针始终与输入指针相同，因为不需要调整大小。 
 * 这是一个映射关系，替换字符也是根据对应的位置，例如只会将h替换为0，不会将h替换为1*/
sds sdsmapchars(sds s, const char *from, const char *to, size_t setlen)
{
    size_t j, i, l = sdslen(s);

    for (j = 0; j < l; j++)
    {
        for (i = 0; i < setlen; i++)
        {
            // 用相应位置的目标字符替换源字符
            if (s[j] == from[i])
            {
                s[j] = to[i];
                break;
            }
        }
    }
    return s;
}

/* 使用指定的分隔符连接c字符串，返回结果为sds字符串 */
sds sdsjoin(char **argv, int argc, char *sep)
{
    sds join = sdsempty();
    int j;

    for (j = 0; j < argc; j++)
    {
        join = sdscat(join, argv[j]);
        if (j != argc - 1)
            join = sdscat(join, sep);
    }
    return join;
}

/* 和sdsjoin()函数类似, 但是连接的是sds字符串数组 */
sds sdsjoinsds(sds *argv, int argc, const char *sep, size_t seplen)
{
    sds join = sdsempty();
    int j;

    for (j = 0; j < argc; j++)
    {
        join = sdscatsds(join, argv[j]);
        if (j != argc - 1)
            join = sdscatlen(join, sep, seplen);
    }
    return join;
}

void *sds_malloc(size_t size) { return s_malloc(size); }
void *sds_realloc(void *ptr, size_t size) { return s_realloc(ptr, size); }
void sds_free(void *ptr) { s_free(ptr); }

#if defined(SDS_TEST_MAIN)
#include <stdio.h>
#include "testhelp.h"
#include "limits.h"

#define UNUSED(x) (void)(x)
int sdsTest(void)
{
    {
        sds x = sdsnew("foo"), y;

        test_cond("Create a string and obtain the length",
                  sdslen(x) == 3 && memcmp(x, "foo\0", 4) == 0)

            sdsfree(x);
        x = sdsnewlen("foo", 2);
        test_cond("Create a string with specified length",
                  sdslen(x) == 2 && memcmp(x, "fo\0", 3) == 0)

            x = sdscat(x, "bar");
        test_cond("Strings concatenation",
                  sdslen(x) == 5 && memcmp(x, "fobar\0", 6) == 0);

        x = sdscpy(x, "a");
        test_cond("sdscpy() against an originally longer string",
                  sdslen(x) == 1 && memcmp(x, "a\0", 2) == 0)

            x = sdscpy(x, "xyzxxxxxxxxxxyyyyyyyyyykkkkkkkkkk");
        test_cond("sdscpy() against an originally shorter string",
                  sdslen(x) == 33 &&
                      memcmp(x, "xyzxxxxxxxxxxyyyyyyyyyykkkkkkkkkk\0", 33) == 0)

            sdsfree(x);
        x = sdscatprintf(sdsempty(), "%d", 123);
        test_cond("sdscatprintf() seems working in the base case",
                  sdslen(x) == 3 && memcmp(x, "123\0", 4) == 0)

            sdsfree(x);
        x = sdsnew("--");
        x = sdscatfmt(x, "Hello %s World %I,%I--", "Hi!", LLONG_MIN, LLONG_MAX);
        test_cond("sdscatfmt() seems working in the base case",
                  sdslen(x) == 60 &&
                      memcmp(x, "--Hello Hi! World -9223372036854775808,"
                                "9223372036854775807--",
                             60) == 0)
            printf("[%s]\n", x);

        sdsfree(x);
        x = sdsnew("--");
        x = sdscatfmt(x, "%u,%U--", UINT_MAX, ULLONG_MAX);
        test_cond("sdscatfmt() seems working with unsigned numbers",
                  sdslen(x) == 35 &&
                      memcmp(x, "--4294967295,18446744073709551615--", 35) == 0)

            sdsfree(x);
        x = sdsnew(" x ");
        sdstrim(x, " x");
        test_cond("sdstrim() works when all chars match",
                  sdslen(x) == 0)

            sdsfree(x);
        x = sdsnew(" x ");
        sdstrim(x, " ");
        test_cond("sdstrim() works when a single char remains",
                  sdslen(x) == 1 && x[0] == 'x')

            sdsfree(x);
        x = sdsnew("xxciaoyyy");
        sdstrim(x, "xy");
        test_cond("sdstrim() correctly trims characters",
                  sdslen(x) == 4 && memcmp(x, "ciao\0", 5) == 0)

            y = sdsdup(x);
        sdsrange(y, 1, 1);
        test_cond("sdsrange(...,1,1)",
                  sdslen(y) == 1 && memcmp(y, "i\0", 2) == 0)

            sdsfree(y);
        y = sdsdup(x);
        sdsrange(y, 1, -1);
        test_cond("sdsrange(...,1,-1)",
                  sdslen(y) == 3 && memcmp(y, "iao\0", 4) == 0)

            sdsfree(y);
        y = sdsdup(x);
        sdsrange(y, -2, -1);
        test_cond("sdsrange(...,-2,-1)",
                  sdslen(y) == 2 && memcmp(y, "ao\0", 3) == 0)

            sdsfree(y);
        y = sdsdup(x);
        sdsrange(y, 2, 1);
        test_cond("sdsrange(...,2,1)",
                  sdslen(y) == 0 && memcmp(y, "\0", 1) == 0)

            sdsfree(y);
        y = sdsdup(x);
        sdsrange(y, 1, 100);
        test_cond("sdsrange(...,1,100)",
                  sdslen(y) == 3 && memcmp(y, "iao\0", 4) == 0)

            sdsfree(y);
        y = sdsdup(x);
        sdsrange(y, 100, 100);
        test_cond("sdsrange(...,100,100)",
                  sdslen(y) == 0 && memcmp(y, "\0", 1) == 0)

            sdsfree(y);
        sdsfree(x);
        x = sdsnew("foo");
        y = sdsnew("foa");
        test_cond("sdscmp(foo,foa)", sdscmp(x, y) > 0)

            sdsfree(y);
        sdsfree(x);
        x = sdsnew("bar");
        y = sdsnew("bar");
        test_cond("sdscmp(bar,bar)", sdscmp(x, y) == 0)

            sdsfree(y);
        sdsfree(x);
        x = sdsnew("aar");
        y = sdsnew("bar");
        test_cond("sdscmp(bar,bar)", sdscmp(x, y) < 0)

            sdsfree(y);
        sdsfree(x);
        x = sdsnewlen("\a\n\0foo\r", 7);
        y = sdscatrepr(sdsempty(), x, sdslen(x));
        test_cond("sdscatrepr(...data...)",
                  memcmp(y, "\"\\a\\n\\x00foo\\r\"", 15) == 0)

        {
            unsigned int oldfree;
            char *p;
            int step = 10, j, i;

            sdsfree(x);
            sdsfree(y);
            x = sdsnew("0");
            test_cond("sdsnew() free/len buffers", sdslen(x) == 1 && sdsavail(x) == 0);

            /* Run the test a few times in order to hit the first two
             * SDS header types. */
            for (i = 0; i < 10; i++)
            {
                int oldlen = sdslen(x);
                x = sdsMakeRoomFor(x, step);
                int type = x[-1] & SDS_TYPE_MASK;

                test_cond("sdsMakeRoomFor() len", sdslen(x) == oldlen);
                if (type != SDS_TYPE_5)
                {
                    test_cond("sdsMakeRoomFor() free", sdsavail(x) >= step);
                    oldfree = sdsavail(x);
                }
                p = x + oldlen;
                for (j = 0; j < step; j++)
                {
                    p[j] = 'A' + j;
                }
                sdsIncrLen(x, step);
            }
            test_cond("sdsMakeRoomFor() content",
                      memcmp("0ABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJ", x, 101) == 0);
            test_cond("sdsMakeRoomFor() final length", sdslen(x) == 101);

            sdsfree(x);
        }
    }
    test_report() return 0;
}
#endif

#ifdef SDS_TEST_MAIN
int main(void)
{
    return sdsTest();
}
#endif
