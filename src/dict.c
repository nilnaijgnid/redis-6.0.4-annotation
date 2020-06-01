#include "fmacros.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <limits.h>
#include <sys/time.h>

#include "dict.h"
#include "zmalloc.h"
#ifndef DICT_BENCHMARK_MAIN
#include "redisassert.h"
#else
#include <assert.h>
#endif

/* redis使用dictEnableResize()和dictDisableResize()两个函数来设置是否可以在需要的
 * 时候执行哈希表的resize操作。这个对于redis非常重要，因为redis使用了写时复制，不希望在
 * 执行存储数据的时候移动太多内存 
 * 当dict_can_resize设置为0时，不代表所有的resize操作被禁止，
 * 当负载因子 > dict_force_resize_ratio时允许扩容的。 */
static int dict_can_resize = 1;

// ratio = used / size
static unsigned int dict_force_resize_ratio = 5;

/* -------------------------- private prototypes ---------------------------- */

static int _dictExpandIfNeeded(dict *ht);
static unsigned long _dictNextPower(unsigned long size);
static long _dictKeyIndex(dict *ht, const void *key, uint64_t hash, dictEntry **existing);
static int _dictInit(dict *ht, dictType *type, void *privDataPtr);

/* -------------------------- hash functions -------------------------------- */

static uint8_t dict_hash_function_seed[16];

void dictSetHashFunctionSeed(uint8_t *seed)
{
    memcpy(dict_hash_function_seed, seed, sizeof(dict_hash_function_seed));
}

uint8_t *dictGetHashFunctionSeed(void)
{
    return dict_hash_function_seed;
}

/* The default hashing function uses SipHash implementation
 * in siphash.c. */

uint64_t siphash(const uint8_t *in, const size_t inlen, const uint8_t *k);
uint64_t siphash_nocase(const uint8_t *in, const size_t inlen, const uint8_t *k);

uint64_t dictGenHashFunction(const void *key, int len)
{
    return siphash(key, len, dict_hash_function_seed);
}

uint64_t dictGenCaseHashFunction(const unsigned char *buf, int len)
{
    return siphash_nocase(buf, len, dict_hash_function_seed);
}

/* ----------------------------- API implementation ------------------------- */

/* 重置一个已经使用ht_init()函数初始化的哈希表，只能被ht_destroy()函数调用 */
static void _dictReset(dictht *ht)
{
    ht->table = NULL; // 释放table内存
    ht->size = 0;     // 哈希表的大小重置为0
    ht->sizemask = 0;
    ht->used = 0;
}

/* 创建一个哈希表 */
dict *dictCreate(dictType *type,
                 void *privDataPtr)
{
    dict *d = zmalloc(sizeof(*d));

    _dictInit(d, type, privDataPtr);
    return d;
}

/* 初始化哈希表 */
int _dictInit(dict *d, dictType *type,
              void *privDataPtr)
{
    _dictReset(&d->ht[0]); // 重置第0个哈希表
    _dictReset(&d->ht[1]); // 重置第1个哈希表
    d->type = type;
    d->privdata = privDataPtr;
    d->rehashidx = -1; // dict默认没有做rehash操作
    d->iterators = 0;
    return DICT_OK; // 初始化成功，返回0
}

/* 调整哈希表的大小，使用最小的容量存放所有的元素，但是USED/BUCKETS的值应该接近1 */
int dictResize(dict *d)
{
    unsigned long minimal;
    // 如果dict处于不能resize的状态或者正在rehash，则返回错误
    if (!dict_can_resize || dictIsRehashing(d))
        return DICT_ERR;
    minimal = d->ht[0].used;
    if (minimal < DICT_HT_INITIAL_SIZE)
        minimal = DICT_HT_INITIAL_SIZE;
    return dictExpand(d, minimal);
}

/* 扩展或者创建一个哈希表 */
int dictExpand(dict *d, unsigned long size)
{
    /* 判断dict是否在做rehash或者已使用的容量是否大于size */
    if (dictIsRehashing(d) || d->ht[0].used > size)
        return DICT_ERR;

    dictht n; /* 创建一个新的哈希表，用于替换旧的哈希表 */
    // 这里为了计算大于当然已使用的容量的最小2次幂，最为新的哈希表的容量
    unsigned long realsize = _dictNextPower(size);

    /* 如果目标哈希表的大小和当前已使用的大小一致，则没有必要扩容。返回错误 */
    if (realsize == d->ht[0].size)
        return DICT_ERR;

    /* 为新的hash表分配空间，并将所有的指针初始化为Null */
    n.size = realsize;
    n.sizemask = realsize - 1;
    n.table = zcalloc(realsize * sizeof(dictEntry *));
    n.used = 0;

    /* 如果哈希表是第一次初始化，则只需要设置第一个哈希表即可 */
    if (d->ht[0].table == NULL)
    {
        d->ht[0] = n;
        return DICT_OK;
    }

    /* 如果这次是rehash操作的话，需要准备第2个hash表，作为新的hash表 */
    d->ht[1] = n;
    d->rehashidx = 0;
    return DICT_OK;
}

/* 执行N次增量哈希，如果还有key需要从老的哈希表迁移到新的哈希表，则返回1，否则返回0
 * 需要注意的是，一次rehash的步骤是只将一整个bucket迁移到新的哈希表，一个bucket中可能包含多个key，
 * 有时候一个bucket中没有任何key，所以不能保证每次执行rehash步骤时都能将key从老的哈希表迁移到新的哈希表，
 * 所以，每次最毒迁移N*10个空的bucket，防止函数阻塞的时间过长 */
int dictRehash(dict *d, int n)
{
    int empty_visits = n * 10; /* 最大可能访问的空的bucket的数量 */
    // 如果没有在进行rehash，则返回0
    if (!dictIsRehashing(d))
        return 0;

    // 依次迁移N个bucket
    while (n-- && d->ht[0].used != 0)
    {
        dictEntry *de, *nextde;

        assert(d->ht[0].size > (unsigned long)d->rehashidx);
        // 如果hash表中某个hash表的bucket是空的，则不需要移动，rehashidx直接+1
        while (d->ht[0].table[d->rehashidx] == NULL)
        {
            d->rehashidx++;
            // 相应地，本次可以访问的空bucket的数量也要减1
            if (--empty_visits == 0)
                return 1;
        }

        // 计算本次要从哪个bucket开始移动
        de = d->ht[0].table[d->rehashidx];

        // 每个bucket中可能包含多个key，依次迁移
        while (de)
        {
            uint64_t h;

            nextde = de->next;
            /* 计算当前key在新的哈希表中的索引，并且移动到相应的位置 */
            h = dictHashKey(d, de->key) & d->ht[1].sizemask;
            de->next = d->ht[1].table[h];
            d->ht[1].table[h] = de;
            d->ht[0].used--;
            d->ht[1].used++;
            de = nextde;
        }
        d->ht[0].table[d->rehashidx] = NULL;
        d->rehashidx++;
    }

    /* 检查我们是否已经把所有的key都迁移完了 */
    if (d->ht[0].used == 0)
    {
        zfree(d->ht[0].table); // 哈希表0释放掉
        d->ht[0] = d->ht[1];   // 哈希表1赋值给哈希表0
        _dictReset(&d->ht[1]); // 哈希表1重置，等待下次rehash
        d->rehashidx = -1;     // rehashidx重置为-1，本次rehash结束
        return 0;              // rehash结束，返回0
    }

    /* rehash还未结束，还有更多的key需要迁移，返回1 */
    return 1;
}

// 获取毫秒单位的时间
long long timeInMilliseconds(void)
{
    struct timeval tv;

    gettimeofday(&tv, NULL);
    return (((long long)tv.tv_sec) * 1000) + (tv.tv_usec / 1000);
}

/* 在指定的时间段内，对dict进行rehash操作 */
int dictRehashMilliseconds(dict *d, int ms)
{
    // 获取当前时间，用来计时
    long long start = timeInMilliseconds();
    int rehashes = 0;

    // 每次进行100次rehash，如果时间还没到，再执行100次，以此类推
    while (dictRehash(d, 100))
    {
        rehashes += 100;
        // 时间到了，退出循环
        if (timeInMilliseconds() - start > ms)
            break;
    }
    // 返回本次执行的rehash的总次数
    return rehashes;
}

/* 这个函数只在没有安全迭代器绑定到哈希表的的条件下，执行一步rehash操作。当在rehash的过程中
 * 有迭代器绑定到哈希表上，我们不能将两个哈希表弄混，否则会遗漏或者重复一些数据 
 * 此函数由字典中的常见查找或更新操作调用，以便在主动使用哈希表时自动从H1迁移到H2 */
static void _dictRehashStep(dict *d)
{
    if (d->iterators == 0)
        dictRehash(d, 1);
}

/* 向哈希表中添加元素 */
int dictAdd(dict *d, void *key, void *val)
{
    dictEntry *entry = dictAddRaw(d, key, NULL);
    // 先判断key是添加成功，如果添加成功的话，设置key对应的value
    if (!entry)
        return DICT_ERR;
    dictSetVal(d, entry, val);
    return DICT_OK;
}

/* 底层的添加或者查找：
 * 此函数添加条目，但不设置值，而是将dictEntry结构返回给用户，
 * 这将确保按照用户的意愿填充value字段。这个函数还直接暴露给要调用的用户API，
 * 主要是为了在哈希值中存储非指针，例如：
 * 
 * entry = dictAddRaw(dict,mykey,NULL);
 * if (entry != NULL) dictSetSignedIntegerVal(entry,1000);
 * 
 * 返回值：
 * 如果key已经存在，则返回Null，如果key被添加成功，则返回对应entry的指针
 * */
dictEntry *dictAddRaw(dict *d, void *key, dictEntry **existing)
{
    long index;
    dictEntry *entry;
    dictht *ht;

    if (dictIsRehashing(d))
        _dictRehashStep(d);

    /* 计算index，如果key已经存在，返回Null */
    if ((index = _dictKeyIndex(d, key, dictHashKey(d, key), existing)) == -1)
        return NULL;

    // 如果dict在做rehash，则加到新的哈希表，否则加到原来的哈希表
    ht = dictIsRehashing(d) ? &d->ht[1] : &d->ht[0];
    // 为新的key分配内存
    entry = zmalloc(sizeof(*entry));
    // 新增的key会放在bucket的最前端，因为最近新增的key会认为被访问的可能性更大
    entry->next = ht->table[index];
    ht->table[index] = entry;
    ht->used++;

    dictSetKey(d, entry, key);
    return entry;
}

/* 新增或者覆盖：
 * 添加一个元素到dict，无论之前是否存在，存在的话替换原来的值。
 * 如果是新增的，返回1，如果是key已经存在并修改值的，返回0 */
int dictReplace(dict *d, void *key, void *val)
{
    dictEntry *entry, *existing, auxentry;

    /* key新增成功 */
    entry = dictAddRaw(d, key, &existing);
    if (entry)
    {
        dictSetVal(d, entry, val);
        return 1;
    }

    auxentry = *existing;
    dictSetVal(d, existing, val);
    dictFreeVal(d, &auxentry);
    return 0;
}

/* 增加后者查找：
 * 这是一个简易版本的dictAddRaw()函数，永远都返回指定key的哈希条目，如果key已经存了，
 * 就返回已经存在的哈希条目*/
dictEntry *dictAddOrFind(dict *d, void *key)
{
    dictEntry *entry, *existing;
    entry = dictAddRaw(d, key, &existing);
    return entry ? entry : existing;
}

/* 搜索并删除元素，这是dictDelete()和dictUnlink()函数的帮助函数 */
static dictEntry *dictGenericDelete(dict *d, const void *key, int nofree)
{
    uint64_t h, idx;
    dictEntry *he, *prevHe;
    int table;

    if (d->ht[0].used == 0 && d->ht[1].used == 0)
        return NULL;

    if (dictIsRehashing(d))
        _dictRehashStep(d);
    h = dictHashKey(d, key);

    for (table = 0; table <= 1; table++)
    {
        idx = h & d->ht[table].sizemask;
        he = d->ht[table].table[idx];
        prevHe = NULL;
        while (he)
        {
            if (key == he->key || dictCompareKeys(d, key, he->key))
            {
                /* Unlink the element from the list */
                if (prevHe)
                    prevHe->next = he->next;
                else
                    d->ht[table].table[idx] = he->next;
                if (!nofree)
                {
                    dictFreeKey(d, he);
                    dictFreeVal(d, he);
                    zfree(he);
                }
                d->ht[table].used--;
                return he;
            }
            prevHe = he;
            he = he->next;
        }
        if (!dictIsRehashing(d))
            break;
    }
    return NULL; /* not found */
}

/* 删除一个元素，删除成功返回DICT_OK，元素不存在返回DICT_ERR */
int dictDelete(dict *ht, const void *key)
{
    return dictGenericDelete(ht, key, 0) ? DICT_OK : DICT_ERR;
}

/* 从table中移除一个key，但是实际上不释放这个元素，如果这个元素存在的的话，就将它从
 * table中解绑并返回。之后用户可以调用dictFreeUnlinkedEntry()函数去释放该元素；
 * 如果没有找到该key的话就返回null
 * 这个函数在某些情况下比较有用，例如你想在删除这个元素之前还要使用这个元素，
 * 如果没有这个函数的话，你可能需要执行2次查询操作： 
 * 
 * entry = dictFind(...);
 * // Do something with entry
 * dictDelete(dictionary,entry);
 *  
 * 因为有这个函数的存在，我们避免使用以上方式，而是用以下方式代替：
 * 
 * entry = dictUnlink(dictionary,entry);
 * // Do something with entry
 * dictFreeUnlinkedEntry(entry); // 这里就不需要再去查找这个key了 */
dictEntry *dictUnlink(dict *ht, const void *key)
{
    return dictGenericDelete(ht, key, 1);
}

/* 调用完dictUnlink()这个函数之后再调用这个函数释放元素，即便该元素为空，也是安全的 */
void dictFreeUnlinkedEntry(dict *d, dictEntry *he)
{
    if (he == NULL)
        return;
    dictFreeKey(d, he);
    dictFreeVal(d, he);
    zfree(he);
}

/* 销毁整个字典中的内容 */
int _dictClear(dict *d, dictht *ht, void(callback)(void *))
{
    unsigned long i;

    /* 释放字典中所有的元素 */
    for (i = 0; i < ht->size && ht->used > 0; i++)
    {
        dictEntry *he, *nextHe;

        if (callback && (i & 65535) == 0)
            callback(d->privdata);

        if ((he = ht->table[i]) == NULL)
            continue;
        while (he)
        {
            nextHe = he->next;
            dictFreeKey(d, he);
            dictFreeVal(d, he);
            zfree(he);
            ht->used--;
            he = nextHe;
        }
    }
    zfree(ht->table);
    /* 重新初始化table */
    _dictReset(ht);
    return DICT_OK;
}

/* 清空并释放哈希表 */
void dictRelease(dict *d)
{
    _dictClear(d, &d->ht[0], NULL);
    _dictClear(d, &d->ht[1], NULL);
    zfree(d);
}

/* 查找元素 */
dictEntry *dictFind(dict *d, const void *key)
{
    dictEntry *he;
    uint64_t h, idx, table;
    // 哈希表为空，直接返回
    if (dictSize(d) == 0)
        return NULL;
    if (dictIsRehashing(d))
        _dictRehashStep(d);
    // 计算出该key应该在字典的哪个位置
    h = dictHashKey(d, key);
    for (table = 0; table <= 1; table++)
    {
        idx = h & d->ht[table].sizemask;
        he = d->ht[table].table[idx];
        while (he)
        {
            if (key == he->key || dictCompareKeys(d, key, he->key))
                return he;
            // 对比bucket列表中的每一个值
            he = he->next;
        }
        if (!dictIsRehashing(d))
            return NULL;
    }
    return NULL;
}

/* 获取字典中某个key对应的value */
void *dictFetchValue(dict *d, const void *key)
{
    dictEntry *he;

    he = dictFind(d, key);
    return he ? dictGetVal(he) : NULL;
}

/* A fingerprint is a 64 bit number that represents the state of the dictionary
 * at a given time, it's just a few dict properties xored together.
 * When an unsafe iterator is initialized, we get the dict fingerprint, and check
 * the fingerprint again when the iterator is released.
 * If the two fingerprints are different it means that the user of the iterator
 * performed forbidden operations against the dictionary while iterating. 
 * 指纹是一个代表字典当前状态的64位的数字，它是字典的一些属性的异或的结果。
 * 当一个不安全的迭代器被初始化的时候，我们获取到字典的指纹，当迭代器释放的时候，再次校验指纹。
 * 如果两个自问不一样的话，意味着在迭代子字典的时候用户执行了被禁止的操作 */
long long dictFingerprint(dict *d)
{
    long long integers[6], hash = 0;
    int j;

    integers[0] = (long)d->ht[0].table;
    integers[1] = d->ht[0].size;
    integers[2] = d->ht[0].used;
    integers[3] = (long)d->ht[1].table;
    integers[4] = d->ht[1].size;
    integers[5] = d->ht[1].used;

    /* 通过将每个连续整数与前一个和的整数哈希相加来哈希N个整数，相当于
     *
     * Result = hash(hash(hash(int1)+int2)+int3) ...
     *
     * 这样的话，即便是相同的一组数字，顺序不同的话，哈希值也是不同的。*/
    for (j = 0; j < 6; j++)
    {
        hash += integers[j];
        /* For the hashing step we use Tomas Wang's 64 bit integer hash. */
        hash = (~hash) + (hash << 21); // hash = (hash << 21) - hash - 1;
        hash = hash ^ (hash >> 24);
        hash = (hash + (hash << 3)) + (hash << 8); // hash * 265
        hash = hash ^ (hash >> 14);
        hash = (hash + (hash << 2)) + (hash << 4); // hash * 21
        hash = hash ^ (hash >> 28);
        hash = hash + (hash << 31);
    }
    return hash;
}

/* 创建一个非安全的迭代器 */
dictIterator *dictGetIterator(dict *d)
{
    dictIterator *iter = zmalloc(sizeof(*iter));

    iter->d = d;
    iter->table = 0;
    iter->index = -1;
    iter->safe = 0;
    iter->entry = NULL;
    iter->nextEntry = NULL;
    return iter;
}

/* 创建一个安全迭代器 */
dictIterator *dictGetSafeIterator(dict *d)
{
    dictIterator *i = dictGetIterator(d);

    // 标记安全迭代器
    i->safe = 1;
    return i;
}

/* 获取迭代器的下一个条目 */
dictEntry *dictNext(dictIterator *iter)
{
    while (1)
    {
        if (iter->entry == NULL)
        {
            // 哈希表的当前索引位置的entry为NULL（没有entry或者是最后一个entry）
            dictht *ht = &iter->d->ht[iter->table];
            // 当前哈希表为第0个table，说明没有在进行rehash
            if (iter->index == -1 && iter->table == 0)
            {
                if (iter->safe)
                    // 如果是安全迭代器，iterators加1
                    iter->d->iterators++;
                else
                    // 如果是非安全的迭代器，获取字典的指纹
                    iter->fingerprint = dictFingerprint(iter->d);
            }
            iter->index++;
            // 当前的table迭代完成
            if (iter->index >= (long)ht->size)
            {
                // 如果字典正在做rehash，那么跳到ht[1]继续迭代
                if (dictIsRehashing(iter->d) && iter->table == 0)
                {
                    iter->table++;
                    iter->index = 0;
                    ht = &iter->d->ht[1];
                }
                // 否则退出
                else
                {
                    break;
                }
            }
            iter->entry = ht->table[iter->index];
        }
        // 不是table的最后一个元素，那么获取下一个元素
        else
        {
            iter->entry = iter->nextEntry;
        }
        // 如果获取到的元素不为空就返回元素
        if (iter->entry)
        {
            iter->nextEntry = iter->entry->next;
            return iter->entry;
        }
    }
    return NULL;
}

/* 释放字典的迭代器 */
void dictReleaseIterator(dictIterator *iter)
{
    if (!(iter->index == -1 && iter->table == 0))
    {
        if (iter->safe)
            iter->d->iterators--;
        else
            assert(iter->fingerprint == dictFingerprint(iter->d));
    }
    zfree(iter);
}

/* 随机返回一个哈希表的条目 */
dictEntry *dictGetRandomKey(dict *d)
{
    dictEntry *he, *orighe;
    unsigned long h;
    int listlen, listele;

    // 元素为空，返回Null
    if (dictSize(d) == 0)
        return NULL;
    // 执行一次rehash步骤
    if (dictIsRehashing(d))
        _dictRehashStep(d);
    
    // 如果在在rehash，就要考虑2个哈希表的问题
    if (dictIsRehashing(d))
    {
        do
        {
            /*  因为小于rehashinx的条目都已经被移动到了ht[1]中，所以ht[0]中的空元素就不要返回了 */
            /* 首先我们要随机值，该值一定会大于rehashidx */
            h = d->rehashidx + (random() % (d->ht[0].size +
                                            d->ht[1].size -
                                            d->rehashidx));
            /* 确认选择的元素是在ht[0]还是ht[1] */
            he = (h >= d->ht[0].size) ? d->ht[1].table[h - d->ht[0].size] : d->ht[0].table[h];
        } while (he == NULL); // 既然哈希表里有元素，就不会返回一个空的条目
    }
    // 没有做rehash，只需要考虑一个哈希表
    else
    {
        do
        {
            h = random() & d->ht[0].sizemask;
            he = d->ht[0].table[h];
        } while (he == NULL);
    }


    /* 现在我们找到了一个非空的bucket，但是这个bucket是一个列表，
     * 我们还需要从这个列表中再随机找一个元素，*/
    listlen = 0;
    orighe = he;
    // 遍历元素确认列表的长度
    while (he)
    {
        he = he->next;
        listlen++;
    }
    // 获取随机的元素
    listele = random() % listlen;
    he = orighe;
    while (listele--)
        he = he->next;
    return he;
}

/* 
 * 对字典进行采样，在随机的位置获取一些数量的key并返回
 * 不能保证返回指定数量的key（字典的大小可能小于执行的count），也不能保证返回的key不重复。
 * 函数返回存储到‘des’的元素的数量，这个数量可能要比count小，因为字典的容量可能较小，
 * 或者在合理的次数内，没有获取到这么多的key */
unsigned int dictGetSomeKeys(dict *d, dictEntry **des, unsigned int count)
{
    unsigned long j;      /* 内部的哈希表的id, 0 或者 1. */
    unsigned long tables; /* 1个表还是2个table? */
    unsigned long stored = 0, maxsizemask;
    unsigned long maxsteps;

    // 如果字典大小小于指定的count，那么调整count为字典的大小
    if (dictSize(d) < count)
        count = dictSize(d);
    maxsteps = count * 10; // 最多随机count*10次

    for (j = 0; j < count; j++)
    {
        if (dictIsRehashing(d))
            _dictRehashStep(d);
        else
            break;
    }

    // 确认哈希表的个数
    tables = dictIsRehashing(d) ? 2 : 1;
    maxsizemask = d->ht[0].sizemask;
    if (tables > 1 && maxsizemask < d->ht[1].sizemask)
        maxsizemask = d->ht[1].sizemask;

    unsigned long i = random() & maxsizemask;
    unsigned long emptylen = 0; /* 遇到的空的bucket的数量 */
    // stored < count根据指定的count判断有没有达到目标数量，
    while (stored < count && maxsteps--)
    {
        for (j = 0; j < tables; j++)
        {
            /* 跳过rehash过程中ht[0]已经迁移的bucket */
            if (tables == 2 && j == 0 && i < (unsigned long)d->rehashidx)
            {
                if (i >= d->ht[1].size)
                    i = d->rehashidx;
                else
                    continue;
            }
            if (i >= d->ht[j].size)
                continue; /* Out of range for this table. */
            dictEntry *he = d->ht[j].table[i];

            /* 遇到太多的连续的空bucket，重新选一个随机的位置 */
            if (he == NULL)
            {
                emptylen++;
                if (emptylen >= 5 && emptylen > count)
                {
                    i = random() & maxsizemask;
                    emptylen = 0;
                }
            }
            else
            {
                emptylen = 0;
                while (he)
                {
                    /* 存储找到的bucket中的所有元素 */
                    *des = he;
                    des++;
                    he = he->next;
                    stored++;
                    if (stored == count)
                        return stored;
                }
            }
        }
        i = (i + 1) & maxsizemask;
    }
    return stored;
}

/* 这个函数返回随机的key，而且尽量保证返回的key有一个良好的分布，之所以这样是因为这个函数会
 * 从bucket的列表中随机选择一个key */
#define GETFAIR_NUM_ENTRIES 15
dictEntry *dictGetFairRandomKey(dict *d)
{
    dictEntry *entries[GETFAIR_NUM_ENTRIES];
    unsigned int count = dictGetSomeKeys(d, entries, GETFAIR_NUM_ENTRIES);
    /* 在极端的情况下，可能没有获取到bucket，那么只能调用dictGetRandomKey()函数来保证至少获得一个bucket */
    if (count == 0)
        return dictGetRandomKey(d);
    unsigned int idx = rand() % count;
    return entries[idx];
}

/* Function to reverse bits. Algorithm from:
 * http://graphics.stanford.edu/~seander/bithacks.html#ReverseParallel */
static unsigned long rev(unsigned long v)
{
    unsigned long s = CHAR_BIT * sizeof(v); // bit size; must be power of 2
    unsigned long mask = ~0UL;
    while ((s >>= 1) > 0)
    {
        mask ^= (mask << s);
        v = ((v >> s) & mask) | ((v << s) & ~mask);
    }
    return v;
}

/* 迭代字典中的元素
 * 迭代的工作方式如下：
 *
 * 1) Initially you call the function using a cursor (v) value of 0.
 * 2) The function performs one step of the iteration, and returns the
 *    new cursor value you must use in the next call.
 * 3) When the returned cursor is 0, the iteration is complete.
 *
 * The function guarantees all elements present in the
 * dictionary get returned between the start and end of the iteration.
 * However it is possible some elements get returned multiple times.
 *
 * For every element returned, the callback argument 'fn' is
 * called with 'privdata' as first argument and the dictionary entry
 * 'de' as second argument.
 *
 * HOW IT WORKS.
 *
 * The iteration algorithm was designed by Pieter Noordhuis.
 * The main idea is to increment a cursor starting from the higher order
 * bits. That is, instead of incrementing the cursor normally, the bits
 * of the cursor are reversed, then the cursor is incremented, and finally
 * the bits are reversed again.
 *
 * This strategy is needed because the hash table may be resized between
 * iteration calls.
 *
 * dict.c hash tables are always power of two in size, and they
 * use chaining, so the position of an element in a given table is given
 * by computing the bitwise AND between Hash(key) and SIZE-1
 * (where SIZE-1 is always the mask that is equivalent to taking the rest
 *  of the division between the Hash of the key and SIZE).
 *
 * For example if the current hash table size is 16, the mask is
 * (in binary) 1111. The position of a key in the hash table will always be
 * the last four bits of the hash output, and so forth.
 *
 * WHAT HAPPENS IF THE TABLE CHANGES IN SIZE?
 *
 * If the hash table grows, elements can go anywhere in one multiple of
 * the old bucket: for example let's say we already iterated with
 * a 4 bit cursor 1100 (the mask is 1111 because hash table size = 16).
 *
 * If the hash table will be resized to 64 elements, then the new mask will
 * be 111111. The new buckets you obtain by substituting in ??1100
 * with either 0 or 1 can be targeted only by keys we already visited
 * when scanning the bucket 1100 in the smaller hash table.
 *
 * By iterating the higher bits first, because of the inverted counter, the
 * cursor does not need to restart if the table size gets bigger. It will
 * continue iterating using cursors without '1100' at the end, and also
 * without any other combination of the final 4 bits already explored.
 *
 * Similarly when the table size shrinks over time, for example going from
 * 16 to 8, if a combination of the lower three bits (the mask for size 8
 * is 111) were already completely explored, it would not be visited again
 * because we are sure we tried, for example, both 0111 and 1111 (all the
 * variations of the higher bit) so we don't need to test it again.
 *
 * WAIT... YOU HAVE *TWO* TABLES DURING REHASHING!
 *
 * Yes, this is true, but we always iterate the smaller table first, then
 * we test all the expansions of the current cursor into the larger
 * table. For example if the current cursor is 101 and we also have a
 * larger table of size 16, we also test (0)101 and (1)101 inside the larger
 * table. This reduces the problem back to having only one table, where
 * the larger one, if it exists, is just an expansion of the smaller one.
 *
 * LIMITATIONS
 *
 * This iterator is completely stateless, and this is a huge advantage,
 * including no additional memory used.
 *
 * The disadvantages resulting from this design are:
 *
 * 1) It is possible we return elements more than once. However this is usually
 *    easy to deal with in the application level.
 * 2) The iterator must return multiple elements per call, as it needs to always
 *    return all the keys chained in a given bucket, and all the expansions, so
 *    we are sure we don't miss keys moving during rehashing.
 * 3) The reverse cursor is somewhat hard to understand at first, but this
 *    comment is supposed to help.
 */
unsigned long dictScan(dict *d,
                       unsigned long v,
                       dictScanFunction *fn,
                       dictScanBucketFunction *bucketfn,
                       void *privdata)
{
    dictht *t0, *t1;
    const dictEntry *de, *next;
    unsigned long m0, m1;

    if (dictSize(d) == 0)
        return 0;

    /* 存在安全迭代器意味着不能发生rehash操作 */
    d->iterators++;

    if (!dictIsRehashing(d))
    {
        t0 = &(d->ht[0]);
        m0 = t0->sizemask;

        /* Emit entries at cursor */
        if (bucketfn)
            bucketfn(privdata, &t0->table[v & m0]);
        de = t0->table[v & m0];
        while (de)
        {
            next = de->next;
            fn(privdata, de);
            de = next;
        }

        /* Set unmasked bits so incrementing the reversed cursor
         * operates on the masked bits */
        v |= ~m0;

        /* Increment the reverse cursor */
        v = rev(v);
        v++;
        v = rev(v);
    }
    else
    {
        t0 = &d->ht[0];
        t1 = &d->ht[1];

        /* Make sure t0 is the smaller and t1 is the bigger table */
        if (t0->size > t1->size)
        {
            t0 = &d->ht[1];
            t1 = &d->ht[0];
        }

        m0 = t0->sizemask;
        m1 = t1->sizemask;

        /* Emit entries at cursor */
        if (bucketfn)
            bucketfn(privdata, &t0->table[v & m0]);
        de = t0->table[v & m0];
        while (de)
        {
            next = de->next;
            fn(privdata, de);
            de = next;
        }

        /* Iterate over indices in larger table that are the expansion
         * of the index pointed to by the cursor in the smaller table */
        do
        {
            /* Emit entries at cursor */
            if (bucketfn)
                bucketfn(privdata, &t1->table[v & m1]);
            de = t1->table[v & m1];
            while (de)
            {
                next = de->next;
                fn(privdata, de);
                de = next;
            }

            /* Increment the reverse cursor not covered by the smaller mask.*/
            v |= ~m1;
            v = rev(v);
            v++;
            v = rev(v);

            /* Continue while bits covered by mask difference is non-zero */
        } while (v & (m0 ^ m1));
    }

    /* undo the ++ at the top */
    d->iterators--;

    return v;
}

/* ------------------------- private functions ------------------------------ */

/* 如果字典需要扩容，则扩之 */
static int _dictExpandIfNeeded(dict *d)
{
    /* 如果已经在做rehash了，返回 */
    if (dictIsRehashing(d))
        return DICT_OK;

    /* 如果哈希表为空，那么转换成初始化大小，4 */
    if (d->ht[0].size == 0)
        return dictExpand(d, DICT_HT_INITIAL_SIZE);

    /* 如果可以扩容的话，那么将哈希表扩容到至少能容纳目前容量的2的幂的大小的量 */
    if (d->ht[0].used >= d->ht[0].size &&
        (dict_can_resize ||
         d->ht[0].used / d->ht[0].size > dict_force_resize_ratio))
    {
        return dictExpand(d, d->ht[0].used * 2);
    }
    return DICT_OK;
}

/* 哈希表的容量是一定是2的幂 */
static unsigned long _dictNextPower(unsigned long size)
{
    unsigned long i = DICT_HT_INITIAL_SIZE;

    if (size >= LONG_MAX)
        return LONG_MAX + 1LU;
    while (1)
    {
        if (i >= size)
            return i;
        i *= 2;
    }
}

/* Returns the index of a free slot that can be populated with
 * a hash entry for the given 'key'.
 * If the key already exists, -1 is returned
 * and the optional output parameter may be filled.
 *
 * Note that if we are in the process of rehashing the hash table, the
 * index is always returned in the context of the second (new) hash table. */
static long _dictKeyIndex(dict *d, const void *key, uint64_t hash, dictEntry **existing)
{
    unsigned long idx, table;
    dictEntry *he;
    if (existing)
        *existing = NULL;

    /* Expand the hash table if needed */
    if (_dictExpandIfNeeded(d) == DICT_ERR)
        return -1;
    for (table = 0; table <= 1; table++)
    {
        idx = hash & d->ht[table].sizemask;
        /* Search if this slot does not already contain the given key */
        he = d->ht[table].table[idx];
        while (he)
        {
            if (key == he->key || dictCompareKeys(d, key, he->key))
            {
                if (existing)
                    *existing = he;
                return -1;
            }
            he = he->next;
        }
        if (!dictIsRehashing(d))
            break;
    }
    return idx;
}

// 清空字典
void dictEmpty(dict *d, void(callback)(void *))
{
    _dictClear(d, &d->ht[0], callback);
    _dictClear(d, &d->ht[1], callback);
    d->rehashidx = -1;
    d->iterators = 0;
}

void dictEnableResize(void)
{
    dict_can_resize = 1;
}

void dictDisableResize(void)
{
    dict_can_resize = 0;
}

uint64_t dictGetHash(dict *d, const void *key)
{
    return dictHashKey(d, key);
}

/* 使用指针和提前计算好的哈希值寻找字典条目的引用
 * oldkey是一个死指针，不应被访问。
 * 哈希值由dictGetHash()函数提供
 * 不执行字符串/key的比较
 * 如果找到了，返回字典条目的引用，否则返回Null */
dictEntry **dictFindEntryRefByPtrAndHash(dict *d, const void *oldptr, uint64_t hash)
{
    dictEntry *he, **heref;
    unsigned long idx, table;

    if (dictSize(d) == 0)
        return NULL; /* dict is empty */
    for (table = 0; table <= 1; table++)
    {
        idx = hash & d->ht[table].sizemask;
        heref = &d->ht[table].table[idx];
        he = *heref;
        while (he)
        {
            if (oldptr == he->key)
                return heref;
            heref = &he->next;
            he = *heref;
        }
        if (!dictIsRehashing(d))
            return NULL;
    }
    return NULL;
}

/* ------------------------------- Debugging ---------------------------------*/

#define DICT_STATS_VECTLEN 50
size_t _dictGetStatsHt(char *buf, size_t bufsize, dictht *ht, int tableid)
{
    unsigned long i, slots = 0, chainlen, maxchainlen = 0;
    unsigned long totchainlen = 0;
    unsigned long clvector[DICT_STATS_VECTLEN];
    size_t l = 0;

    if (ht->used == 0)
    {
        return snprintf(buf, bufsize,
                        "No stats available for empty dictionaries\n");
    }

    /* Compute stats. */
    for (i = 0; i < DICT_STATS_VECTLEN; i++)
        clvector[i] = 0;
    for (i = 0; i < ht->size; i++)
    {
        dictEntry *he;

        if (ht->table[i] == NULL)
        {
            clvector[0]++;
            continue;
        }
        slots++;
        /* For each hash entry on this slot... */
        chainlen = 0;
        he = ht->table[i];
        while (he)
        {
            chainlen++;
            he = he->next;
        }
        clvector[(chainlen < DICT_STATS_VECTLEN) ? chainlen : (DICT_STATS_VECTLEN - 1)]++;
        if (chainlen > maxchainlen)
            maxchainlen = chainlen;
        totchainlen += chainlen;
    }

    /* Generate human readable stats. */
    l += snprintf(buf + l, bufsize - l,
                  "Hash table %d stats (%s):\n"
                  " table size: %ld\n"
                  " number of elements: %ld\n"
                  " different slots: %ld\n"
                  " max chain length: %ld\n"
                  " avg chain length (counted): %.02f\n"
                  " avg chain length (computed): %.02f\n"
                  " Chain length distribution:\n",
                  tableid, (tableid == 0) ? "main hash table" : "rehashing target",
                  ht->size, ht->used, slots, maxchainlen,
                  (float)totchainlen / slots, (float)ht->used / slots);

    for (i = 0; i < DICT_STATS_VECTLEN - 1; i++)
    {
        if (clvector[i] == 0)
            continue;
        if (l >= bufsize)
            break;
        l += snprintf(buf + l, bufsize - l,
                      "   %s%ld: %ld (%.02f%%)\n",
                      (i == DICT_STATS_VECTLEN - 1) ? ">= " : "",
                      i, clvector[i], ((float)clvector[i] / ht->size) * 100);
    }

    /* Unlike snprintf(), teturn the number of characters actually written. */
    if (bufsize)
        buf[bufsize - 1] = '\0';
    return strlen(buf);
}

void dictGetStats(char *buf, size_t bufsize, dict *d)
{
    size_t l;
    char *orig_buf = buf;
    size_t orig_bufsize = bufsize;

    l = _dictGetStatsHt(buf, bufsize, &d->ht[0], 0);
    buf += l;
    bufsize -= l;
    if (dictIsRehashing(d) && bufsize > 0)
    {
        _dictGetStatsHt(buf, bufsize, &d->ht[1], 1);
    }
    /* Make sure there is a NULL term at the end. */
    if (orig_bufsize)
        orig_buf[orig_bufsize - 1] = '\0';
}

/* ------------------------------- Benchmark ---------------------------------*/

#ifdef DICT_BENCHMARK_MAIN

#include "sds.h"

uint64_t hashCallback(const void *key)
{
    return dictGenHashFunction((unsigned char *)key, sdslen((char *)key));
}

int compareCallback(void *privdata, const void *key1, const void *key2)
{
    int l1, l2;
    DICT_NOTUSED(privdata);

    l1 = sdslen((sds)key1);
    l2 = sdslen((sds)key2);
    if (l1 != l2)
        return 0;
    return memcmp(key1, key2, l1) == 0;
}

void freeCallback(void *privdata, void *val)
{
    DICT_NOTUSED(privdata);

    sdsfree(val);
}

dictType BenchmarkDictType = {
    hashCallback,
    NULL,
    NULL,
    compareCallback,
    freeCallback,
    NULL};

#define start_benchmark() start = timeInMilliseconds()
#define end_benchmark(msg)                                      \
    do                                                          \
    {                                                           \
        elapsed = timeInMilliseconds() - start;                 \
        printf(msg ": %ld items in %lld ms\n", count, elapsed); \
    } while (0);

/* dict-benchmark [count] */
int main(int argc, char **argv)
{
    long j;
    long long start, elapsed;
    dict *dict = dictCreate(&BenchmarkDictType, NULL);
    long count = 0;

    if (argc == 2)
    {
        count = strtol(argv[1], NULL, 10);
    }
    else
    {
        count = 5000000;
    }

    start_benchmark();
    for (j = 0; j < count; j++)
    {
        int retval = dictAdd(dict, sdsfromlonglong(j), (void *)j);
        assert(retval == DICT_OK);
    }
    end_benchmark("Inserting");
    assert((long)dictSize(dict) == count);

    /* Wait for rehashing. */
    while (dictIsRehashing(dict))
    {
        dictRehashMilliseconds(dict, 100);
    }

    start_benchmark();
    for (j = 0; j < count; j++)
    {
        sds key = sdsfromlonglong(j);
        dictEntry *de = dictFind(dict, key);
        assert(de != NULL);
        sdsfree(key);
    }
    end_benchmark("Linear access of existing elements");

    start_benchmark();
    for (j = 0; j < count; j++)
    {
        sds key = sdsfromlonglong(j);
        dictEntry *de = dictFind(dict, key);
        assert(de != NULL);
        sdsfree(key);
    }
    end_benchmark("Linear access of existing elements (2nd round)");

    start_benchmark();
    for (j = 0; j < count; j++)
    {
        sds key = sdsfromlonglong(rand() % count);
        dictEntry *de = dictFind(dict, key);
        assert(de != NULL);
        sdsfree(key);
    }
    end_benchmark("Random access of existing elements");

    start_benchmark();
    for (j = 0; j < count; j++)
    {
        sds key = sdsfromlonglong(rand() % count);
        key[0] = 'X';
        dictEntry *de = dictFind(dict, key);
        assert(de == NULL);
        sdsfree(key);
    }
    end_benchmark("Accessing missing");

    start_benchmark();
    for (j = 0; j < count; j++)
    {
        sds key = sdsfromlonglong(j);
        int retval = dictDelete(dict, key);
        assert(retval == DICT_OK);
        key[0] += 17; /* Change first number to letter. */
        retval = dictAdd(dict, key, (void *)j);
        assert(retval == DICT_OK);
    }
    end_benchmark("Removing and adding");
}
#endif
