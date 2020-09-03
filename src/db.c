#include "server.h"
#include "cluster.h"
#include "atomicvar.h"

#include <signal.h>
#include <ctype.h>

/*-----------------------------------------------------------------------------
 * C-level DB API
 *----------------------------------------------------------------------------*/

int keyIsExpired(redisDb *db, robj *key);

/* 当对象被访问时更新LFU
 * 首先，如果达到递减时间，则递减计数器。
 * 然后对数递增计数器，并更新访问时间。
 * Firstly, decrement the counter if the decrement time is reached.
 * Then logarithmically increment the counter, and update the access time. */
void updateLFU(robj *val) {
    unsigned long counter = LFUDecrAndReturn(val);
    counter = LFULogIncr(counter);
    val->lru = (LFUGetTimeInMinutes()<<8) | counter;
}

/* 低级key查找API，实际上不是直接从命令实现中调用的，
 * 这些命令实现应该依赖于lookupKeyRead()、lookupKeyWrite()和lookupKeyReadWithFlags()函数。*/
robj *lookupKey(redisDb *db, robj *key, int flags) {
    dictEntry *de = dictFind(db->dict,key->ptr);
    if (de) {
        // 找到对应的key，或者其对应的值
        robj *val = dictGetVal(de);

        /* 如果启动了LFU的maxmemory的策略，更新key的使用时间，如果有正在执行rdbsave或者aof等操作则不执行 */
        if (!hasActiveChildProcess() && !(flags & LOOKUP_NOTOUCH)){
            if (server.maxmemory_policy & MAXMEMORY_FLAG_LFU) {
                updateLFU(val);
            } else {
                val->lru = LRU_CLOCK();
            }
        }
        return val;
    } else {
        return NULL;
    }
}

/* 以读操作在指定的db中查找key，如果没找到则返回NULL
 * 调用该函数相应的副作用：
 * 1. 如果该key的TTL到了，则会过期
 * 2. key的最后访问时间会被更新
 * 3. 全局的hits/misses数据会被更新
 * 4. 如果key空间的通知被启用, "keymiss"通知会被触发
 *
 * This API should not be used when we write to the key after obtaining
 * the object linked to the key, but only for read only operations.
 *
 * Flags change the behavior of this command:
 *
 *  LOOKUP_NONE (or zero): no special flags are passed.
 *  LOOKUP_NOTOUCH: don't alter the last access time of the key.
 *
 * 注意: 如果key已经过期但还存在，仍然返回NULL */
robj *lookupKeyReadWithFlags(redisDb *db, robj *key, int flags) {
    robj *val;

    if (expireIfNeeded(db,key) == 1) {
        /* 如果是主节点，则key会被删除 */
        if (server.masterhost == NULL) {
            server.stat_keyspace_misses++;
            notifyKeyspaceEvent(NOTIFY_KEY_MISS, "keymiss", key, db->id);
            return NULL;
        }

        // 如果我们在从节点环境， expireIfNeeded()函数不会删除过期的键，它返回的仅仅是键是否被删除的逻辑值
        if (server.current_client &&
            server.current_client != server.master &&
            server.current_client->cmd &&
            server.current_client->cmd->flags & CMD_READONLY)
        {
            server.stat_keyspace_misses++;
            notifyKeyspaceEvent(NOTIFY_KEY_MISS, "keymiss", key, db->id);
            return NULL;
        }
    }
    val = lookupKey(db,key,flags);
    if (val == NULL) {
        server.stat_keyspace_misses++;
        notifyKeyspaceEvent(NOTIFY_KEY_MISS, "keymiss", key, db->id);
    }
    else
        server.stat_keyspace_hits++;
    return val;
}

robj *lookupKeyRead(redisDb *db, robj *key) {
    return lookupKeyReadWithFlags(db,key,LOOKUP_NONE);
}

/* 查找一个key从来做写操作，如果key的ttl到了，将其设置为过期
 * 如果找到了，则返回key对应的值得指针，否则返回null */
robj *lookupKeyWriteWithFlags(redisDb *db, robj *key, int flags) {
    expireIfNeeded(db,key);
    return lookupKey(db,key,flags);
}

robj *lookupKeyWrite(redisDb *db, robj *key) {
    return lookupKeyWriteWithFlags(db, key, LOOKUP_NONE);
}

robj *lookupKeyReadOrReply(client *c, robj *key, robj *reply) {
    robj *o = lookupKeyRead(c->db, key);
    if (!o) addReply(c,reply);
    return o;
}

robj *lookupKeyWriteOrReply(client *c, robj *key, robj *reply) {
    robj *o = lookupKeyWrite(c->db, key);
    if (!o) addReply(c,reply);
    return o;
}

/* 向db中增加key，由函数的调用者增加值的引用计数
 *
 * The program is aborted if the key already exists. */
void dbAdd(redisDb *db, robj *key, robj *val) {
    sds copy = sdsdup(key->ptr);
    int retval = dictAdd(db->dict, copy, val); // 将key-val添加到db的字典中

    serverAssertWithInfo(NULL,key,retval == DICT_OK);
    if (val->type == OBJ_LIST ||
        val->type == OBJ_ZSET ||
        val->type == OBJ_STREAM)
        signalKeyAsReady(db, key);
    // 如果开启了集群模式，将key添加到对应的slot中
    if (server.cluster_enabled) slotToKeyAdd(key->ptr);
}

/* dbAdd()函数特殊的版本，仅仅在从RDB文件加载数据时使用 */
int dbAddRDBLoad(redisDb *db, sds key, robj *val) {
    int retval = dictAdd(db->dict, key, val);
    if (retval != DICT_OK) return 0;
    if (server.cluster_enabled) slotToKeyAdd(key);
    return 1;
}

/* 覆盖一个已经存在的key的值，该函数不会修改已经存在的key的过期时间，如果key不存在，则终止 */
void dbOverwrite(redisDb *db, robj *key, robj *val) {
    dictEntry *de = dictFind(db->dict,key->ptr);

    serverAssertWithInfo(NULL,key,de != NULL);
    dictEntry auxentry = *de;
    robj *old = dictGetVal(de);
    if (server.maxmemory_policy & MAXMEMORY_FLAG_LFU) {
        val->lru = old->lru;
    }
    dictSetVal(db->dict, de, val);

    if (server.lazyfree_lazy_server_del) {
        freeObjAsync(old);
        dictSetVal(db->dict, &auxentry, NULL);
    }

    dictFreeVal(db->dict, &auxentry);
}

/* 高级别的set操作，该函数用于set一个key，不管key是否存在
 *
 * 1) 引用计数增加
 * 2) watcher被通知
 * 3) 过期时间被重置，除非keepttl参数设置为true */
void genericSetKey(client *c, redisDb *db, robj *key, robj *val, int keepttl, int signal) {
    if (lookupKeyWrite(db,key) == NULL) {
        dbAdd(db,key,val);
    } else {
        dbOverwrite(db,key,val);
    }
    incrRefCount(val);
    // 从过期字典中移除，永不过期
    if (!keepttl) removeExpire(db,key);
    if (signal) signalModifiedKey(c,db,key);
}

/* set key，并去除过期时间 */
void setKey(client *c, redisDb *db, robj *key, robj *val) {
    genericSetKey(c,db,key,val,0,1);
}

/* 返回某个key是否存在某个db中，LRU/LFU信息不更新. */
int dbExists(redisDb *db, robj *key) {
    return dictFind(db->dict,key->ptr) != NULL;
}

/* 返回一个随机的key，如果没有key则返回NULL
 *
 * 该函数保证返回的不是过期的key */
robj *dbRandomKey(redisDb *db) {
    dictEntry *de;
    int maxtries = 100;
    int allvolatile = dictSize(db->dict) == dictSize(db->expires);

    while(1) {
        sds key;
        robj *keyobj;

        de = dictGetFairRandomKey(db->dict);
        if (de == NULL) return NULL;

        key = dictGetKey(de);
        keyobj = createStringObject(key,sdslen(key));
        if (dictFind(db->expires,key)) {
            if (allvolatile && server.masterhost && --maxtries == 0) {
                /* 如果这个key在过期字典中，检查key是否过期，
                 * 如果过期且被删除，则释放该key对象，并且重新随机返回一个key */
                return keyobj;
            }
            if (expireIfNeeded(db,keyobj)) {
                decrRefCount(keyobj);
                continue; /* key已经过期，寻找下一个key */
            }
        }
        return keyobj;
    }
}

/* 删除一个键值对以及键的过期时间，返回1表示删除成功 */
int dbSyncDelete(redisDb *db, robj *key) {
    /* 键值对从过期字典中删除 */
    if (dictSize(db->expires) > 0) dictDelete(db->expires,key->ptr);
    // 从主字典中删除
    if (dictDelete(db->dict,key->ptr) == DICT_OK) {
        if (server.cluster_enabled) slotToKeyDel(key->ptr);
        return 1;
    } else {
        return 0;
    }
}

/* 根据lazyfree的配置情况选择是异步删除还是同步删除 */
int dbDelete(redisDb *db, robj *key) {
    return server.lazyfree_lazy_server_del ? dbAsyncDelete(db,key) :
                                             dbSyncDelete(db,key);
}

/* Prepare the string object stored at 'key' to be modified destructively
 * to implement commands like SETBIT or APPEND.
 *
 * An object is usually ready to be modified unless one of the two conditions
 * are true:
 *
 * 1) The object 'o' is shared (refcount > 1), we don't want to affect
 *    other users.
 * 2) The object encoding is not "RAW".
 *
 * If the object is found in one of the above conditions (or both) by the
 * function, an unshared / not-encoded copy of the string object is stored
 * at 'key' in the specified 'db'. Otherwise the object 'o' itself is
 * returned.
 *
 * USAGE:
 *
 * The object 'o' is what the caller already obtained by looking up 'key'
 * in 'db', the usage pattern looks like this:
 *
 * o = lookupKeyWrite(db,key);
 * if (checkType(c,o,OBJ_STRING)) return;
 * o = dbUnshareStringValue(db,key,o);
 *
 * At this point the caller is ready to modify the object, for example
 * using an sdscat() call to append some data, or anything else.
 * 解除key的值对象的共享，用于修改key的值 */
robj *dbUnshareStringValue(redisDb *db, robj *key, robj *o) {
    serverAssert(o->type == OBJ_STRING);
    if (o->refcount != 1 || o->encoding != OBJ_ENCODING_RAW) {
        robj *decoded = getDecodedObject(o);
        o = createRawStringObject(decoded->ptr, sdslen(decoded->ptr));
        decrRefCount(decoded);
        dbOverwrite(db,key,o);
    }
    return o;
}

/* 清空redis db中的key
 *
 * 如果dbnum参数为-1，则清空所有db的key，或者清空指定db中的key
 *
 * Flags are be EMPTYDB_NO_FLAGS if no special flags are specified or
 * 1. EMPTYDB_ASYNC 如果想在另一个线程中清内存
 * 2. EMPTYDB_BACKUP 如果只想清空由disklessLoadMakeBackups生成的备份字典
 *
 * 执行成功的情况下，返回清空的key的数量，如果dbnum不存在则返回-1，errno被设置为EINVAL */
long long emptyDbGeneric(redisDb *dbarray, int dbnum, int flags, void(callback)(void*)) {
    int async = (flags & EMPTYDB_ASYNC);
    int backup = (flags & EMPTYDB_BACKUP); /* 只清空内存，不做其他事 */
    RedisModuleFlushInfoV1 fi = {REDISMODULE_FLUSHINFO_VERSION,!async,dbnum};
    long long removed = 0;
    // dbnum索引越界
    if (dbnum < -1 || dbnum >= server.dbnum) {
        errno = EINVAL;
        return -1;
    }

    /* Pre-flush actions */
    if (!backup) {
        /* Fire the flushdb modules event. */
        moduleFireServerEvent(REDISMODULE_EVENT_FLUSHDB,
                              REDISMODULE_SUBEVENT_FLUSHDB_START,
                              &fi);
        signalFlushedDb(dbnum);
    }

    int startdb, enddb;
    // 是否为flushall
    if (dbnum == -1) {
        startdb = 0;
        enddb = server.dbnum-1;
    } else {
        startdb = enddb = dbnum;
    }

    for (int j = startdb; j <= enddb; j++) {
        // 计算清空的key的数量
        removed += dictSize(dbarray[j].dict);
        if (async) {
            // 异步清空db，实际上的创建新的字典，异步释放老字典
            emptyDbAsync(&dbarray[j]);
        } else {
            // 同步删除
            dictEmpty(dbarray[j].dict,callback);
            dictEmpty(dbarray[j].expires,callback);
        }
    }

    /* Post-flush actions */
    if (!backup) {
        if (server.cluster_enabled) {
            if (async) {
                // 异步
                slotToKeyFlushAsync();
            } else {
                // 同步
                slotToKeyFlush();
            }
        }
        if (dbnum == -1) flushSlaveKeysWithExpireList();

        /* Also fire the end event. Note that this event will fire almost
         * immediately after the start event if the flush is asynchronous. */
        moduleFireServerEvent(REDISMODULE_EVENT_FLUSHDB,
                              REDISMODULE_SUBEVENT_FLUSHDB_END,
                              &fi);
    }

    return removed;
}

long long emptyDb(int dbnum, int flags, void(callback)(void*)) {
    return emptyDbGeneric(server.db, dbnum, flags, callback);
}

// 切换数据库
int selectDb(client *c, int id) {
    // 索引越界
    if (id < 0 || id >= server.dbnum)
        return C_ERR;
    c->db = &server.db[id];
    return C_OK;
}

// 返回所有db中的key的数量总和
long long dbTotalServerKeyCount() {
    long long total = 0;
    int j;
    for (j = 0; j < server.dbnum; j++) {
        total += dictSize(server.db[j].dict);
    }
    return total;
}

/*-----------------------------------------------------------------------------
 * Hooks for key space changes.
 *
 * 钩子函数
 * 每当数据库中的一个key被修改，调用signalModifiedKey()函数
 * Every time a key in the database is modified the function
 * signalModifiedKey() is called.
 *
 * Every time a DB is flushed the function signalFlushDb() is called.
 *----------------------------------------------------------------------------*/

/* Note that the 'c' argument may be NULL if the key was modified out of
 * a context of a client. */
void signalModifiedKey(client *c, redisDb *db, robj *key) {
    touchWatchedKey(db,key);
    trackingInvalidateKey(c,key);
}

// 清空db通知函数
void signalFlushedDb(int dbid) {
    touchWatchedKeysOnFlush(dbid);
    trackingInvalidateKeysOnFlush(dbid);
}

/*-----------------------------------------------------------------------------
 * Type agnostic commands operating on the key space
 *----------------------------------------------------------------------------*/

/* 解析flush命令的参数 */
int getFlushCommandFlags(client *c, int *flags) {
    /* Parse the optional ASYNC option. */
    if (c->argc > 1) {
        // 如果flush命令有参数，那么只能是async
        if (c->argc > 2 || strcasecmp(c->argv[1]->ptr,"async")) {
            addReply(c,shared.syntaxerr);
            return C_ERR;
        }
        *flags = EMPTYDB_ASYNC;
    } else {
        *flags = EMPTYDB_NO_FLAGS;
    }
    return C_OK;
}

/* 清空整个服务的数据. */
void flushAllDataAndResetRDB(int flags) {
    server.dirty += emptyDb(-1,flags,NULL);
    if (server.rdb_child_pid != -1) killRDBChild();
    if (server.saveparamslen > 0) {
        /* Normally rdbSave() will reset dirty, but we don't want this here
         * as otherwise FLUSHALL will not be replicated nor put into the AOF. */
        int saved_dirty = server.dirty;
        rdbSaveInfo rsi, *rsiptr;
        rsiptr = rdbPopulateSaveInfo(&rsi);
        rdbSave(server.rdb_filename,rsiptr);
        server.dirty = saved_dirty;
    }
    server.dirty++;
#if defined(USE_JEMALLOC)
    /* jemalloc 5 doesn't release pages back to the OS when there's no traffic.
     * for large databases, flushdb blocks for long anyway, so a bit more won't
     * harm and this way the flush and purge will be synchroneus. */
    if (!(flags & EMPTYDB_ASYNC))
        jemalloc_purge();
#endif
}

/* FLUSHDB [ASYNC]
 *
 * 清空选择的db的数据 */
void flushdbCommand(client *c) {
    int flags;

    if (getFlushCommandFlags(c,&flags) == C_ERR) return;
    server.dirty += emptyDb(c->db->id,flags,NULL);
    addReply(c,shared.ok);
#if defined(USE_JEMALLOC)
    /* jemalloc 5 doesn't release pages back to the OS when there's no traffic.
     * for large databases, flushdb blocks for long anyway, so a bit more won't
     * harm and this way the flush and purge will be synchroneus. */
    if (!(flags & EMPTYDB_ASYNC))
        jemalloc_purge();
#endif
}

/* FLUSHALL [ASYNC]
 *
 * 清空所有db的数据 */
void flushallCommand(client *c) {
    int flags;
    if (getFlushCommandFlags(c,&flags) == C_ERR) return;
    flushAllDataAndResetRDB(flags);
    addReply(c,shared.ok);
}

/* 该命令实现 DEL 和 LAZYDEL. */
void delGenericCommand(client *c, int lazy) {
    int numdel = 0, j;

    for (j = 1; j < c->argc; j++) {
        expireIfNeeded(c->db,c->argv[j]);
        int deleted  = lazy ? dbAsyncDelete(c->db,c->argv[j]) :
                              dbSyncDelete(c->db,c->argv[j]);
        if (deleted) {
            signalModifiedKey(c,c->db,c->argv[j]);
            notifyKeyspaceEvent(NOTIFY_GENERIC,
                "del",c->argv[j],c->db->id);
            server.dirty++;
            numdel++;
        }
    }
    addReplyLongLong(c,numdel);
}

void delCommand(client *c) {
    delGenericCommand(c,server.lazyfree_lazy_user_del);
}

// 异步删除命令
void unlinkCommand(client *c) {
    delGenericCommand(c,1);
}

/* EXISTS key1 key2 ... key_N.
 * 返回存在的key的数量 */
void existsCommand(client *c) {
    long long count = 0;
    int j;

    for (j = 1; j < c->argc; j++) {
        if (lookupKeyRead(c->db,c->argv[j])) count++;
    }
    addReplyLongLong(c,count);
}

// SELECT命令
void selectCommand(client *c) {
    long id;

    if (getLongFromObjectOrReply(c, c->argv[1], &id,
        "invalid DB index") != C_OK)
        return;

    // 集群模式下不允许执行SELECT命令
    if (server.cluster_enabled && id != 0) {
        addReplyError(c,"SELECT is not allowed in cluster mode");
        return;
    }
    if (selectDb(c,id) == C_ERR) {
        addReplyError(c,"DB index is out of range");
    } else {
        addReply(c,shared.ok);
    }
}

// randomkey命令
void randomkeyCommand(client *c) {
    robj *key;

    if ((key = dbRandomKey(c->db)) == NULL) {
        addReplyNull(c);
        return;
    }

    addReplyBulk(c,key);
    decrRefCount(key);
}

// keys命令
void keysCommand(client *c) {
    dictIterator *di;
    dictEntry *de;
    sds pattern = c->argv[1]->ptr;
    int plen = sdslen(pattern), allkeys;
    unsigned long numkeys = 0;
    void *replylen = addReplyDeferredLen(c);

    di = dictGetSafeIterator(c->db->dict);
    allkeys = (pattern[0] == '*' && plen == 1);
    while((de = dictNext(di)) != NULL) {
        sds key = dictGetKey(de);
        robj *keyobj;

        if (allkeys || stringmatchlen(pattern,plen,key,sdslen(key),0)) {
            keyobj = createStringObject(key,sdslen(key));
            if (!keyIsExpired(c->db,keyobj)) {
                addReplyBulk(c,keyobj);
                numkeys++;
            }
            decrRefCount(keyobj);
        }
    }
    dictReleaseIterator(di);
    setDeferredArrayLen(c,replylen,numkeys);
}

/* scanCallback()函数被scanGenericCommand()函数调用，为了保存被字典迭代器返回到列表中的元素 */
void scanCallback(void *privdata, const dictEntry *de) {
    void **pd = (void**) privdata;
    list *keys = pd[0];
    robj *o = pd[1];
    robj *key, *val = NULL;

    if (o == NULL) {
        sds sdskey = dictGetKey(de);
        key = createStringObject(sdskey, sdslen(sdskey));
    } else if (o->type == OBJ_SET) {
        sds keysds = dictGetKey(de);
        key = createStringObject(keysds,sdslen(keysds));
    } else if (o->type == OBJ_HASH) {
        sds sdskey = dictGetKey(de);
        sds sdsval = dictGetVal(de);
        key = createStringObject(sdskey,sdslen(sdskey));
        val = createStringObject(sdsval,sdslen(sdsval));
    } else if (o->type == OBJ_ZSET) {
        sds sdskey = dictGetKey(de);
        key = createStringObject(sdskey,sdslen(sdskey));
        val = createStringObjectFromLongDouble(*(double*)dictGetVal(de),0);
    } else {
        serverPanic("Type not handled in SCAN callback.");
    }

    listAddNodeTail(keys, key);
    if (val) listAddNodeTail(keys, val);
}

/* Try to parse a SCAN cursor stored at object 'o':
 * if the cursor is valid, store it as unsigned integer into *cursor and
 * returns C_OK. Otherwise return C_ERR and send an error to the
 * client. 
 * 获取scan命令的游标，尝试取解析一个保存在o中的游标，如果游标合法，保存到cursor中否则返回C_ER */
int parseScanCursorOrReply(client *c, robj *o, unsigned long *cursor) {
    char *eptr;

    /* Use strtoul() because we need an *unsigned* long, so
     * getLongLongFromObject() does not cover the whole cursor space. */
    errno = 0;
    *cursor = strtoul(o->ptr, &eptr, 10);
    if (isspace(((char*)o->ptr)[0]) || eptr[0] != '\0' || errno == ERANGE)
    {
        addReplyError(c, "invalid cursor");
        return C_ERR;
    }
    return C_OK;
}

/* This command implements SCAN, HSCAN and SSCAN commands.
 * If object 'o' is passed, then it must be a Hash, Set or Zset object, otherwise
 * if 'o' is NULL the command will operate on the dictionary associated with
 * the current database.
 *
 * When 'o' is not NULL the function assumes that the first argument in
 * the client arguments vector is a key so it skips it before iterating
 * in order to parse options.
 *
 * In the case of a Hash object the function returns both the field and value
 * of every element on the Hash. 
 * o对象必须是哈希对象或集合对象，否则命令将操作当前数据库
 * 如果o不是NULL，那么说明他是一个哈希或集合对象，函数将跳过这些键对象，对参数进行分析
 * 如果是哈希对象，返回返回的是键值对 */
void scanGenericCommand(client *c, robj *o, unsigned long cursor) {
    int i, j;
    list *keys = listCreate();
    listNode *node, *nextnode;
    long count = 10;
    sds pat = NULL;
    sds typename = NULL;
    int patlen = 0, use_pattern = 0;
    dict *ht;

    /* Object must be NULL (to iterate keys names), or the type of the object
     * must be Set, Sorted Set, or Hash. */
    serverAssert(o == NULL || o->type == OBJ_SET || o->type == OBJ_HASH ||
                o->type == OBJ_ZSET);

    /* Set i to the first option argument. The previous one is the cursor. */
    i = (o == NULL) ? 2 : 3; /* Skip the key argument if needed. */

    /* Step 1: Parse options. */
    while (i < c->argc) {
        j = c->argc - i;
        if (!strcasecmp(c->argv[i]->ptr, "count") && j >= 2) {
            if (getLongFromObjectOrReply(c, c->argv[i+1], &count, NULL)
                != C_OK)
            {
                goto cleanup;
            }

            if (count < 1) {
                addReply(c,shared.syntaxerr);
                goto cleanup;
            }

            i += 2;
        } else if (!strcasecmp(c->argv[i]->ptr, "match") && j >= 2) {
            pat = c->argv[i+1]->ptr;
            patlen = sdslen(pat);

            /* The pattern always matches if it is exactly "*", so it is
             * equivalent to disabling it. */
            use_pattern = !(pat[0] == '*' && patlen == 1);

            i += 2;
        } else if (!strcasecmp(c->argv[i]->ptr, "type") && o == NULL && j >= 2) {
            /* SCAN for a particular type only applies to the db dict */
            typename = c->argv[i+1]->ptr;
            i+= 2;
        } else {
            addReply(c,shared.syntaxerr);
            goto cleanup;
        }
    }

    /* Step 2: Iterate the collection.
     *
     * Note that if the object is encoded with a ziplist, intset, or any other
     * representation that is not a hash table, we are sure that it is also
     * composed of a small number of elements. So to avoid taking state we
     * just return everything inside the object in a single call, setting the
     * cursor to zero to signal the end of the iteration. */

    /* Handle the case of a hash table. */
    ht = NULL;
    if (o == NULL) {
        ht = c->db->dict;
    } else if (o->type == OBJ_SET && o->encoding == OBJ_ENCODING_HT) {
        ht = o->ptr;
    } else if (o->type == OBJ_HASH && o->encoding == OBJ_ENCODING_HT) {
        ht = o->ptr;
        count *= 2; /* We return key / value for this type. */
    } else if (o->type == OBJ_ZSET && o->encoding == OBJ_ENCODING_SKIPLIST) {
        zset *zs = o->ptr;
        ht = zs->dict;
        count *= 2; /* We return key / value for this type. */
    }

    if (ht) {
        void *privdata[2];
        /* We set the max number of iterations to ten times the specified
         * COUNT, so if the hash table is in a pathological state (very
         * sparsely populated) we avoid to block too much time at the cost
         * of returning no or very few elements. */
        long maxiterations = count*10;

        /* We pass two pointers to the callback: the list to which it will
         * add new elements, and the object containing the dictionary so that
         * it is possible to fetch more data in a type-dependent way. */
        privdata[0] = keys;
        privdata[1] = o;
        do {
            cursor = dictScan(ht, cursor, scanCallback, NULL, privdata);
        } while (cursor &&
              maxiterations-- &&
              listLength(keys) < (unsigned long)count);
    } else if (o->type == OBJ_SET) {
        int pos = 0;
        int64_t ll;

        while(intsetGet(o->ptr,pos++,&ll))
            listAddNodeTail(keys,createStringObjectFromLongLong(ll));
        cursor = 0;
    } else if (o->type == OBJ_HASH || o->type == OBJ_ZSET) {
        unsigned char *p = ziplistIndex(o->ptr,0);
        unsigned char *vstr;
        unsigned int vlen;
        long long vll;

        while(p) {
            ziplistGet(p,&vstr,&vlen,&vll);
            listAddNodeTail(keys,
                (vstr != NULL) ? createStringObject((char*)vstr,vlen) :
                                 createStringObjectFromLongLong(vll));
            p = ziplistNext(o->ptr,p);
        }
        cursor = 0;
    } else {
        serverPanic("Not handled encoding in SCAN.");
    }

    /* Step 3: Filter elements. */
    node = listFirst(keys);
    while (node) {
        robj *kobj = listNodeValue(node);
        nextnode = listNextNode(node);
        int filter = 0;

        /* Filter element if it does not match the pattern. */
        if (!filter && use_pattern) {
            if (sdsEncodedObject(kobj)) {
                if (!stringmatchlen(pat, patlen, kobj->ptr, sdslen(kobj->ptr), 0))
                    filter = 1;
            } else {
                char buf[LONG_STR_SIZE];
                int len;

                serverAssert(kobj->encoding == OBJ_ENCODING_INT);
                len = ll2string(buf,sizeof(buf),(long)kobj->ptr);
                if (!stringmatchlen(pat, patlen, buf, len, 0)) filter = 1;
            }
        }

        /* Filter an element if it isn't the type we want. */
        if (!filter && o == NULL && typename){
            robj* typecheck = lookupKeyReadWithFlags(c->db, kobj, LOOKUP_NOTOUCH);
            char* type = getObjectTypeName(typecheck);
            if (strcasecmp((char*) typename, type)) filter = 1;
        }

        /* Filter element if it is an expired key. */
        if (!filter && o == NULL && expireIfNeeded(c->db, kobj)) filter = 1;

        /* Remove the element and its associted value if needed. */
        if (filter) {
            decrRefCount(kobj);
            listDelNode(keys, node);
        }

        /* If this is a hash or a sorted set, we have a flat list of
         * key-value elements, so if this element was filtered, remove the
         * value, or skip it if it was not filtered: we only match keys. */
        if (o && (o->type == OBJ_ZSET || o->type == OBJ_HASH)) {
            node = nextnode;
            nextnode = listNextNode(node);
            if (filter) {
                kobj = listNodeValue(node);
                decrRefCount(kobj);
                listDelNode(keys, node);
            }
        }
        node = nextnode;
    }

    /* Step 4: Reply to the client. */
    addReplyArrayLen(c, 2);Ò
    addReplyBulkLongLong(c,cursor);

    addReplyArrayLen(c, listLength(keys));
    while ((node = listFirst(keys)) != NULL) {
        robj *kobj = listNodeValue(node);
        addReplyBulk(c, kobj);
        decrRefCount(kobj);
        listDelNode(keys, node);
    }

cleanup:
    listSetFreeMethod(keys,decrRefCountVoid);
    listRelease(keys);
}

/* SCAN命令完全依赖于 scanGenericCommand. */
void scanCommand(client *c) {
    unsigned long cursor;
    if (parseScanCursorOrReply(c,c->argv[1],&cursor) == C_ERR) return;
    scanGenericCommand(c,NULL,cursor);
}

// DBSIZE命令
void dbsizeCommand(client *c) {
    addReplyLongLong(c,dictSize(c->db->dict));
}

// LASTSAVE命令
void lastsaveCommand(client *c) {
    addReplyLongLong(c,server.lastsave);
}

// 获取对象的类型名称
char* getObjectTypeName(robj *o) {
    char* type;
    if (o == NULL) {
        type = "none";
    } else {
        switch(o->type) {
        case OBJ_STRING: type = "string"; break;
        case OBJ_LIST: type = "list"; break;
        case OBJ_SET: type = "set"; break;
        case OBJ_ZSET: type = "zset"; break;
        case OBJ_HASH: type = "hash"; break;
        case OBJ_STREAM: type = "stream"; break;
        case OBJ_MODULE: {
            moduleValue *mv = o->ptr;
            type = mv->type->name;
        }; break;
        default: type = "unknown"; break;
        }
    }
    return type;
}

// TYPE命令
void typeCommand(client *c) {
    robj *o;
    o = lookupKeyReadWithFlags(c->db,c->argv[1],LOOKUP_NOTOUCH);
    addReplyStatus(c, getObjectTypeName(o));
}

// SHUTDOWN命令
void shutdownCommand(client *c) {
    int flags = 0;

    if (c->argc > 2) {
        // 参数不能超过2个
        addReply(c,shared.syntaxerr);
        return;
    } else if (c->argc == 2) {
        // SHUTDOWN NOSAVE
        if (!strcasecmp(c->argv[1]->ptr,"nosave")) {
            flags |= SHUTDOWN_NOSAVE;
        // SHUTDOWN SAVE
        } else if (!strcasecmp(c->argv[1]->ptr,"save")) {
            flags |= SHUTDOWN_SAVE;
        } else {
            // 只支持SAVE和NOSAVE 2个参数
            addReply(c,shared.syntaxerr);
            return;
        }
    }
    /* When SHUTDOWN is called while the server is loading a dataset in
     * memory we need to make sure no attempt is performed to save
     * the dataset on shutdown (otherwise it could overwrite the current DB
     * with half-read data).
     *
     * Also when in Sentinel mode clear the SAVE flag and force NOSAVE. */
    if (server.loading || server.sentinel_mode)
        flags = (flags & ~SHUTDOWN_SAVE) | SHUTDOWN_NOSAVE;
    if (prepareForShutdown(flags) == C_OK) exit(0);
    addReplyError(c,"Errors trying to SHUTDOWN. Check logs.");
}

// RENAME命令
void renameGenericCommand(client *c, int nx) {
    robj *o;
    long long expire;
    int samekey = 0;

    /* 如果源和目标是同一个key，不做任何操作
     * if the key exists, however we still return an error on unexisting key. */
    if (sdscmp(c->argv[1]->ptr,c->argv[2]->ptr) == 0) samekey = 1;

    if ((o = lookupKeyWriteOrReply(c,c->argv[1],shared.nokeyerr)) == NULL)
        return;
    // 同一个key
    if (samekey) {
        addReply(c,nx ? shared.czero : shared.ok);
        return;
    }

    incrRefCount(o);
    expire = getExpire(c->db,c->argv[1]);
    if (lookupKeyWrite(c->db,c->argv[2]) != NULL) {
        if (nx) {
            decrRefCount(o);
            addReply(c,shared.czero);
            return;
        }
        /* 创建新的key之前删除老key*/
        dbDelete(c->db,c->argv[2]);
    }
    dbAdd(c->db,c->argv[2],o);
    // 设置同意的过期时间
    if (expire != -1) setExpire(c,c->db,c->argv[2],expire);
    dbDelete(c->db,c->argv[1]);
    signalModifiedKey(c,c->db,c->argv[1]);
    signalModifiedKey(c,c->db,c->argv[2]);
    notifyKeyspaceEvent(NOTIFY_GENERIC,"rename_from",
        c->argv[1],c->db->id);
    notifyKeyspaceEvent(NOTIFY_GENERIC,"rename_to",
        c->argv[2],c->db->id);
    server.dirty++;
    addReply(c,nx ? shared.cone : shared.ok);
}

// RENAME命令
void renameCommand(client *c) {
    renameGenericCommand(c,0);
}
// RENAMENX命令，修改成功时，返回1 。 如果key已经存在，返回 0 。
void renamenxCommand(client *c) {
    renameGenericCommand(c,1);
}

// MOVE命令，将key从一个db移动到另一个db
void moveCommand(client *c) {
    robj *o;
    redisDb *src, *dst;
    int srcid;
    long long dbid, expire;

    if (server.cluster_enabled) {
        addReplyError(c,"MOVE is not allowed in cluster mode");
        return;
    }

    /* 获取源和目的DB的指针 */
    src = c->db;
    srcid = c->db->id;

    if (getLongLongFromObject(c->argv[2],&dbid) == C_ERR ||
        dbid < INT_MIN || dbid > INT_MAX ||
        selectDb(c,dbid) == C_ERR)
    {
        addReply(c,shared.outofrangeerr);
        return;
    }
    dst = c->db;
    selectDb(c,srcid); /* Back to the source DB */

    /* db相同，返回错误 */
    if (src == dst) {
        addReply(c,shared.sameobjecterr);
        return;
    }

    /* 如果key不存在，返回错误 */
    o = lookupKeyWrite(c->db,c->argv[1]);
    if (!o) {
        addReply(c,shared.czero);
        return;
    }
    expire = getExpire(c->db,c->argv[1]);

    /* 如果key在目标db中已经存在，返回0 */
    if (lookupKeyWrite(dst,c->argv[1]) != NULL) {
        addReply(c,shared.czero);
        return;
    }
    // 目标db中添加该key，并设置过期时间
    dbAdd(dst,c->argv[1],o);
    if (expire != -1) setExpire(c,dst,c->argv[1],expire);
    incrRefCount(o);

    /* key已经移动，从源db中删除 */
    dbDelete(src,c->argv[1]);
    signalModifiedKey(c,src,c->argv[1]);
    signalModifiedKey(c,dst,c->argv[1]);
    notifyKeyspaceEvent(NOTIFY_GENERIC,
                "move_from",c->argv[1],src->id);
    notifyKeyspaceEvent(NOTIFY_GENERIC,
                "move_to",c->argv[1],dst->id);

    server.dirty++;
    addReply(c,shared.cone);
}

/* Helper function for dbSwapDatabases(): scans the list of keys that have
 * one or more blocked clients for B[LR]POP or other blocking commands
 * and signal the keys as ready if they are of the right type. See the comment
 * where the function is used for more info. */
void scanDatabaseForReadyLists(redisDb *db) {
    dictEntry *de;
    dictIterator *di = dictGetSafeIterator(db->blocking_keys);
    while((de = dictNext(di)) != NULL) {
        robj *key = dictGetKey(de);
        robj *value = lookupKey(db,key,LOOKUP_NOTOUCH);
        if (value && (value->type == OBJ_LIST ||
                      value->type == OBJ_STREAM ||
                      value->type == OBJ_ZSET))
            signalKeyAsReady(db, key);
    }
    dictReleaseIterator(di);
}

/* 交换DB*/
int dbSwapDatabases(long id1, long id2) {
    if (id1 < 0 || id1 >= server.dbnum ||
        id2 < 0 || id2 >= server.dbnum) return C_ERR;
    if (id1 == id2) return C_OK;
    redisDb aux = server.db[id1];
    redisDb *db1 = &server.db[id1], *db2 = &server.db[id2];

    /* Swap hash tables. Note that we don't swap blocking_keys,
     * ready_keys and watched_keys, since we want clients to
     * remain in the same DB they were. */
    db1->dict = db2->dict;
    db1->expires = db2->expires;
    db1->avg_ttl = db2->avg_ttl;
    db1->expires_cursor = db2->expires_cursor;

    db2->dict = aux.dict;
    db2->expires = aux.expires;
    db2->avg_ttl = aux.avg_ttl;
    db2->expires_cursor = aux.expires_cursor;

    /* Now we need to handle clients blocked on lists: as an effect
     * of swapping the two DBs, a client that was waiting for list
     * X in a given DB, may now actually be unblocked if X happens
     * to exist in the new version of the DB, after the swap.
     *
     * However normally we only do this check for efficiency reasons
     * in dbAdd() when a list is created. So here we need to rescan
     * the list of clients blocked on lists and signal lists as ready
     * if needed. */
    scanDatabaseForReadyLists(db1);
    scanDatabaseForReadyLists(db2);
    return C_OK;
}

/* SWAPDB db1 db2 */
void swapdbCommand(client *c) {
    long id1, id2;

    /* 集群模式下不允许交换，因为只有db0 */
    if (server.cluster_enabled) {
        addReplyError(c,"SWAPDB is not allowed in cluster mode");
        return;
    }

    /* 获取2个db的索引. */
    if (getLongFromObjectOrReply(c, c->argv[1], &id1,
        "invalid first DB index") != C_OK)
        return;

    if (getLongFromObjectOrReply(c, c->argv[2], &id2,
        "invalid second DB index") != C_OK)
        return;

    /* 交换 */
    if (dbSwapDatabases(id1,id2) == C_ERR) {
        addReplyError(c,"DB index is out of range");
        return;
    } else {
        server.dirty++;
        addReply(c,shared.ok);
    }
}

/*-----------------------------------------------------------------------------
 * Expires API
 *----------------------------------------------------------------------------*/

// 将key从过期字典中移除，永不过期
int removeExpire(redisDb *db, robj *key) {
    serverAssertWithInfo(NULL,key,dictFind(db->dict,key->ptr) != NULL);
    return dictDelete(db->expires,key->ptr) == DICT_OK;
}

/* 为key设置过期时间 */
void setExpire(client *c, redisDb *db, robj *key, long long when) {
    dictEntry *kde, *de;

    /* Reuse the sds from the main dict in the expire dict */
    kde = dictFind(db->dict,key->ptr);
    serverAssertWithInfo(NULL,key,kde != NULL);
    de = dictAddOrFind(db->expires,dictGetKey(kde));
    dictSetSignedIntegerVal(de,when);

    int writable_slave = server.masterhost && server.repl_slave_ro == 0;
    if (c && writable_slave && !(c->flags & CLIENT_MASTER))
        rememberSlaveKeyWithExpire(db,key);
}

/* 返回key的过期时间，如果没有永不过期则返回-1 */
long long getExpire(redisDb *db, robj *key) {
    dictEntry *de;

    /* db中不存在有过期时间的key，或者在过期表中没有找到对应的key，则返回-1 */
    if (dictSize(db->expires) == 0 ||
       (de = dictFind(db->expires,key->ptr)) == NULL) return -1;

    serverAssertWithInfo(NULL,key,dictFind(db->dict,key->ptr) != NULL);
    return dictGetSignedIntegerVal(de);
}

/* 传播过期信息到slave和aof文件中
 * 如果key在master中过期，则像slave和aof文件传播del命令 */
void propagateExpire(redisDb *db, robj *key, int lazy) {
    robj *argv[2];

    argv[0] = lazy ? shared.unlink : shared.del;
    argv[1] = key;
    incrRefCount(argv[0]);
    incrRefCount(argv[1]);

    if (server.aof_state != AOF_OFF)
        feedAppendOnlyFile(server.delCommand,db->id,argv,2);
    replicationFeedSlaves(server.slaves,db->id,argv,2);

    decrRefCount(argv[0]);
    decrRefCount(argv[1]);
}

/* 检查key是否已经过期 */
int keyIsExpired(redisDb *db, robj *key) {
    mstime_t when = getExpire(db,key);
    mstime_t now;

    if (when < 0) return 0; /* when为-1，该key永不过期 */

    /* 如果正在加载数据，则不作过期处理 */
    if (server.loading) return 0;

    if (server.lua_caller) {
        now = server.lua_time_start;
    }
 
    else if (server.fixed_time_expire > 0) {
        now = server.mstime;
    }
    else {
        now = mstime();
    }

    return now > when;
}

/* This function is called when we are going to perform some operation
 * in a given key, but such key may be already logically expired even if
 * it still exists in the database. The main way this function is called
 * is via lookupKey*() family of functions.
 *
 * The behavior of the function depends on the replication role of the
 * instance, because slave instances do not expire keys, they wait
 * for DELs from the master for consistency matters. However even
 * slaves will try to have a coherent return value for the function,
 * so that read commands executed in the slave side will be able to
 * behave like if the key is expired even if still present (because the
 * master has yet to propagate the DEL).
 *
 * In masters as a side effect of finding a key which is expired, such
 * key will be evicted from the database. Also this may trigger the
 * propagation of a DEL/UNLINK command in AOF / replication stream.
 *
 * The return value of the function is 0 if the key is still valid,
 * otherwise the function returns 1 if the key is expired. 
 * 检查键是否过期，如果过期，从数据库中删除
 * 返回0表示没有过期或没有过期时间，返回1 表示键被删除*/
int expireIfNeeded(redisDb *db, robj *key) {
    // key还没到过期时间，返回0
    if (!keyIsExpired(db,key)) return 0;

    /* slave节点不执行过期操作，slave的过期操作是同步master的DEL命令进行管理的 */
    if (server.masterhost != NULL) return 1;

    /* 执行到这里，说明是master中的key，且已经过期，删除key */
    server.stat_expiredkeys++;
    // 传播删除命令到slave和aof文件
    propagateExpire(db,key,server.lazyfree_lazy_expire);
    notifyKeyspaceEvent(NOTIFY_EXPIRED,
        "expired",key,db->id);
    int retval = server.lazyfree_lazy_expire ? dbAsyncDelete(db,key) :
                                               dbSyncDelete(db,key);
    if (retval) signalModifiedKey(NULL,db,key);
    return retval;
}

/* -----------------------------------------------------------------------------
 * API to get key arguments from commands
 * ---------------------------------------------------------------------------*/
#define MAX_KEYS_BUFFER 256
static int getKeysTempBuffer[MAX_KEYS_BUFFER];

/* The base case is to use the keys position as given in the command table
 * (firstkey, lastkey, step). 获取命令中的所有 key */
int *getKeysUsingCommandTable(struct redisCommand *cmd,robj **argv, int argc, int *numkeys) {
    int j, i = 0, last, *keys;
    UNUSED(argv);
    // 如果第一个参数就是key，返回空，numkeys设置为0
    if (cmd->firstkey == 0) {
        *numkeys = 0;
        return NULL;
    }

    last = cmd->lastkey;
    if (last < 0) last = argc+last;

    int count = ((last - cmd->firstkey)+1);
    keys = getKeysTempBuffer;
    if (count > MAX_KEYS_BUFFER)
        keys = zmalloc(sizeof(int)*count);

    for (j = cmd->firstkey; j <= last; j += cmd->keystep) {
        if (j >= argc) {
            /* Modules commands, and standard commands with a not fixed number
             * of arguments (negative arity parameter) do not have dispatch
             * time arity checks, so we need to handle the case where the user
             * passed an invalid number of arguments here. In this case we
             * return no keys and expect the command implementation to report
             * an arity or syntax error. */
            if (cmd->flags & CMD_MODULE || cmd->arity < 0) {
                getKeysFreeResult(keys);
                *numkeys = 0;
                return NULL;
            } else {
                serverPanic("Redis built-in command declared keys positions not matching the arity requirements.");
            }
        }
        keys[i++] = j;
    }
    *numkeys = i;
    return keys;
}

/* Return all the arguments that are keys in the command passed via argc / argv.
 *
 * The command returns the positions of all the key arguments inside the array,
 * so the actual return value is an heap allocated array of integers. The
 * length of the array is returned by reference into *numkeys.
 *
 * 'cmd' must be point to the corresponding entry into the redisCommand
 * table, according to the command name in argv[0].
 *
 * This function uses the command table if a command-specific helper function
 * is not required, otherwise it calls the command-specific function. 从argv和argc指定的参数列表中返回所有的键 */
int *getKeysFromCommand(struct redisCommand *cmd, robj **argv, int argc, int *numkeys) {
    if (cmd->flags & CMD_MODULE_GETKEYS) {
        return moduleGetCommandKeysViaAPI(cmd,argv,argc,numkeys);
    } else if (!(cmd->flags & CMD_MODULE) && cmd->getkeys_proc) {
        return cmd->getkeys_proc(cmd,argv,argc,numkeys);
    } else {
        return getKeysUsingCommandTable(cmd,argv,argc,numkeys);
    }
}

/* 释放getKeysFromCommand的结果 */
void getKeysFreeResult(int *result) {
    if (result != getKeysTempBuffer)
        zfree(result);
}

/* Helper function to extract keys from following commands:
 * ZUNIONSTORE <destkey> <num-keys> <key> <key> ... <key> <options>
 * ZINTERSTORE <destkey> <num-keys> <key> <key> ... <key> <options> 
 * 从ZUNIONSTORE、ZINTERSTORE命令中提取key的下标 */
int *zunionInterGetKeys(struct redisCommand *cmd, robj **argv, int argc, int *numkeys) {
    int i, num, *keys;
    UNUSED(cmd);

    num = atoi(argv[2]->ptr);
    /* Sanity check. Don't return any key if the command is going to
     * reply with syntax error. */
    if (num < 1 || num > (argc-3)) {
        *numkeys = 0;
        return NULL;
    }

    /* Keys in z{union,inter}store come from two places:
     * argv[1] = storage key,
     * argv[3...n] = keys to intersect */
    keys = getKeysTempBuffer;
    if (num+1>MAX_KEYS_BUFFER)
        keys = zmalloc(sizeof(int)*(num+1));

    /* Add all key positions for argv[3...n] to keys[] */
    for (i = 0; i < num; i++) keys[i] = 3+i;

    /* Finally add the argv[1] key position (the storage key target). */
    keys[num] = 1;
    *numkeys = num+1;  /* Total keys = {union,inter} keys + storage key */
    return keys;
}

/* Helper function to extract keys from the following commands:
 * EVAL <script> <num-keys> <key> <key> ... <key> [more stuff]
 * EVALSHA <script> <num-keys> <key> <key> ... <key> [more stuff] 
 * 从EVAL和EVALSHA命令中获取key的下标 */
int *evalGetKeys(struct redisCommand *cmd, robj **argv, int argc, int *numkeys) {
    int i, num, *keys;
    UNUSED(cmd);

    num = atoi(argv[2]->ptr);
    /* Sanity check. Don't return any key if the command is going to
     * reply with syntax error. */
    if (num <= 0 || num > (argc-3)) {
        *numkeys = 0;
        return NULL;
    }

    keys = getKeysTempBuffer;
    if (num>MAX_KEYS_BUFFER)
        keys = zmalloc(sizeof(int)*num);

    *numkeys = num;

    /* Add all key positions for argv[3...n] to keys[] */
    for (i = 0; i < num; i++) keys[i] = 3+i;

    return keys;
}

/* Helper function to extract keys from the SORT command.
 *
 * SORT <sort-key> ... STORE <store-key> ...
 *
 * The first argument of SORT is always a key, however a list of options
 * follow in SQL-alike style. Here we parse just the minimum in order to
 * correctly identify keys in the "STORE" option. 
 * 从SORT命令中获取key的下标 */
int *sortGetKeys(struct redisCommand *cmd, robj **argv, int argc, int *numkeys) {
    int i, j, num, *keys, found_store = 0;
    UNUSED(cmd);

    num = 0;
    keys = getKeysTempBuffer; /* Alloc 2 places for the worst case. */

    keys[num++] = 1; /* <sort-key> is always present. */

    /* Search for STORE option. By default we consider options to don't
     * have arguments, so if we find an unknown option name we scan the
     * next. However there are options with 1 or 2 arguments, so we
     * provide a list here in order to skip the right number of args. */
    struct {
        char *name;
        int skip;
    } skiplist[] = {
        {"limit", 2},
        {"get", 1},
        {"by", 1},
        {NULL, 0} /* End of elements. */
    };

    for (i = 2; i < argc; i++) {
        for (j = 0; skiplist[j].name != NULL; j++) {
            if (!strcasecmp(argv[i]->ptr,skiplist[j].name)) {
                i += skiplist[j].skip;
                break;
            } else if (!strcasecmp(argv[i]->ptr,"store") && i+1 < argc) {
                /* Note: we don't increment "num" here and continue the loop
                 * to be sure to process the *last* "STORE" option if multiple
                 * ones are provided. This is same behavior as SORT. */
                found_store = 1;
                keys[num] = i+1; /* <store-key> */
                break;
            }
        }
    }
    *numkeys = num + found_store;
    return keys;
}

// 将 key 原子性地从当前实例传送到目标实例的指定数据库上，一旦传送成功， key保证会出现在目标实例上，而当前实例上的 key 会被删除。
// MIGRATE命令中获取key的下标
int *migrateGetKeys(struct redisCommand *cmd, robj **argv, int argc, int *numkeys) {
    int i, num, first, *keys;
    UNUSED(cmd);

    /* Assume the obvious form. */
    first = 3;
    num = 1;

    /* But check for the extended one with the KEYS option. */
    if (argc > 6) {
        for (i = 6; i < argc; i++) {
            if (!strcasecmp(argv[i]->ptr,"keys") &&
                sdslen(argv[3]->ptr) == 0)
            {
                first = i+1;
                num = argc-first;
                break;
            }
        }
    }

    keys = getKeysTempBuffer;
    if (num>MAX_KEYS_BUFFER)
        keys = zmalloc(sizeof(int)*num);

    for (i = 0; i < num; i++) keys[i] = first+i;
    *numkeys = num;
    return keys;
}

/* Helper function to extract keys from following commands:
 * GEORADIUS key x y radius unit [WITHDIST] [WITHHASH] [WITHCOORD] [ASC|DESC]
 *                             [COUNT count] [STORE key] [STOREDIST key]
 * GEORADIUSBYMEMBER key member radius unit ... options ... */
int *georadiusGetKeys(struct redisCommand *cmd, robj **argv, int argc, int *numkeys) {
    int i, num, *keys;
    UNUSED(cmd);

    /* Check for the presence of the stored key in the command */
    int stored_key = -1;
    for (i = 5; i < argc; i++) {
        char *arg = argv[i]->ptr;
        /* For the case when user specifies both "store" and "storedist" options, the
         * second key specified would override the first key. This behavior is kept
         * the same as in georadiusCommand method.
         */
        if ((!strcasecmp(arg, "store") || !strcasecmp(arg, "storedist")) && ((i+1) < argc)) {
            stored_key = i+1;
            i++;
        }
    }
    num = 1 + (stored_key == -1 ? 0 : 1);

    /* Keys in the command come from two places:
     * argv[1] = key,
     * argv[5...n] = stored key if present
     */
    keys = getKeysTempBuffer;
    if (num>MAX_KEYS_BUFFER)
        keys = zmalloc(sizeof(int) * num);

    /* Add all key positions to keys[] */
    keys[0] = 1;
    if(num > 1) {
         keys[1] = stored_key;
    }
    *numkeys = num;
    return keys;
}

/* LCS ... [KEYS <key1> <key2>] ... */
int *lcsGetKeys(struct redisCommand *cmd, robj **argv, int argc, int *numkeys)
{
    int i;
    int *keys = getKeysTempBuffer;
    UNUSED(cmd);

    /* We need to parse the options of the command in order to check for the
     * "KEYS" argument before the "STRINGS" argument. */
    for (i = 1; i < argc; i++) {
        char *arg = argv[i]->ptr;
        int moreargs = (argc-1) - i;

        if (!strcasecmp(arg, "strings")) {
            break;
        } else if (!strcasecmp(arg, "keys") && moreargs >= 2) {
            keys[0] = i+1;
            keys[1] = i+2;
            *numkeys = 2;
            return keys;
        }
    }
    *numkeys = 0;
    return keys;
}

/* Helper function to extract keys from memory command.
 * MEMORY USAGE <key> */
int *memoryGetKeys(struct redisCommand *cmd, robj **argv, int argc, int *numkeys) {
    int *keys;
    UNUSED(cmd);

    if (argc >= 3 && !strcasecmp(argv[1]->ptr,"usage")) {
        keys = getKeysTempBuffer;
        keys[0] = 2;
        *numkeys = 1;
        return keys;
    }
    *numkeys = 0;
    return NULL;
}

/* XREAD [BLOCK <milliseconds>] [COUNT <count>] [GROUP <groupname> <ttl>]
 *       STREAMS key_1 key_2 ... key_N ID_1 ID_2 ... ID_N */
int *xreadGetKeys(struct redisCommand *cmd, robj **argv, int argc, int *numkeys) {
    int i, num = 0, *keys;
    UNUSED(cmd);

    /* We need to parse the options of the command in order to seek the first
     * "STREAMS" string which is actually the option. This is needed because
     * "STREAMS" could also be the name of the consumer group and even the
     * name of the stream key. */
    int streams_pos = -1;
    for (i = 1; i < argc; i++) {
        char *arg = argv[i]->ptr;
        if (!strcasecmp(arg, "block")) {
            i++; /* Skip option argument. */
        } else if (!strcasecmp(arg, "count")) {
            i++; /* Skip option argument. */
        } else if (!strcasecmp(arg, "group")) {
            i += 2; /* Skip option argument. */
        } else if (!strcasecmp(arg, "noack")) {
            /* Nothing to do. */
        } else if (!strcasecmp(arg, "streams")) {
            streams_pos = i;
            break;
        } else {
            break; /* Syntax error. */
        }
    }
    if (streams_pos != -1) num = argc - streams_pos - 1;

    /* Syntax error. */
    if (streams_pos == -1 || num == 0 || num % 2 != 0) {
        *numkeys = 0;
        return NULL;
    }
    num /= 2; /* We have half the keys as there are arguments because
                 there are also the IDs, one per key. */

    keys = getKeysTempBuffer;
    if (num>MAX_KEYS_BUFFER)
        keys = zmalloc(sizeof(int) * num);

    for (i = streams_pos+1; i < argc-num; i++) keys[i-streams_pos-1] = i;
    *numkeys = num;
    return keys;
}

/* 将key添加到对应的slot */
void slotToKeyUpdateKey(sds key, int add) {
    size_t keylen = sdslen(key);
    unsigned int hashslot = keyHashSlot(key,keylen);
    unsigned char buf[64];
    unsigned char *indexed = buf;
    // 判断是增加key还是减少key
    server.cluster->slots_keys_count[hashslot] += add ? 1 : -1;
    if (keylen+2 > 64) indexed = zmalloc(keylen+2);
    indexed[0] = (hashslot >> 8) & 0xff;
    indexed[1] = hashslot & 0xff;
    memcpy(indexed+2,key,keylen);
    if (add) {
        raxInsert(server.cluster->slots_to_keys,indexed,keylen+2,NULL,NULL);
    } else {
        raxRemove(server.cluster->slots_to_keys,indexed,keylen+2,NULL);
    }
    if (indexed != buf) zfree(indexed);
}

// slot增加key
void slotToKeyAdd(sds key) {
    slotToKeyUpdateKey(key,1);
}

// slot删除key
void slotToKeyDel(sds key) {
    slotToKeyUpdateKey(key,0);
}

// 同步清空key-slot map
void slotToKeyFlush(void) {
    raxFree(server.cluster->slots_to_keys);
    server.cluster->slots_to_keys = raxNew();
    memset(server.cluster->slots_keys_count,0,
           sizeof(server.cluster->slots_keys_count));
}

/* Pupulate the specified array of objects with keys in the specified slot.
 * New objects are returned to represent keys, it's up to the caller to
 * decrement the reference count to release the keys names. */
unsigned int getKeysInSlot(unsigned int hashslot, robj **keys, unsigned int count) {
    raxIterator iter;
    int j = 0;
    unsigned char indexed[2];

    indexed[0] = (hashslot >> 8) & 0xff;
    indexed[1] = hashslot & 0xff;
    raxStart(&iter,server.cluster->slots_to_keys);
    raxSeek(&iter,">=",indexed,2);
    while(count-- && raxNext(&iter)) {
        if (iter.key[0] != indexed[0] || iter.key[1] != indexed[1]) break;
        keys[j++] = createStringObject((char*)iter.key+2,iter.key_len-2);
    }
    raxStop(&iter);
    return j;
}

/* 将指定的slot中的key全部移除，返回移除的元素的数量 */
unsigned int delKeysInSlot(unsigned int hashslot) {
    raxIterator iter;
    int j = 0;
    unsigned char indexed[2];

    indexed[0] = (hashslot >> 8) & 0xff;
    indexed[1] = hashslot & 0xff;
    raxStart(&iter,server.cluster->slots_to_keys);
    while(server.cluster->slots_keys_count[hashslot]) {
        raxSeek(&iter,">=",indexed,2);
        raxNext(&iter);

        robj *key = createStringObject((char*)iter.key+2,iter.key_len-2);
        dbDelete(&server.db[0],key);
        decrRefCount(key);
        j++;
    }
    raxStop(&iter);
    return j;
}

// 返回指定的slot中key的数量
unsigned int countKeysInSlot(unsigned int hashslot) {
    return server.cluster->slots_keys_count[hashslot];
}
