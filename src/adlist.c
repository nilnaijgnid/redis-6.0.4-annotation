#include <stdlib.h>
#include "adlist.h"
#include "zmalloc.h"

/* 创建一个新的list，被创建的list可以调用AlFreeList()函数释放，但是每个node的
 * 私有的值需要先调用AlFreeList()来释放 
 * 如果出现错误将返回NULL，否则返回指向新创建的list的指针 */
list *listCreate(void)
{
    struct list *list;

    if ((list = zmalloc(sizeof(*list))) == NULL)
        return NULL;
    list->head = list->tail = NULL;
    list->len = 0;
    list->dup = NULL;
    list->free = NULL;
    list->match = NULL;
    return list;
}

/* 移除list中的所有元素，但是并不销毁list本身 */
void listEmpty(list *list)
{
    unsigned long len;
    listNode *current, *next;
    
    current = list->head; // 从list的头开始释放
    len = list->len; // 需要释放的node的数量就是list的长度
    while(len--) {
        next = current->next;
        if (list->free) list->free(current->value);
        zfree(current);
        current = next;
    }
    list->head = list->tail = NULL;
    list->len = 0;
}

/* 释放整个list */
void listRelease(list *list)
{
    listEmpty(list);
    zfree(list);
}

/* 添加一个新的node到list的头部，node的值为value指针指向的位置 
 * 如果失败，则返回NULL，不会执行任何操作，列表不会修改
 * 如果成功，则返回传递给函数的list的指针 */
list *listAddNodeHead(list *list, void *value)
{
    listNode *node;

    if ((node = zmalloc(sizeof(*node))) == NULL)
        return NULL;
    node->value = value;
    if (list->len == 0) {
        list->head = list->tail = node;
        node->prev = node->next = NULL;
    } else {
        node->prev = NULL;
        node->next = list->head;
        list->head->prev = node;
        list->head = node;
    }
    list->len++;
    return list;
}

/* 添加一个新的node到list的尾部，node的值为value指针指向的位置 
 * 如果失败，则返回NULL，不会执行任何操作，列表不会修改
 * 如果成功，则返回传递给函数的list的指针 */
list *listAddNodeTail(list *list, void *value)
{
    listNode *node;

    if ((node = zmalloc(sizeof(*node))) == NULL)
        return NULL;
    node->value = value;
    if (list->len == 0) {
        list->head = list->tail = node;
        node->prev = node->next = NULL;
    } else {
        node->prev = list->tail;
        node->next = NULL;
        list->tail->next = node;
        list->tail = node;
    }
    list->len++;
    return list;
}

/* 在指定位置插入新节点 */
list *listInsertNode(list *list, listNode *old_node, void *value, int after) {
    listNode *node;

    if ((node = zmalloc(sizeof(*node))) == NULL)
        return NULL;
    node->value = value;
    if (after) {
        // 在指定的node之后添加节点
        node->prev = old_node; // 设置新增的node节点的前一个节点为old_node的前一个位置
        node->next = old_node->next; // 设置新增的node节点的后一个节点为old_node的后一个位置
        // 如果被添加的节点为list的最后一个节点，则将新增的节点设置为尾节点
        if (list->tail == old_node) {
            list->tail = node;
        }
    } else {
        // 与上面逻辑相似，将新节点添加的指定节点的前面
        node->next = old_node;
        node->prev = old_node->prev;
        if (list->head == old_node) {
            list->head = node;
        }
    }
    // 链接新增节点的前后节点
    if (node->prev != NULL) {
        node->prev->next = node;
    }
    if (node->next != NULL) {
        node->next->prev = node;
    }
    list->len++;
    return list;
}

/* 从list删除指定的节点 */
void listDelNode(list *list, listNode *node)
{
    if (node->prev)
        node->prev->next = node->next;
    else
        list->head = node->next;
    if (node->next)
        node->next->prev = node->prev;
    else
        list->tail = node->prev;
    if (list->free) list->free(node->value);
    zfree(node);
    list->len--;
}

/* 返回一个list迭代器，初始化之后每次调用listNext()函数都会返回list中的下一个元素 */
listIter *listGetIterator(list *list, int direction)
{
    listIter *iter;

    if ((iter = zmalloc(sizeof(*iter))) == NULL) return NULL;
    // 如果从list头开始迭代，则迭代器的下一个节点为头节点
    if (direction == AL_START_HEAD)
        iter->next = list->head;
    else
        // 如果从list尾开始迭代，则迭代器的下一个节点为尾节点
        iter->next = list->tail;
    // 设置迭代器的方向
    iter->direction = direction;
    return iter;
}

/* 释放迭代器内存 */
void listReleaseIterator(listIter *iter) {
    zfree(iter);
}

/* 将迭代器的位置重置为头节点 */
void listRewind(list *list, listIter *li) {
    li->next = list->head;
    li->direction = AL_START_HEAD;
}

/* 将迭代器的位置重置为尾节点 */
void listRewindTail(list *list, listIter *li) {
    li->next = list->tail;
    li->direction = AL_START_TAIL;
}

/* 返回迭代器的下一个元素 
 * 函数返回下一个元素的指针，如果后面没有元素则返回NULL */
listNode *listNext(listIter *iter)
{
    listNode *current = iter->next;

    if (current != NULL) {
        if (iter->direction == AL_START_HEAD)
            iter->next = current->next;
        else
            iter->next = current->prev;
    }
    return current;
}

/* 复制整个list，如果内存溢出则返回NULL 
 * 如果成功则返回原始列表的复制 
 * 无论成功失败，原始列表都不会改变 */
list *listDup(list *orig)
{
    list *copy;
    listIter iter;
    listNode *node;

    // 如果创建新列表失败，则直接返回NULL
    if ((copy = listCreate()) == NULL)
        return NULL;
    copy->dup = orig->dup;
    copy->free = orig->free;
    copy->match = orig->match;
    listRewind(orig, &iter); // 从头开始迭代的迭代器
    while((node = listNext(&iter)) != NULL) {
        void *value;

        if (copy->dup) {
            value = copy->dup(node->value);
            // 如果内存溢出，则释放目标list空间，直接返回NULL
            if (value == NULL) {
                listRelease(copy);
                return NULL;
            }
        } else
            value = node->value;
        // 如果内存溢出，则释放目标list空间，直接返回NULL
        if (listAddNodeTail(copy, value) == NULL) {
            listRelease(copy);
            return NULL;
        }
    }
    return copy;
}

/* 匹配给定的key，搜索list 
 * 匹配成功则返回第一个搜索到的node的指针（从头部搜索）
 * 没有搜索到则返回NULL */
listNode *listSearchKey(list *list, void *key)
{
    listIter iter;
    listNode *node;

    // 从头部开始的迭代器
    listRewind(list, &iter);
    while((node = listNext(&iter)) != NULL) {
        // 如果定义的match方法，则使用match方法匹配
        if (list->match) {
            if (list->match(node->value, key)) {
                return node;
            }
        } else {
            // 如果没有定义match方法，则直接比较node的值
            if (key == node->value) {
                return node;
            }
        }
    }
    return NULL;
}

/* 根据给定的下标返回元素， 如果给定的是负数，则从list的尾部开始计算
 * -1是最后一个节点（尾节点），如果给定的索引越界则返回NULL */
listNode *listIndex(list *list, long index) {
    listNode *n;

    // 给定的索引小于0则从尾开始
    if (index < 0) {
        index = (-index)-1;
        n = list->tail;
        // index递减，向前寻找node
        while(index-- && n) n = n->prev;
    } else {
        n = list->head;
        // index递减，向后寻找node
        while(index-- && n) n = n->next;
    }
    return n;
}

/* 把list的尾移动到list的头部 */
void listRotateTailToHead(list *list) {
    if (listLength(list) <= 1) return;

    /* Detach current tail */
    listNode *tail = list->tail;
    list->tail = tail->prev;
    list->tail->next = NULL;
    /* Move it as head */
    list->head->prev = tail;
    tail->prev = NULL;
    tail->next = list->head;
    list->head = tail;
}

/* 把list的头移动到list的尾部 */
void listRotateHeadToTail(list *list) {
    if (listLength(list) <= 1) return;

    listNode *head = list->head;
    /* Detach current head */
    list->head = head->next;
    list->head->prev = NULL;
    /* Move it as tail */
    list->tail->next = head;
    head->next = NULL;
    head->prev = list->tail;
    list->tail = head;
}

/* 将列表o的元素追加到列表l的尾部，并且释放o */
void listJoin(list *l, list *o) {
    if (o->head)
        o->head->prev = l->tail;

    if (l->tail)
        l->tail->next = o->head;
    else
        l->head = o->head;

    if (o->tail) l->tail = o->tail;
    l->len += o->len;

    /* 释放o */
    o->head = o->tail = NULL;
    o->len = 0;
}
