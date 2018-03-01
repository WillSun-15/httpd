#include "hashtable.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define TABLE_SIZE (1024*1024)

/* element of the hash table's chain list */
struct kv
{
    struct kv* next;
    int key;
    void* value;
    void(*free_value)(void*);
};

/* HashTable */
typedef struct HashTable
{
    struct kv ** table;
}HashTable;

/* constructor of struct kv */
static void init_kv(struct kv* kv)
{
    kv->next = NULL;
    kv->key = -1;
    kv->value = NULL;
    kv->free_value = NULL;
}

/* destructor of struct kv */
static void free_kv(struct kv* kv)
{
    if (kv) {
        if (kv->free_value) {
            kv->free_value(kv->value);
        }
        kv->key = -1;
        free(kv);
    }
}

/* the classic Times33 hash function */
static unsigned int hash(int key, int max)
{
	return key % max;
}

/* new a HashTable instance */
HashTable* hash_table_new()
{
    HashTable* ht = malloc(sizeof(HashTable));
    if (NULL == ht) {
        hash_table_delete(ht);
        return NULL;
    }
    ht->table = malloc(sizeof(struct kv*) * TABLE_SIZE);
    if (NULL == ht->table) {
        hash_table_delete(ht);
        return NULL;
    }
    memset(ht->table, 0, sizeof(struct kv*) * TABLE_SIZE);

    return ht;
}

/* delete a HashTable instance */
void hash_table_delete(HashTable* ht)
{
    if (ht) {
        if (ht->table) {
            int i = 0;
            for (i = 0; i<TABLE_SIZE; i++) {
                struct kv* p = ht->table[i];
                struct kv* q = NULL;
                while (p) {
                    q = p->next;
                    free_kv(p);
                    p = q;
                }
            }
            free(ht->table);
            ht->table = NULL;
        }
        free(ht);
    }
}

/* insert or update a value indexed by key */
int hash_table_put2(HashTable* ht, int key, void* value, void(*free_value)(void*))
{
    int i = hash(key,TABLE_SIZE);
    struct kv* p = ht->table[i];
    struct kv* prep = p;

    while (p) { /* if key is already stroed, update its value */
        if (p->key == key) {
            if (p->free_value) {
                p->free_value(p->value);
            }
            p->value = value;
            p->free_value = free_value;
            break;
        }
        prep = p;
        p = p->next;
    }

    if (p == NULL) {/* if key has not been stored, then add it */

        struct kv * kv = malloc(sizeof(struct kv));
        if (NULL == kv) {
            return -1;
        }
        init_kv(kv);
        kv->next = NULL;
        kv->key = key;
        kv->value = value;
        kv->free_value = free_value;

        if (prep == NULL) {
            ht->table[i] = kv;
        }
        else {
            prep->next = kv;
        }
    }
    return 0;
}

/* get a value indexed by key */
void* hash_table_get(HashTable* ht, int key)
{
    int i = hash(key, TABLE_SIZE);
    struct kv* p = ht->table[i];
    while (p) {
        if (p->key == key) {
            return p->value;
        }
        p = p->next;
    }
    return NULL;
}

/* remove a value indexed by key */
void hash_table_rm(HashTable* ht, int key)
{
    int i = hash(key,TABLE_SIZE);

    struct kv* p = ht->table[i];
    struct kv* prep = p;
    while (p) {
        if (p->key == key) {
            free_kv(p);
            if (p == prep) {
                ht->table[i] = NULL;
            }
            else {
                prep->next = p->next;
            }
        }
        prep = p;
        p = p->next;
    }
}
