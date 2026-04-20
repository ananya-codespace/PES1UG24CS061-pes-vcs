#ifndef INDEX_H
#define INDEX_H

#include "pes.h"

#define MAX_INDEX_ENTRIES 10000

typedef struct {
    uint32_t mode;
    ObjectID hash;
    uint64_t mtime_sec;
    uint32_t size;
    char path[512];
} IndexEntry;

struct Index {
    IndexEntry entries[MAX_INDEX_ENTRIES];
    int count;
};

IndexEntry* index_find(Index *index, const char *path);
int index_remove(Index *index, const char *path);
int index_status(const Index *index);

#endif
