#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

void * kzalloc (size_t size, uint32_t flags) {
    (void)flags;
    return malloc(size);
}

void * kcalloc (size_t n, size_t size, uint32_t flags) {
    (void)flags;
    return calloc(n, size);
}

void kfree (void * objp) {
    free(objp);
}