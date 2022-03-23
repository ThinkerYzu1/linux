#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#if 0
#define REG_RAX 0

#define REG_RBX 1

#define REG_RCX 2

#define REG_RDX 3

#define REG_RSI 4

#define REG_RDI 5

#define REG_RSP 6

#define REG_RBP 7

#define REG_R8 8

#define REG_R9 9

#define REG_R10 10

#define REG_R11 11

#define REG_R12 12

#define REG_R13 13

#define REG_R14 14

#define REG_R15 15

#define REG_RIP 16
#endif

typedef struct KSymResolver KSymResolver;

struct KSymResolver *sym_resolver_create(void);

void sym_resolver_free(struct KSymResolver *resolver_ptr);

const char *sym_resolver_find_addr(struct KSymResolver *resolver_ptr, uint64_t addr);
