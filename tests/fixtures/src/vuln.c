/*
 * vuln.c - deliberately vulnerable "parser", no libc needed on the hot path.
 *
 *   struct local { char name[8]; uint64_t magic; };
 *   parse() copies len bytes of an UNTRUSTED packet straight into name[]
 *   with no bounds check  ->  stack buffer overflow:
 *       bytes beyond name[7] overwrite the adjacent magic field.
 *   Then it checks: if (magic == 0x1122334455667788) win();
 *
 *   magic starts as 0, so the ONLY way win() can run is if the attacker's
 *   bytes overflowed name[] and corrupted magic - i.e. the condition is
 *   only reachable through the buffer overflow.
 *
 * We compile this identically for x86-64, AArch64, ARM and RISC-V and let
 * angr find the overflowing input on EVERY architecture from the VEX IR alone.
 */
#include <stdint.h>

char packet[64];          /* pretend this is a network/firmware input buffer */
volatile int caught = 0;  /* set by win() */

void win(void) {
    caught = 1;           /* "attacker controlled code / flag" */
}

__attribute__((noinline))
int parse(char *src) {
    struct {
        char name[8];         /* destination - too small! */
        uint64_t magic;       /* right after name in memory */
    } local;
    local.magic = 0;          /* initialized safely... */

    int i;
    for (i = 0; i < 24; i++)  /* ...but then 24 bytes are copied in anyway */
        local.name[i] = src[i];   /*  <-- overflow: writes past name[] */

    if (local.magic == 0x1122334455667788ULL)  /* corrupted by the overflow? */
        win();                                 /* only reachable if yes */

    return caught;
}

int main(void) { return 0; }   /* never run by angr; we start inside parse() */
