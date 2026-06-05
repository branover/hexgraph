/*
 * keyderive — derives a license "unlock code" at runtime through a small arithmetic
 * schedule, so the magic value never appears as a literal in the binary. A static
 * reader sees only the arithmetic loop; recovering the constant requires either
 * re-deriving the schedule by hand or EMULATING the routine. HexGraph analysis
 * fixture (Phase 4 P-Code emulation) — never run it as a service.
 */
#include <stdio.h>
#include <stdint.h>

/* No inputs: a pure derivation. Emulating from entry to return recovers the code. */
uint32_t derive_unlock_code(void) {
    uint32_t k = 0x1337c0deu;
    for (int i = 1; i <= 16; i++) {
        k = k * 1103515245u + 12345u;
        k ^= (k >> 7);
        k += (uint32_t)i * 0x9e3779b9u;
    }
    return k;
}

int main(void) {
    printf("%08x\n", derive_unlock_code());
    return 0;
}
