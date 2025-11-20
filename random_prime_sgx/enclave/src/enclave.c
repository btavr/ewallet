#include <stdio.h>      /* vsprintf */
#include <stdarg.h>
#include <string.h>
#include <math.h>

#include "enclave.h"
#include "enclave_t.h"  /* ocall_print_string */
#include "sgx_trts.h"

/* 
 * Trusted function to generate a random integer.
 * Uses SGX hardware instructions (RDRAND) for cryptographic randomness.
 */
int get_random_int(void) {
    int val;
    /* sgx_read_rand: Generates random bytes using the CPU's hardware RNG */
    sgx_status_t ret = sgx_read_rand((unsigned char*)&val, sizeof(val));
    if (ret != SGX_SUCCESS) {
        return 0; /* Fail safe */
    }
    /* Ensure positive value */
    if (val < 0) val = -val;
    return val;
}

/* 
 * Trusted function to check if a number is prime.
 * This computation happens entirely inside the enclave, protected from the OS.
 */
int is_prime(int n) {
    int p = 1; /* Assume prime by default */

    if (n <= 1) {
        p = 0;
    } else if (n != 2 && (n % 2) == 0) {
        p = 0; /* Even numbers > 2 are not prime */
    } else {
        /* Trial division up to sqrt(n) */
        for (int i = 2; i <= sqrt(n); ++i) {
            if (n % i == 0) {
                p = 0;
                break;
            }
        }
    }

    return p;
}
