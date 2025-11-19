#include <stdio.h>      /* vsprintf */
#include <stdarg.h>
#include <string.h>
#include <math.h>

#include "enclave.h"
#include "enclave_t.h"  /* ocall_print_string */
#include "sgx_trts.h"

int get_random_int(void) {
    int val;
    sgx_status_t ret = sgx_read_rand((unsigned char*)&val, sizeof(val));
    if (ret != SGX_SUCCESS) {
        return 0;
    }
    if (val < 0) val = -val;
    return val;
}

int is_prime(int n) {
    int p = 1;

    if (n <= 1) {
        p = 0;
    } else if (n != 2 && (n % 2) == 0) {
        p = 0;
    } else {
        for (int i = 2; i <= sqrt(n); ++i) {
            if (n % i == 0) {
                p = 0;
                break;
            }
        }
    }

    return p;
}
