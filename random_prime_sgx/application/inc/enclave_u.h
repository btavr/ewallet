#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif


sgx_status_t get_random_int(sgx_enclave_id_t eid, int* retval);
sgx_status_t is_prime(sgx_enclave_id_t eid, int* retval, int n);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
