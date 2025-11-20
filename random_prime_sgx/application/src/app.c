#include <stdio.h>
#include <stdlib.h>
#include "sgx_urts.h"
#include "enclave_u.h"
#include "app.h"

#define ENCLAVE_FILENAME "enclave.signed.so"

sgx_enclave_id_t global_eid = 0;

/* Application entry */
int main( int argc, char *argv[] )
{
	(void)(argc);
	(void)(argv);

    /* 
     * Step 1: Initialize the Enclave
     * sgx_create_enclave loads the signed enclave image into protected memory.
     * - ENCLAVE_FILENAME: The path to the signed enclave file.
     * - SGX_DEBUG_FLAG: Enables debugging if compiled in debug mode.
     * - global_eid: Stores the Enclave ID needed for future calls.
     */
	sgx_status_t ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
	if (ret != SGX_SUCCESS) {
		printf("Error creating enclave: %d\n", ret);
		return -1;
	}

	int p = 0;
	int n;
    sgx_status_t status;

	do {
        /* 
         * Step 2: ECALL - Get Random Number
         * Calls the trusted function get_random_int inside the enclave.
         * Note: The return value of the C function is passed via the pointer &n.
         */
		status = get_random_int(global_eid, &n);
        if (status != SGX_SUCCESS) {
            printf("Error in get_random_int: %d\n", status);
            break;
        }

        /* 
         * Step 3: ECALL - Check Primality
         * Calls the trusted function is_prime inside the enclave to check 'n'.
         * The result (1 if prime, 0 otherwise) is stored in 'p'.
         */
		status = is_prime(global_eid, &p, n);
        if (status != SGX_SUCCESS) {
            printf("Error in is_prime: %d\n", status);
            break;
        }

		printf("%d is%s a prime number.\n", n, (p == 0) ? "n't" : "" );
	} while( p != 1 ); /* Repeat until a prime number is found */

    /* 
     * Step 4: Destroy the Enclave
     * Releases the protected memory and resources associated with the enclave.
     */
	sgx_destroy_enclave(global_eid);

	return 0;
}
