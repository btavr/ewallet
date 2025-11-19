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

	sgx_status_t ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
	if (ret != SGX_SUCCESS) {
		printf("Error creating enclave: %d\n", ret);
		return -1;
	}

	int p = 0;
	int n;
    sgx_status_t status;

	do {
		status = get_random_int(global_eid, &n);
        if (status != SGX_SUCCESS) {
            printf("Error in get_random_int: %d\n", status);
            break;
        }

		status = is_prime(global_eid, &p, n);
        if (status != SGX_SUCCESS) {
            printf("Error in is_prime: %d\n", status);
            break;
        }

		printf("%d is%s a prime number.\n", n, (p == 0) ? "n't" : "" );
	} while( p != 1 );

	sgx_destroy_enclave(global_eid);

	return 0;
}
