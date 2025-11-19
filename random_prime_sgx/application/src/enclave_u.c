#include "enclave_u.h"
#include <errno.h>

typedef struct ms_get_random_int_t {
	int ms_retval;
} ms_get_random_int_t;

typedef struct ms_is_prime_t {
	int ms_retval;
	int ms_n;
} ms_is_prime_t;

static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_enclave = {
	0,
	{ NULL },
};
sgx_status_t get_random_int(sgx_enclave_id_t eid, int* retval)
{
	sgx_status_t status;
	ms_get_random_int_t ms;
	status = sgx_ecall(eid, 0, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t is_prime(sgx_enclave_id_t eid, int* retval, int n)
{
	sgx_status_t status;
	ms_is_prime_t ms;
	ms.ms_n = n;
	status = sgx_ecall(eid, 1, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

