#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

int ecall_print_prime_random(void);
int ecall_generate_password(int p_length);
int ecall_create_wallet(const char* master_password);
int ecall_show_wallet(const char* master_password);
int ecall_add_item(const char* master_password, const char* title, const char* username, const char* password);
int ecall_remove_item(const char* master_password, int index);
int ecall_change_master_password(const char* old_password, const char* new_password);

sgx_status_t SGX_CDECL ocall_print_string(const char* str);
sgx_status_t SGX_CDECL ocall_save_wallet(int* retval, const uint8_t* data, uint32_t size);
sgx_status_t SGX_CDECL ocall_load_wallet(int* retval, uint8_t* data, uint32_t size);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
