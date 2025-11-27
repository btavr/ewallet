#include "enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


typedef struct ms_ecall_print_prime_random_t {
	int ms_retval;
} ms_ecall_print_prime_random_t;

typedef struct ms_ecall_generate_password_t {
	int ms_retval;
	int ms_p_length;
} ms_ecall_generate_password_t;

typedef struct ms_ecall_create_wallet_t {
	int ms_retval;
	const char* ms_master_password;
	size_t ms_master_password_len;
} ms_ecall_create_wallet_t;

typedef struct ms_ecall_show_wallet_t {
	int ms_retval;
	const char* ms_master_password;
	size_t ms_master_password_len;
} ms_ecall_show_wallet_t;

typedef struct ms_ecall_add_item_t {
	int ms_retval;
	const char* ms_master_password;
	size_t ms_master_password_len;
	const char* ms_title;
	size_t ms_title_len;
	const char* ms_username;
	size_t ms_username_len;
	const char* ms_password;
	size_t ms_password_len;
} ms_ecall_add_item_t;

typedef struct ms_ecall_remove_item_t {
	int ms_retval;
	const char* ms_master_password;
	size_t ms_master_password_len;
	int ms_index;
} ms_ecall_remove_item_t;

typedef struct ms_ecall_change_master_password_t {
	int ms_retval;
	const char* ms_old_password;
	size_t ms_old_password_len;
	const char* ms_new_password;
	size_t ms_new_password_len;
} ms_ecall_change_master_password_t;

typedef struct ms_ocall_print_string_t {
	const char* ms_str;
} ms_ocall_print_string_t;

typedef struct ms_ocall_save_wallet_t {
	int ms_retval;
	const uint8_t* ms_data;
	uint32_t ms_size;
} ms_ocall_save_wallet_t;

typedef struct ms_ocall_load_wallet_t {
	int ms_retval;
	uint8_t* ms_data;
	uint32_t ms_size;
} ms_ocall_load_wallet_t;

static sgx_status_t SGX_CDECL sgx_ecall_print_prime_random(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_print_prime_random_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_print_prime_random_t* ms = SGX_CAST(ms_ecall_print_prime_random_t*, pms);
	ms_ecall_print_prime_random_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_print_prime_random_t), ms, sizeof(ms_ecall_print_prime_random_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	int _in_retval;


	_in_retval = ecall_print_prime_random();
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_generate_password(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_generate_password_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_generate_password_t* ms = SGX_CAST(ms_ecall_generate_password_t*, pms);
	ms_ecall_generate_password_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_generate_password_t), ms, sizeof(ms_ecall_generate_password_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	int _in_retval;


	_in_retval = ecall_generate_password(__in_ms.ms_p_length);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_create_wallet(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_create_wallet_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_create_wallet_t* ms = SGX_CAST(ms_ecall_create_wallet_t*, pms);
	ms_ecall_create_wallet_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_create_wallet_t), ms, sizeof(ms_ecall_create_wallet_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const char* _tmp_master_password = __in_ms.ms_master_password;
	size_t _len_master_password = __in_ms.ms_master_password_len ;
	char* _in_master_password = NULL;
	int _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_master_password, _len_master_password);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_master_password != NULL && _len_master_password != 0) {
		_in_master_password = (char*)malloc(_len_master_password);
		if (_in_master_password == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_master_password, _len_master_password, _tmp_master_password, _len_master_password)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_master_password[_len_master_password - 1] = '\0';
		if (_len_master_password != strlen(_in_master_password) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	_in_retval = ecall_create_wallet((const char*)_in_master_password);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	if (_in_master_password) free(_in_master_password);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_show_wallet(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_show_wallet_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_show_wallet_t* ms = SGX_CAST(ms_ecall_show_wallet_t*, pms);
	ms_ecall_show_wallet_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_show_wallet_t), ms, sizeof(ms_ecall_show_wallet_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const char* _tmp_master_password = __in_ms.ms_master_password;
	size_t _len_master_password = __in_ms.ms_master_password_len ;
	char* _in_master_password = NULL;
	int _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_master_password, _len_master_password);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_master_password != NULL && _len_master_password != 0) {
		_in_master_password = (char*)malloc(_len_master_password);
		if (_in_master_password == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_master_password, _len_master_password, _tmp_master_password, _len_master_password)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_master_password[_len_master_password - 1] = '\0';
		if (_len_master_password != strlen(_in_master_password) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	_in_retval = ecall_show_wallet((const char*)_in_master_password);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	if (_in_master_password) free(_in_master_password);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_add_item(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_add_item_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_add_item_t* ms = SGX_CAST(ms_ecall_add_item_t*, pms);
	ms_ecall_add_item_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_add_item_t), ms, sizeof(ms_ecall_add_item_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const char* _tmp_master_password = __in_ms.ms_master_password;
	size_t _len_master_password = __in_ms.ms_master_password_len ;
	char* _in_master_password = NULL;
	const char* _tmp_title = __in_ms.ms_title;
	size_t _len_title = __in_ms.ms_title_len ;
	char* _in_title = NULL;
	const char* _tmp_username = __in_ms.ms_username;
	size_t _len_username = __in_ms.ms_username_len ;
	char* _in_username = NULL;
	const char* _tmp_password = __in_ms.ms_password;
	size_t _len_password = __in_ms.ms_password_len ;
	char* _in_password = NULL;
	int _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_master_password, _len_master_password);
	CHECK_UNIQUE_POINTER(_tmp_title, _len_title);
	CHECK_UNIQUE_POINTER(_tmp_username, _len_username);
	CHECK_UNIQUE_POINTER(_tmp_password, _len_password);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_master_password != NULL && _len_master_password != 0) {
		_in_master_password = (char*)malloc(_len_master_password);
		if (_in_master_password == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_master_password, _len_master_password, _tmp_master_password, _len_master_password)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_master_password[_len_master_password - 1] = '\0';
		if (_len_master_password != strlen(_in_master_password) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_tmp_title != NULL && _len_title != 0) {
		_in_title = (char*)malloc(_len_title);
		if (_in_title == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_title, _len_title, _tmp_title, _len_title)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_title[_len_title - 1] = '\0';
		if (_len_title != strlen(_in_title) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_tmp_username != NULL && _len_username != 0) {
		_in_username = (char*)malloc(_len_username);
		if (_in_username == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_username, _len_username, _tmp_username, _len_username)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_username[_len_username - 1] = '\0';
		if (_len_username != strlen(_in_username) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_tmp_password != NULL && _len_password != 0) {
		_in_password = (char*)malloc(_len_password);
		if (_in_password == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_password, _len_password, _tmp_password, _len_password)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_password[_len_password - 1] = '\0';
		if (_len_password != strlen(_in_password) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	_in_retval = ecall_add_item((const char*)_in_master_password, (const char*)_in_title, (const char*)_in_username, (const char*)_in_password);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	if (_in_master_password) free(_in_master_password);
	if (_in_title) free(_in_title);
	if (_in_username) free(_in_username);
	if (_in_password) free(_in_password);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_remove_item(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_remove_item_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_remove_item_t* ms = SGX_CAST(ms_ecall_remove_item_t*, pms);
	ms_ecall_remove_item_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_remove_item_t), ms, sizeof(ms_ecall_remove_item_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const char* _tmp_master_password = __in_ms.ms_master_password;
	size_t _len_master_password = __in_ms.ms_master_password_len ;
	char* _in_master_password = NULL;
	int _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_master_password, _len_master_password);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_master_password != NULL && _len_master_password != 0) {
		_in_master_password = (char*)malloc(_len_master_password);
		if (_in_master_password == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_master_password, _len_master_password, _tmp_master_password, _len_master_password)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_master_password[_len_master_password - 1] = '\0';
		if (_len_master_password != strlen(_in_master_password) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	_in_retval = ecall_remove_item((const char*)_in_master_password, __in_ms.ms_index);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	if (_in_master_password) free(_in_master_password);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_change_master_password(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_change_master_password_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_change_master_password_t* ms = SGX_CAST(ms_ecall_change_master_password_t*, pms);
	ms_ecall_change_master_password_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_change_master_password_t), ms, sizeof(ms_ecall_change_master_password_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const char* _tmp_old_password = __in_ms.ms_old_password;
	size_t _len_old_password = __in_ms.ms_old_password_len ;
	char* _in_old_password = NULL;
	const char* _tmp_new_password = __in_ms.ms_new_password;
	size_t _len_new_password = __in_ms.ms_new_password_len ;
	char* _in_new_password = NULL;
	int _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_old_password, _len_old_password);
	CHECK_UNIQUE_POINTER(_tmp_new_password, _len_new_password);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_old_password != NULL && _len_old_password != 0) {
		_in_old_password = (char*)malloc(_len_old_password);
		if (_in_old_password == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_old_password, _len_old_password, _tmp_old_password, _len_old_password)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_old_password[_len_old_password - 1] = '\0';
		if (_len_old_password != strlen(_in_old_password) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_tmp_new_password != NULL && _len_new_password != 0) {
		_in_new_password = (char*)malloc(_len_new_password);
		if (_in_new_password == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_new_password, _len_new_password, _tmp_new_password, _len_new_password)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_new_password[_len_new_password - 1] = '\0';
		if (_len_new_password != strlen(_in_new_password) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	_in_retval = ecall_change_master_password((const char*)_in_old_password, (const char*)_in_new_password);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	if (_in_old_password) free(_in_old_password);
	if (_in_new_password) free(_in_new_password);
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[7];
} g_ecall_table = {
	7,
	{
		{(void*)(uintptr_t)sgx_ecall_print_prime_random, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_generate_password, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_create_wallet, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_show_wallet, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_add_item, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_remove_item, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_change_master_password, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[3][7];
} g_dyn_entry_table = {
	3,
	{
		{0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_print_string(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_string_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_string_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(str, _len_str);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (str != NULL) ? _len_str : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_string_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_string_t));
	ocalloc_size -= sizeof(ms_ocall_print_string_t);

	if (str != NULL) {
		if (memcpy_verw_s(&ms->ms_str, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_str % sizeof(*str) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, str, _len_str)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_str);
		ocalloc_size -= _len_str;
	} else {
		ms->ms_str = NULL;
	}

	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_save_wallet(int* retval, const uint8_t* data, uint32_t size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_data = size;

	ms_ocall_save_wallet_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_save_wallet_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(data, _len_data);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (data != NULL) ? _len_data : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_save_wallet_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_save_wallet_t));
	ocalloc_size -= sizeof(ms_ocall_save_wallet_t);

	if (data != NULL) {
		if (memcpy_verw_s(&ms->ms_data, sizeof(const uint8_t*), &__tmp, sizeof(const uint8_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_data % sizeof(*data) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, data, _len_data)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_data);
		ocalloc_size -= _len_data;
	} else {
		ms->ms_data = NULL;
	}

	if (memcpy_verw_s(&ms->ms_size, sizeof(ms->ms_size), &size, sizeof(size))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_load_wallet(int* retval, uint8_t* data, uint32_t size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_data = size;

	ms_ocall_load_wallet_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_load_wallet_t);
	void *__tmp = NULL;

	void *__tmp_data = NULL;

	CHECK_ENCLAVE_POINTER(data, _len_data);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (data != NULL) ? _len_data : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_load_wallet_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_load_wallet_t));
	ocalloc_size -= sizeof(ms_ocall_load_wallet_t);

	if (data != NULL) {
		if (memcpy_verw_s(&ms->ms_data, sizeof(uint8_t*), &__tmp, sizeof(uint8_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_data = __tmp;
		if (_len_data % sizeof(*data) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_data, 0, _len_data);
		__tmp = (void *)((size_t)__tmp + _len_data);
		ocalloc_size -= _len_data;
	} else {
		ms->ms_data = NULL;
	}

	if (memcpy_verw_s(&ms->ms_size, sizeof(ms->ms_size), &size, sizeof(size))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (data) {
			if (memcpy_s((void*)data, _len_data, __tmp_data, _len_data)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

