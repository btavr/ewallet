#include <stdio.h>      /* vsprintf */
#include <stdarg.h>
#include <string.h>
#include <sgx_trts.h>
#include <sgx_tseal.h>
#include <tlibc.h> 		/* malloc */


#include "enclave_config.h"
#include "enclave.h"
#include "enclave_t.h"  /* ocall_print_string */

/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
int printf( const char *fmt, ... )
{
	char buf[BUFSIZ] = {'\0'};
	va_list ap;

	va_start( ap, fmt );
	vsnprintf(buf, BUFSIZ, fmt, ap);
	va_end( ap );

	ocall_print_string( buf );

    return ( (int) strnlen( buf, BUFSIZ - 1 ) + 1 );
}

//transform a string into an integer
int yetAnotherAtoiBecauseSgxNotFound(char *str)
{
 int res = 0; // Initialize result

 // Iterate through all characters of input string and
 // update result
 for (int i = 0; str[i] != '\0'; ++i) {
     if (str[i]> '9' || str[i]<'0')
         return -1;
     res = res*10 + str[i] - '0';
 }
 // return result.
 return res;
}

//generates a random integer
int get_random_int( void ) {
    unsigned char rand_num[10];
    sgx_status_t rand_ret = sgx_read_rand(rand_num, sizeof(rand_num));
    return yetAnotherAtoiBecauseSgxNotFound(rand_num);
}

//returns 0 if the parameter n is not a prime number else it returns 1
int is_prime( int n ) {

	int p = 1;

	if ( n <= 1 ) {
		p = 0;
	} else if ( n != 2 && (n % 2) == 0) {
		p = 0;
	} else {
		for ( int i = 2; i <= sqrt(n); ++i ) {
	 		// If n is divisible by any number between 2 and n/2, it is not prime
			if ( n % i == 0 ) {
				p = 0;
				break;
			}
		}
	}

    return p;
}

//generate random password with size p_length between 8 and 100
int generate_password(char *p_value, int p_length) {

	int i, randomizer;

	// check password policy
	if (p_length < 8 || p_length+1 > WALLET_MAX_ITEM_SIZE) {
		return ERR_PASSWORD_OUT_OF_RANGE;
	}

	for (i=0; i<p_length; i++) {

        randomizer = get_random_int() % 4;

        switch(randomizer) {
            case 0:
                	p_value[i] = get_pwd_char(numbers, NUM_SIZE);
                	break;
            case 1:
                	p_value[i] = get_pwd_char(letter, ALPHA_SIZE);
                	break;
            case 2:
                	p_value[i] = get_pwd_char(letterr, ALPHA_SIZE);
                	break;
            case 3:
                	p_value[i] = get_pwd_char(symbols, SYM_SIZE);
                	break;
            default:
                	break;
        }
	}

	p_value[p_length] = '\0';

	return RET_SUCCESS;
}

char get_pwd_char(char *charlist, int len)
{
	return (charlist[(get_random_int() / (RAND_MAX / len))]);
}

//Seals the provided wallet, if it fails it will release the sealed buffer resources and return an error code
int seal_my_wallet(wallet_t* wallet, uint32_t sealed_size, uint8_t *sealed_buffer)
{
    sgx_status_t ret = sgx_seal_data(0, NULL, sizeof(wallet_t), (uint8_t*)wallet, sealed_size, (sgx_sealed_data_t*)sealed_buffer);
	free(wallet);

    if (ret != SGX_SUCCESS) {
        free(sealed_buffer);
        return SGX_ERROR_FAILURE_SEAL;
    }
	return RET_SUCCESS;
}

//Unseals the provided wallet, if it fails it will release allocated wallet resources and return an error code
int unseal_my_wallet(wallet_t* wallet, uint32_t sealed_size, uint8_t *sealed_buffer)
{
    uint32_t out_len = sizeof(wallet_t);
    sgx_status_t ret = sgx_unseal_data((sgx_sealed_data_t*)sealed_buffer, NULL, NULL, (uint8_t*)wallet, &out_len);
	free(sealed_buffer);

    if (ret != SGX_SUCCESS) {
		free(wallet);
		return SGX_ERROR_FAILURE_UNSEAL;
	}

	return RET_SUCCESS;
}

//create a new wallet
int create_wallet(const char* master_password) {

	int ret;

	// check password policy
	if (strlen(master_password) < 8 || strlen(master_password)+1 > WALLET_MAX_ITEM_SIZE) {
		return ERR_PASSWORD_OUT_OF_RANGE;
	}

	//create sealed size
	uint32_t sealed_size = sgx_calc_sealed_data_size(0, sizeof(wallet_t));
    if (sealed_size == UINT32_MAX) {
        return ERR_CANNOT_SAVE_WALLET;
	}

	// create new wallet
	wallet_t* wallet = (wallet_t*)malloc(sizeof(wallet_t));
	wallet->size = 0;
	strncpy(wallet->master_password, master_password, strlen(master_password)+1);

	//create sealed buffer
    uint8_t *sealed_buffer = (uint8_t*) malloc(sealed_size);
    if (!sealed_buffer) {
		free(sealed_buffer);
		free(wallet);
        return ERR_CANNOT_SAVE_WALLET;
	}

	ret = seal_my_wallet(wallet, sealed_size, sealed_buffer);

	if(ret == RET_SUCCESS) {
		//Send sealed data to untrusted app
		ret = ocall_save_wallet(sealed_buf, sealed_size);
		free(sealed_buf);
	}
	
	if (ret != 0) {
		return ERR_CANNOT_SAVE_WALLET;
	}
	return RET_SUCCESS;
}

//prints wallet data to the console
int show_wallet(const char* master_password) {

	int ret;
	
	// verify master-password
	if (strcmp(wallet->master_password, master_password) != 0) {
		return ERR_WRONG_MASTER_PASSWORD;
	}

	//create sealed size
	uint32_t sealed_size = sgx_calc_sealed_data_size(0, sizeof(wallet_t));
    if (sealed_size == UINT32_MAX) {
        return SGX_ERROR_INVALID_PARAMETER;
	}
	uint8_t* sealed_buffer = (uint8_t*)malloc(sizeof(wallet_t));
	wallet_t* wallet = (wallet_t*)malloc(sizeof(wallet_t));
	
	// load wallet
	ret = ocall_load_wallet(sealed_buffer, sealed_size);
	if (ret != 0) {
		free(sealed_buffer);
		free(wallet);
		return ERR_CANNOT_LOAD_WALLET;
	}

	//unseal wallet
	ret = unseal_my_wallet(wallet, sealed_size, sealed_buffer);
	if (ret != 0) {
		return ERR_CANNOT_LOAD_WALLET;
	}
	
	printf("[INFO] eWallet successfully retrieved.\n");
	print_wallet(wallet);
	free(wallet);
	return RET_SUCCESS;
}

//prints a wallet to the console
void print_wallet(const wallet_t* wallet) {
    printf("\n-----------------------------------------\n");
    printf("Simple password eWallet.\n");
    printf("-----------------------------------------\n");
    printf("Number of items: %lu\n", wallet->size);
    for (int i = 0; i < wallet->size; ++i) {
        printf("\n#%d -- %s\n", i, wallet->items[i].title);
        printf("Username: %s\n", wallet->items[i].username);
        printf("Password: %s\n", wallet->items[i].password);
    }
    printf("\n------------------------------------------\n\n");
}

//adds an item to the wallet if the password provided is the wallets password
int add_item(const char* master_password, const item_t* item, const size_t item_size) {

	int ret;

	// check input length
	if (strlen(item->title)+1 > WALLET_MAX_ITEM_SIZE ||
		strlen(item->username)+1 > WALLET_MAX_ITEM_SIZE ||
		strlen(item->password)+1 > WALLET_MAX_ITEM_SIZE) {
		return ERR_ITEM_TOO_LONG;
    }

	//create sealed size
	uint32_t sealed_size = sgx_calc_sealed_data_size(0, sizeof(wallet_t));
    if (sealed_size == UINT32_MAX) {
        return SGX_ERROR_INVALID_PARAMETER;
	}
	uint8_t* sealed_buffer = (uint8_t*)malloc(sizeof(wallet_t));
	wallet_t* wallet = (wallet_t*)malloc(sizeof(wallet_t));
	
	// load wallet
	ret = ocall_load_wallet(sealed_buffer, sealed_size);
	if (ret != 0) {
		free(sealed_buffer);
		free(wallet);
		return ERR_CANNOT_LOAD_WALLET;
	}

	//unseal wallet
	ret = unseal_my_wallet(wallet, sealed_size, sealed_buffer);
	if (ret != 0) {
		return ERR_CANNOT_LOAD_WALLET;
	}
	
	// verify master-password
	if (strcmp(wallet->master_password, master_password) != 0) {
		free(wallet);
		return ERR_WRONG_MASTER_PASSWORD;
	}

	// add item to the wallet
	size_t wallet_size = wallet->size;
	if (wallet_size >= WALLET_MAX_ITEMS) {
		free(wallet);
		return ERR_WALLET_FULL;
	}

	wallet->items[wallet_size] = *item;
	++wallet->size;

	//create sealed buffer
	sealed_buffer = NULL;
    sealed_buffer = (uint8_t*) malloc(sealed_size);
    if (!sealed_buffer) {
		free(sealed_buffer);
		free(wallet);
        return ERR_CANNOT_SAVE_WALLET;
	}

	//seal wallet
	ret = seal_my_wallet(wallet, sealed_size, sealed_buffer);

	if(ret == RET_SUCCESS) {
		//save wallet
		ret = ocall_save_wallet(sealed_buf, sealed_size);
		free(sealed_buf);
	}

	if (ret != 0) {
		return ERR_CANNOT_SAVE_WALLET;
	}

	// exit
	return RET_SUCCESS;
}

//removes an entry from the wallet if the password provided is the wallets password and the index is a valid index
int remove_item(const char* master_password, const int index) {

	int ret;

	// check index bounds
	if (index < 0 || index >= WALLET_MAX_ITEMS) {
		return ERR_ITEM_DOES_NOT_EXIST;
	}

	//create sealed size
	uint32_t sealed_size = sgx_calc_sealed_data_size(0, sizeof(wallet_t));
    if (sealed_size == UINT32_MAX) {
        return SGX_ERROR_INVALID_PARAMETER;
	}
	uint8_t* sealed_buffer = (uint8_t*)malloc(sizeof(wallet_t));
	wallet_t* wallet = (wallet_t*)malloc(sizeof(wallet_t));
	
	// load wallet
	ret = ocall_load_wallet(sealed_buffer, sealed_size);
	if (ret != 0) {
		free(sealed_buffer);
		free(wallet);
		return ERR_CANNOT_LOAD_WALLET;
	}

	//unseal wallet
	ret = unseal_my_wallet(wallet, sealed_size, sealed_buffer);
	if (ret != 0) {
		return ERR_CANNOT_LOAD_WALLET;
	}
	
	// verify master-password
	if (strcmp(wallet->master_password, master_password) != 0) {
		free(wallet);
		return ERR_WRONG_MASTER_PASSWORD;
	}

	// remove item from the wallet
	size_t wallet_size = wallet->size;
	if (index >= wallet_size) {
		free(wallet);
		return ERR_ITEM_DOES_NOT_EXIST;
	}
	for (int i = index; i < wallet_size-1; ++i) {
		wallet->items[i] = wallet->items[i+1];
	}
	--wallet->size;

	//create sealed buffer
	sealed_buffer = NULL;
    sealed_buffer = (uint8_t*) malloc(sealed_size);
    if (!sealed_buffer) {
		free(sealed_buffer);
		free(wallet);
        return ERR_CANNOT_SAVE_WALLET;
	}

	//seal wallet
	ret = seal_my_wallet(wallet, sealed_size, sealed_buffer);

	if(ret == RET_SUCCESS) {
		//save wallet
		ret = ocall_save_wallet(sealed_buf, sealed_size);
		free(sealed_buf);
	}
	
	if (ret != 0) {
		return ERR_CANNOT_SAVE_WALLET;
	}

	// exit
	return RET_SUCCESS;
}

//ECALL to generate and print random numbers until the number generated is a prime number
int ecall_print_prime_random()
{
    int p = 0;
	int n;

	do {
		n = get_random_int();
		p = is_prime( n );
		printf("%d is%s a prime number.\n", n, (p == 0) ? "n't" : "" );
	} while( p != 1 );

	return 0;
}

//ECALL to generate random password with p_length between 8 and 100
int ecall_generate_password(int p_length) {

	char* pwd = (char*)malloc(sizeof(char)*pwd_size);
	int ret = generate_password(pwd, p_length);
	
	if (ret == RET_SUCCESS) {
        printf("[INFO] Password successfully generated.\n");
        printf("The generated password is %s\n", pwd);
    }
    free(pwd);
	return ret;
}

//ECALL to create a new wallet, this function does not validate if the wallet already exists, this should be done before calling this function
int ecall_create_wallet(const char* master_password) {
	return create_wallet(master_password);
}

//ECALL to show the wallet
int ecall_show_wallet(const char* master_password) {
	return show_wallet(master_password);
}

//ECALL to add an item to the wallet
int ecall_add_item(const char* master_password, const char* title, const char* username, const char* password) {
	item_t* new_item = (item_t*)malloc(sizeof(item_t));
	strcpy(new_item->title, title);
    strcpy(new_item->username, username);
    strcpy(new_item->password, password);
	return add_item(master_password, new_item, sizeof(item_t));
}

//ECALL to remove an item from wallet
int ecall_remove_item(const char* master_password, const int index) {
	return remove_item(master_password, index);
}