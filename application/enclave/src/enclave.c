#include <stdio.h>      /* vsprintf */
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <sgx_trts.h>
#include <sgx_tseal.h>


#include "../conf/enclave_config.h"
#include "../inc/enclave.h"
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

/*
* yetAnotherAtoiBecauseSgxNotFound
*	Converts @str into an integer and returns the value.
*	Returns 
*	the the converted value 
*	0 if the value is not valid
*/
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

/*
* get_random_int
*	Generates a random integer
*	Returns 
*	the generated integer
*/
int get_random_int( void ) {
    unsigned char rand_num[10];
    sgx_status_t rand_ret = sgx_read_rand(rand_num, sizeof(rand_num));
    return yetAnotherAtoiBecauseSgxNotFound(rand_num);
}

/*
* is_prime
*	Validates if integer @n is a prime number
*	Returns 
*	0 if @n is prime number
*	1 if @n is not a prime number
*/
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

/*
* generate_password
*	Generates a random password with size @p_length
*	Returns
*	ERR_PASSWORD_OUT_OF_RANGE - @p_length not between 8 and 100
*	RET_SUCCESS - SUCCESS RETURN
*/
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

/*
* get_pwd_char
* this math does not seem right
*/
char get_pwd_char(char *charlist, int len)
{
	return (charlist[(get_random_int() / (RAND_MAX / len))]);
}

/*
* seal_my_wallet
*	Seals the provided wallet
*	releases the memory allocated for @wallet
*	Returns
*	ERROR_SGX_FAILURE_SEAL - if it could not seal the data, releases the memory allocated for @sealed_buffer
*	RET_SUCCESS - SUCCESS RETURN
*/
int seal_my_wallet(wallet_t* wallet, uint32_t sealed_size, uint8_t *sealed_buffer)
{
    sgx_status_t ret = sgx_seal_data(0, NULL, sizeof(wallet_t), (uint8_t*)wallet, sealed_size, (sgx_sealed_data_t*)sealed_buffer);

    if (ret != SGX_SUCCESS) {
        return ERROR_SGX_FAILURE_SEAL;
    }
	return RET_SUCCESS;
}

/*
* unseal_my_wallet
*	Unseals the provided wallet
*	releases the memory allocated for @sealed_buffer
*	Returns
*	SGX_ERROR_FAILURE_UNSEAL - if it could not unseal the data, releases the memory allocated for @wallet
*	RET_SUCCESS - SUCCESS RETURN
*/
int unseal_my_wallet(wallet_t* wallet, uint32_t sealed_size, uint8_t *sealed_buffer)
{
    uint32_t out_len = sizeof(wallet_t);
    sgx_status_t ret = sgx_unseal_data((sgx_sealed_data_t*)sealed_buffer, NULL, NULL, (uint8_t*)wallet, &out_len);

    if (ret != SGX_SUCCESS) {
		return ERROR_SGX_FAILURE_UNSEAL;
	}

	return RET_SUCCESS;
}

/*
* save_wallet
*	Saves the wallet to a file
*	Returns
*	ERR_CANNOT_SAVE_WALLET - could not save the wallet to file
*	RET_SUCCESS - SUCCESS RETURN
*/
int save_wallet(wallet_t* wallet) {

	int ret;

	//create sealed size
	uint32_t sealed_size = sgx_calc_sealed_data_size(0, sizeof(wallet_t));
    if (sealed_size == UINT32_MAX) {
        return ERR_CANNOT_SAVE_WALLET;
	}

	//create sealed buffer
    uint8_t *sealed_buffer = (uint8_t*) malloc(sealed_size);
    if (!sealed_buffer) {
		free(sealed_buffer);
        return ERR_CANNOT_SAVE_WALLET;
	}

	ret = seal_my_wallet(wallet, sealed_size, sealed_buffer);

	if(ret == RET_SUCCESS) {
		//Send sealed data to untrusted app
		int retval;
		sgx_status_t status = ocall_save_wallet(&retval, sealed_buffer, sealed_size);
		if (status != SGX_SUCCESS) {
			ret = 1;
		} else {
			ret = retval;
		}
	}

	free(sealed_buffer);

	if (ret != 0) {
		return ERR_CANNOT_SAVE_WALLET;
	}
	return RET_SUCCESS;	
}

/*
* load_wallet
*	Loads the wallet from file
*	Returns
*	ERR_CANNOT_LOAD_WALLET - could not load the wallet to file
*	RET_SUCCESS - SUCCESS RETURN
*/
int load_wallet(wallet_t* wallet) {

	int ret;
	
	//create sealed size
	uint32_t sealed_size = sgx_calc_sealed_data_size(0, sizeof(wallet_t));
    if (sealed_size == UINT32_MAX) {
        return ERR_CANNOT_LOAD_WALLET;
	}

	uint8_t* sealed_buffer = (uint8_t*)malloc(sealed_size);

	// load wallet
	int retval;
	sgx_status_t status = ocall_load_wallet(&retval, sealed_buffer, sealed_size);
	if (status != SGX_SUCCESS || retval != 0) {
		free(sealed_buffer);
		return ERR_CANNOT_LOAD_WALLET;
	}

	//unseal wallet
	ret = unseal_my_wallet(wallet, sealed_size, sealed_buffer);
	free(sealed_buffer);
	return ret;
}

/*
* create_wallet
*	Creates a new wallet
*	Returns
*	ERR_PASSWORD_OUT_OF_RANGE - @p_length not between 8 and 100
*	ERR_CANNOT_SAVE_WALLET - could not save the wallet to file, failure to create wallet
*	RET_SUCCESS - SUCCESS RETURN
*/
int create_wallet(const char* master_password) {

	int ret;

	// check password policy
	if (strlen(master_password) < 8 || strlen(master_password)+1 > WALLET_MAX_ITEM_SIZE) {
		return ERR_PASSWORD_OUT_OF_RANGE;
	}

	// create new wallet
	wallet_t* wallet = (wallet_t*)malloc(sizeof(wallet_t));
	wallet->size = 0;
	strncpy(wallet->master_password, master_password, strlen(master_password)+1);

	//save wallet
	ret = save_wallet(wallet);
	free(wallet);
	return ret;
}

/*
* show_wallet
*	Prints the wallet to the console
*	Returns
*	ERR_PASSWORD_OUT_OF_RANGE - @p_length not between 8 and 100
*	ERR_CANNOT_LOAD_WALLET - could not load the wallet to file
*	RET_SUCCESS - SUCCESS RETURN
*/
int show_wallet(const char* master_password) {

	int ret;
	
	wallet_t* wallet = (wallet_t*)malloc(sizeof(wallet_t));
	ret = load_wallet(wallet);
	
	if (ret == RET_SUCCESS) {
		// verify master-password
		if (strcmp(wallet->master_password, master_password) != 0) {
			free(wallet);
			return ERR_WRONG_MASTER_PASSWORD;
		}

		printf("[INFO] eWallet successfully retrieved.\n");
		print_wallet(wallet);
	}

	free(wallet);
	return ret;
}

/*
* print_wallet
*	Prints the wallet to the console
*/
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

/*
* add_item
*	Adds an item to the wallet
*	Returns
*	ERR_ITEM_TOO_LONG - one or more @item parameter/s is/are too long
*	ERR_CANNOT_LOAD_WALLET - could not load the wallet to file
*	ERR_WRONG_MASTER_PASSWORD - if the wallet password does not have the same value as the password provided
*	ERR_WALLET_FULL - wallet is full, please delete an item from the wallet first
*	ERR_CANNOT_SAVE_WALLET - could not save the wallet to file
*	RET_SUCCESS - SUCCESS RETURN
*/
int add_item(const char* master_password, const item_t* item, const size_t item_size) {

	int ret;

	// check input length
	if (strlen(item->title)+1 > WALLET_MAX_ITEM_SIZE ||
		strlen(item->username)+1 > WALLET_MAX_ITEM_SIZE ||
		strlen(item->password)+1 > WALLET_MAX_ITEM_SIZE) {
		return ERR_ITEM_TOO_LONG;
    }

	wallet_t* wallet = (wallet_t*)malloc(sizeof(wallet_t));

	//load wallet
	ret = load_wallet(wallet);

	if(ret != RET_SUCCESS) {
		free(wallet);
		return ret;
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

	//save wallet
	ret = save_wallet(wallet);
	free(wallet);

	// exit
	return ret;
}

/*
* remove_item
*	Removes an item from the wallet
*	Returns
*	ERR_ITEM_DOES_NOT_EXIST - @index is not between 0 and 100 or it does not exist in the wallet;
*	ERR_CANNOT_LOAD_WALLET - could not load the wallet to file
*	ERR_WRONG_MASTER_PASSWORD - if the wallet password does not have the same value as the password provided
*	ERR_CANNOT_SAVE_WALLET - could not save the wallet to file
*	RET_SUCCESS - SUCCESS RETURN
*/
int remove_item(const char* master_password, const int index) {

	int ret;

	// check index bounds
	if (index < 0 || index >= WALLET_MAX_ITEMS) {
		return ERR_ITEM_DOES_NOT_EXIST;
	}

	wallet_t* wallet = (wallet_t*)malloc(sizeof(wallet_t));

	ret = load_wallet(wallet);

	if (ret != RET_SUCCESS) {
		free(wallet);
		return ret;
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

	//save wallet
	ret = save_wallet(wallet);
	free(wallet);

	// exit
	return ret;
}

/*
* change_master_password
*	Changes the master password of the wallet
*	Returns
*	ERR_PASSWORD_OUT_OF_RANGE - @p_length not between 8 and 100
*	ERR_CANNOT_LOAD_WALLET - could not load the wallet to file
*	ERR_WRONG_MASTER_PASSWORD - if the wallet password does not have the same value as the password provided
*	ERR_CANNOT_SAVE_WALLET - could not save the wallet to file
*	RET_SUCCESS - SUCCESS RETURN
*/
int change_master_password(const char* old_password, const char* new_password) {

	int ret;

	// check password policy
	if (strlen(new_password) < 8 || strlen(new_password)+1 > WALLET_MAX_ITEM_SIZE) {
		return ERR_PASSWORD_OUT_OF_RANGE;
	}

	
	wallet_t* wallet = (wallet_t*)malloc(sizeof(wallet_t));

	// load wallet
	ret = load_wallet(wallet);
	if (ret != RET_SUCCESS) {
		free(wallet);
		return ERR_CANNOT_LOAD_WALLET;
	}

	// verify master-password
	if (strcmp(wallet->master_password, old_password) != 0) {
		free(wallet);
		return ERR_WRONG_MASTER_PASSWORD;
	}

	// update password
	strncpy(wallet->master_password, new_password, strlen(new_password)+1);

	// save wallet
	ret = save_wallet(wallet);
	free(wallet);
	return ret;
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

	char* pwd = (char*)malloc(sizeof(char)*(p_length+1));
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
	if (title == NULL || username == NULL || password == NULL) {
		return ERR_ITEM_TOO_LONG;
	}

	item_t new_item;
	memset(&new_item, 0, sizeof(new_item));
	strncpy(new_item.title, title, WALLET_MAX_ITEM_SIZE - 1);
	strncpy(new_item.username, username, WALLET_MAX_ITEM_SIZE - 1);
	strncpy(new_item.password, password, WALLET_MAX_ITEM_SIZE - 1);

	return add_item(master_password, &new_item, sizeof(item_t));
}

//ECALL to remove an item from wallet
int ecall_remove_item(const char* master_password, const int index) {
	return remove_item(master_password, index);
}

int ecall_change_master_password(const char* old_password, const char* new_password) {
	return change_master_password(old_password, new_password);
}