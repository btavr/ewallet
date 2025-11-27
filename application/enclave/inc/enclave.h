#ifndef _ENCLAVE_H_
#define _ENCLAVE_H_

#include "../conf/enclave_config.h"
#include "stddef.h" //to validate if secure

#define RET_SUCCESS 0
#define ERR_PASSWORD_OUT_OF_RANGE 1
#define ERR_WALLET_ALREADY_EXISTS 2
#define ERR_CANNOT_SAVE_WALLET 3
#define ERR_CANNOT_LOAD_WALLET 4
#define ERR_WRONG_MASTER_PASSWORD 5
#define ERR_WALLET_FULL 6
#define ERR_ITEM_DOES_NOT_EXIST 7
#define ERR_ITEM_TOO_LONG 8

#define SGX_ERROR_INVALID_PARAMETER  11
#define ERROR_SGX_FAILURE_SEAL  12
#define ERROR_SGX_FAILURE_UNSEAL  13



#define	RAND_MAX 2147483647 /* The largest number rand will return (same as INT_MAX)  */
#define UINT32_MAX 4294967295U
#define ALPHA_SIZE 26
#define NUM_SIZE 10
#define SYM_SIZE 21



static char numbers[] = "1234567890";
static char letter[]  = "abcdefghijklmnoqprstuvwyzx";
static char letterr[] = "ABCDEFGHIJKLMNOQPRSTUYWVZX";
static char symbols[] = "!@#$%^&*(){}[]:<>?,./";

// item
struct Item {
	char  title[WALLET_MAX_ITEM_SIZE];
	char  username[WALLET_MAX_ITEM_SIZE];
	char  password[WALLET_MAX_ITEM_SIZE];
};
typedef struct Item item_t;

// wallet
struct Wallet {
	item_t items[WALLET_MAX_ITEMS];
	size_t size;
	char master_password[WALLET_MAX_ITEM_SIZE];
};
typedef struct Wallet wallet_t;


int printf( const char *fmt, ... );
int yetAnotherAtoiBecauseSgxNotFound(char *str);
int get_random_int( void );
int is_prime( int n );
int generate_password(char *p_value, int p_length);
char get_pwd_char(char *charlist, int len);
int seal_my_wallet(wallet_t* wallet, uint32_t sealed_size, uint8_t *sealed_buffer);
int unseal_my_wallet(wallet_t* wallet, uint32_t sealed_size, uint8_t *sealed_buffer);
int save_wallet(wallet_t* wallet);
int load_wallet(wallet_t* wallet);
int create_wallet(const char* master_password);
int show_wallet(const char* master_password);
void print_wallet(const wallet_t* wallet);
int add_item(const char* master_password, const item_t* item, const size_t item_size);
int remove_item(const char* master_password, const int index);
int change_master_password(const char* old_password, const char* new_password);

#endif /* !_ENCLAVE_H_ */
