#include <stdio.h>      /* vsprintf */
#include <stdarg.h>
#include <string.h>
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

	// save wallet
	ret = save_wallet(wallet, sizeof(wallet_t));
	free(wallet);
	if (ret != 0) {
		return ERR_CANNOT_SAVE_WALLET;
	}

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

