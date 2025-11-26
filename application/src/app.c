#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <stdint.h>

#include <sgx_urts.h>
#include "sgx_utils.h"
#include "enclave_u.h"

#include "config.h"
#include "app.h"

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;


int main(int argc, char** argv) {

    int ret;
    sgx_status_t ret_enclave = SGX_ERROR_UNEXPECTED;
    
	/* Call sgx_create_enclave to initialize an enclave instance */
	/* Debug Support: set 2nd parameter to 1 */
	ret = sgx_create_enclave( ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL) ;
	if ( ret != SGX_SUCCESS ) {
		print_error_message( ret );
		return -1;
	}

    const char* options = ":hnp:c:sax:y:z:r:gl:";
    opterr=0; // prevent 'getopt' from printing err messages
    char err_message[100];
    int opt, stop=0;
    int h_flag=0, g_flag=0, s_flag=0, a_flag=0, n_flag=0;
    char *p_value=NULL, *l_value=NULL, *c_value=NULL, *x_value=NULL, *y_value=NULL, *z_value=NULL, *r_value=NULL;

    // read user input
    while ((opt = getopt(argc, argv, options)) != -1) {
        switch (opt) {
            // help
            case 'h':
                h_flag = 1;
                break;

            // generate random password
            case 'g':
                g_flag = 1;
                break;
            case 'l': // password's length
                l_value = optarg;
                break;

            // create new wallet
            case 'n':
                n_flag = 1;
                break;

            // master-password
            case 'p':
                p_value = optarg;
                break;

            // change master-password
            case 'c':
                c_value = optarg;
                break;

            // show wallet
            case 's':
                s_flag = 1;
                break;

            // add item
            case 'a': // add item flag
                a_flag = 1;
                break;
            case 'x': // item's title
                x_value = optarg;
                break;
            case 'y': // item's username
                y_value = optarg;
                break;
            case 'z': // item's password
                z_value = optarg;
                break;

            // remove item
            case 'r':
                r_value = optarg;
                break;

            // exceptions
            case '?':
                if (optopt == 'p' || optopt == 'c' || optopt == 'r' ||
                    optopt == 'x' || optopt == 'y' || optopt == 'z' ||
                    optopt == 'l') {
                    sprintf(err_message, "Option -%c requires an argument.", optopt);
                }
                else if (isprint(optopt)) {
                    sprintf(err_message, "Unknown option `-%c'.", optopt);
                }
                else {
                    sprintf(err_message, "Unknown option character `\\x%x'.",optopt);
                }
                stop = 1;
                printf("[ERROR] %s\n", err_message);
                printf("[ERROR] Program exiting\n.");
                break;

            default:
                stop = 1;
                printf("[ERROR] %s\n", err_message);
                printf("[ERROR] Program exiting\n.");

        }
    }

    // perform actions
    if (stop != 1) {
        // show help
        if (h_flag) {
            show_help();
        }

        // generate random password
        else if (g_flag) {

            int pwd_size = WALLET_MAX_ITEM_SIZE-1;

            if(l_value!=NULL) {
            	pwd_size = atoi(l_value) + 1;
            }

            int ret;
            sgx_status_t status = ecall_generate_password(global_eid, &ret, pwd_size);
            if (status != SGX_SUCCESS) {
                print_error_message(status);
                ret = -1;
            }

            if (is_error(ret)) {
            	printf("[ERROR] Failed to generate the password.\n");
            }
        }

        // create new wallet
        else if(p_value!=NULL && n_flag) {
            int ret_val;
            sgx_status_t status = ecall_create_wallet(global_eid, &ret_val, p_value);
            if (status != SGX_SUCCESS) {
                print_error_message(status);
                ret_val = -1;
            }
            ret = ret_val;
            if (is_error(ret)) {
            	printf("[ERROR] Failed to create new eWallet.\n");
            }
            else {
            	printf("[INFO] eWallet successfully created.\n");
            }
        }

        // change master-password
        /*else if (p_value!=NULL && c_value!=NULL) {
            ret = change_master_password(p_value, c_value);
            if (is_error(ret)) {
            	printf("[ERROR] Failed to change master-password.\n");
            }
            else {
            	printf("[INFO] Master-password successfully changed.\n");
            }
        }*/

        // show wallet
        else if(p_value!=NULL && s_flag) {
            ret = ecall_show_wallet(p_value);
            if (is_error(ret)) {
            	printf("[ERROR] Failed to retrieve eWallet.\n");
            }
        }

        // add item
        else if (p_value!=NULL && a_flag && x_value!=NULL && y_value!=NULL && z_value!=NULL) {
            ret = ecall_add_item(p_value, x_value, y_value, z_value);
            if (is_error(ret)) {
            	printf("[ERROR] Failed to add new item to the eWallet.\n");
            }
            else {
            	printf("[INFO] Item successfully added to the eWallet.\n");
            }
        }

        // remove item
        else if (p_value!=NULL && r_value!=NULL) {
            char* p_end;
            int index = (int)strtol(r_value, &p_end, 10);
            if (r_value == p_end) {
            	printf("[ERROR] Option -r requires an integer argument.\n");
            }
            else {
            	ret = ecall_remove_item(p_value, index);
                if (is_error(ret)) {
                	printf("[ERROR] Failed to remove item from the eWallet.\n");
                }
                else {
                	printf("[INFO] Item successfully removed from the eWallet.\n");
                }
            }
        }

        // display help
        else {
            printf("[ERROR] Wrong inputs.\n");
            show_help();
        }
    }
    
    /* Destroy the enclave */
	sgx_destroy_enclave( global_eid );
    return 0;
}

//prints a help message, no need for an enclave since no secure data is at risk
void show_help() {
	const char* command = "[-h] [-g [-l password-length]] [-p master-password -n] " \
		"[-p master-password -c new-master-password] [-p master-password -s]" \
		"[-p master-password -a -x item-title -y item-username -z item-password] " \
		"[-p master-password -r item-index]";
	printf("\nUsage: %s %s\n\n", APP_NAME, command);
}

int create_wallet(const char* master_password) {

	int ret;

	// abort if wallet already exist
	ret = is_wallet();
	if (ret == 0) {
		return ERR_WALLET_ALREADY_EXISTS;
	}

	// create new wallet
    return ecall_create_wallet(master_password);
}

int show_wallet(const char* master_password, wallet_t* wallet, size_t wallet_size) {

	int ret;

	// load wallet
	ret = load_wallet(wallet, sizeof(wallet_t));
	if (ret != 0) {
		return ERR_CANNOT_LOAD_WALLET;
	}

	// verify master-password
	if (strcmp(wallet->master_password, master_password) != 0) {
		return ERR_WRONG_MASTER_PASSWORD;
	}

	return RET_SUCCESS;
}

/*int change_master_password(const char* old_password, const char* new_password) {

	int ret;

	// check password policy
	if (strlen(new_password) < 8 || strlen(new_password)+1 > WALLET_MAX_ITEM_SIZE) {
		return ERR_PASSWORD_OUT_OF_RANGE;
	}

	// load wallet
	wallet_t* wallet = (wallet_t*)malloc(sizeof(wallet_t));
	ret = load_wallet(wallet, sizeof(wallet_t));
	if (ret != 0) {
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
	ret = save_wallet(wallet, sizeof(wallet_t));
	free(wallet);
	if (ret != 0) {
		return ERR_CANNOT_SAVE_WALLET;
	}

	return RET_SUCCESS;
}*/

int is_wallet(void) {
    FILE *fp = fopen(WALLET_FILE, "r");
    if (fp == NULL ){
        return 1;
    }
    fclose(fp);
    return 0;
}

int ocall_save_wallet(const uint8_t *data, const uint32_t size)
{
    FILE *fp = fopen(WALLET_FILE, "w");
    if (fp == NULL ){
        return 1;
	}
    fwrite (data, size, 1, fp);
	fclose(fp);
	return 0;
}

int ocall_load_wallet(const uint8_t *data, const uint32_t size) {
    FILE *fp = fopen(WALLET_FILE, "r");
    if (fp == NULL ){
        return 1;
    }
    fread(data, size, 1, fp);
    fclose(fp);
    return 0;
}

/* OCall functions */
void ocall_print_string( const char *str )
{
	/* Proxy/Bridge will check the length and null-terminate 
	 * the input string to prevent buffer overflow. 
	 */
	printf( "%s", str );
}

//no sensitive information is displayed and so it is not needed to in sgx
//prints error messages based on the error code
int is_error(int error_code) {
    char err_message[100];

    // check error case
    switch(error_code) {
        case RET_SUCCESS:
            return 0;

        case ERR_PASSWORD_OUT_OF_RANGE:
            sprintf(err_message, "Password should be at least 8 characters long and at most %d characters long.", WALLET_MAX_ITEM_SIZE);
            break;

        case ERR_WALLET_ALREADY_EXISTS:
            sprintf(err_message, "The eWallet already exists: delete file '%s' first.", WALLET_FILE);
            break;

        case ERR_CANNOT_SAVE_WALLET:
            strcpy(err_message, "Could not save eWallet.");
            break;

        case ERR_CANNOT_LOAD_WALLET:
            strcpy(err_message, "Could not load eWallet.");
            break;

        case ERR_WRONG_MASTER_PASSWORD:
            strcpy(err_message, "Wrong master password.");
            break;

        case ERR_WALLET_FULL:
            sprintf(err_message, "eWallet full (maximum number of items is %d).", WALLET_MAX_ITEMS);
            break;

        case ERR_ITEM_DOES_NOT_EXIST:
            strcpy(err_message, "Item does not exist.");
            break;

        case ERR_ITEM_TOO_LONG:
            sprintf(err_message, "Item too long (maximum size: %d).", WALLET_MAX_ITEM_SIZE);
            break;

        default:
            sprintf(err_message, "Unknown error.");
    }

    // print error message
    printf("[ERROR] %s\n", err_message);
    return 1;
}
