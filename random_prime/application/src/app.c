#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <time.h>

#include "app.h"

/* Application entry */
int main( int argc, char *argv[] )
{
	(void)(argc);
	(void)(argv);

	// Use current time as seed for initializing the random generator
	srand( (unsigned int) time(NULL) );

	int p = 0;
	int n;

	do {
		n = get_random_int();
		p = is_prime( n );
		printf("%d is%s a prime number.\n", n, (p == 0) ? "n't" : "" );
	} while( p != 1 );

	return 0;
}

int get_random_int( void ) {
	return rand();
}

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
