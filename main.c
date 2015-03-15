// This program tests the library trivium.h

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>

#include "trivium.h"

#define BUFLEN 	10000000

// Struct for time value
struct timeval t1, t2;

uint8_t buf[BUFLEN];
uint8_t out1[BUFLEN];
uint8_t out2[BUFLEN];
uint8_t key[10];
uint8_t iv[10];

static void
time_start(void)
{
	gettimeofday(&t1, NULL);
}

static uint32_t
time_stop(void)
{
	gettimeofday(&t2, NULL);

	t2.tv_sec -= t1.tv_sec;
	t2.tv_usec -= t1.tv_usec;

	if(t2.tv_usec < 0) {
		t2.tv_sec--;
		t2.tv_usec += 1000000;
	}

	return (t2.tv_sec * 1000 + t2.tv_usec/1000);
}

int
main(void)
{
	struct trivium_context *ctx;

	memset(buf, 'q', sizeof(buf));
	memset(key, 'k', sizeof(key));
	memset(iv, 'i', sizeof(iv));

	time_start();

	if((ctx = trivium_context_new()) == NULL) {
		printf("Memory allocation error!\n");
		exit(1);
	}
	
	if(trivium_set_key_and_iv(ctx, (uint8_t *)key, 10, iv, 10)) {
		printf("Trivium context filling error!\n");
		exit(1);
	}

	trivium_encrypt(ctx, buf, BUFLEN, out1);

	if(trivium_set_key_and_iv(ctx, (uint8_t *)key, 10, iv, 10)) {
		printf("Trivium context filling error!\n");
		exit(1);
	}

	trivium_encrypt(ctx, out1, BUFLEN, out2);

	trivium_context_free(&ctx);

	printf("Run time = %d\n\n", time_stop());

	return 0;
}

