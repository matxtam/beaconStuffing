#include "../bcstf/bcstf.h"
#include <string.h>  // for memset, strlen
#include <unistd.h>  // for usleep
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
	if (argc != 2) {
		fprintf(stderr, "Usage: %s <length>\n", argv[0]);
		return 1;
	}

	int i = atoi(argv[1]);
	if (i <= 0 || i > 2048) {
		fprintf(stderr, "Invalid length: %d (must be between 1 and 2048)\n", i);
		return 1;
	}

	const char *device = "wlan1";
	const char *ssid = "test";
	bcstf_handle handle = bcstf_create_handle(device, ssid);

	char str[i+1];
	memset(str, 'a', i);
	str[i] = '\0';
	printf("string length = %lu\n", strlen(str));
	for (int j=0; j<100; j++){
		bcstf_send(&handle, (unsigned char *)str, strlen(str));
		usleep(200 * 1000);
	}
}
