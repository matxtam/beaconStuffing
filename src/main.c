#include "bcstf.h"
#include <string.h>  // for memset, strlen
#include <unistd.h>  // for usleep

int main() {
	const char *device = "wlan1";
	const char *ssid = "test";
	bcstf_handle handle = bcstf_create_handle(device, ssid);
	int i = 1451;
	char str[i+1]; 
	memset(str, 'a', i);
	str[i] = '\0';
	printf("string length = %lu\n", strlen(str));
	for (int j=0; j<100; j++){
		bcstf_send(&handle, (unsigned char *)str, strlen(str));
		usleep(200 * 1000);
	}
}
