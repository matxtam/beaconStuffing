#include "bcstf.h"
#include <unistd.h>

int main() {
	const char *device = "wlan1";
	const char *ssid = "test";
	bcstf_handle handle = bcstf_create_handle(device, ssid);
	while(1) {
		bcstf_send(&handle, "hello", sizeof("hello"));
		usleep(200 * 1000);
/*
	char str[101]; 
	memset(str, 'a', 100);
	str[100] = '\0';
	printf("%s\n", str);
	return 0;
	*/
	}
}
