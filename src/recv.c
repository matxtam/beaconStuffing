#include "../bcstf/bcstf.h"
#include <string.h>

void callback(unsigned char *recv, size_t recv_len, bcstf_info info, unsigned char *user){
	if(strcmp(info.ssid, "test") == 0){
		printf("receive length: %zu\ndata: ", recv_len);
		for(int i=0; i<recv_len; i++){
			printf("%02x ", recv[i]);
		}
	}
}

int main() {
	const char *device = "wlan1";
	const char *ssid = "test";
	bcstf_handle handle = bcstf_create_handle(device, ssid);
	bcstf_recv(&handle, 10, callback, NULL);
	bcstf_close(&handle);
}
