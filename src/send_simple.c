#include "../bcstf/bcstf.h"
#include <string.h>  // for strlen

int main() {
	const char *device = "wlan1";
	const char *ssid = "test";
	bcstf_handle handle = bcstf_create_handle(device, ssid);
	bcstf_send(&handle, "hello", strlen("hello"), 100, 200*1000);
}
