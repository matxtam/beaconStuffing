#ifndef BEACON_STUFFING
#define BEACON_STUFFING

#include <pcap.h>
#include <stdbool.h>

typedef struct {
	unsigned char *frame;
	size_t frame_len;
	pcap_t *pcaphandle;
} bcstf_handle;

typedef struct {
	char ssid[33];
} bcstf_info;

bcstf_handle *bcstf_create_handle(const char *device, const char *ssid);

bool bcstf_send(bcstf_handle *handle, unsigned char *stuff, size_t stuff_len, int count, int interval_us);

bool bcstf_recv(bcstf_handle *handle, int count, void (*callback)(unsigned char *, size_t, bcstf_info, unsigned char *), unsigned char *user);

void bcstf_close(bcstf_handle *handle);

#endif
