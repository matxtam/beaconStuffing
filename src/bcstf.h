#ifndef BEACON_STUFFING
#define BEACON_STUFFING

#include <pcap.h>

typedef struct {
	unsigned char *frame;
	size_t frame_len;
	pcap_t *pcaphandle;
} bcstf_handle;

bcstf_handle bcstf_create_handle(const char *, const char *);
void bcstf_send(bcstf_handle *, unsigned char *, size_t);
void bcstf_recv(bcstf_handle *, int, unsigned char *);
void bcstf_close(bcstf_handle *);

#endif
