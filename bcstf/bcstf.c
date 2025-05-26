#include "bcstf.h"

#include <pcap.h>
#include <libwifi.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <malloc.h>

#include <unistd.h>             // close
#include <sys/socket.h>         // socket
#include <sys/ioctl.h>          // ioctl
#include <net/if.h>             // struct ifreq, IFNAMSIZ
#include <linux/if_packet.h>    // AF_PACKET, ETH_P_ALL
#include <netinet/ether.h>      // ETH_P_ALL
#include <arpa/inet.h>          // htons

#define	MAX_TAG_LEN 255

typedef struct {
	void (*callback)(unsigned char *, size_t, unsigned char *);
	unsigned char * user;
} recv_callbacks;
int get_if_mac(const char *ifname, unsigned char mac[6]);
void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet);
 
int get_if_mac(const char *ifname, unsigned char mac[6]) {
	// int sock = socket(AF_INET,SOCK_DGRAM,0);
	struct ifreq ifr;
	int sock;
       	sock = socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
	if(sock < 0){
		perror("socket");
		return -1;
	}

	memset(&ifr,0,sizeof(ifr));
	strncpy(ifr.ifr_name, "wlan1", IFNAMSIZ-1);

	if((ioctl(sock, SIOCGIFHWADDR, &ifr)) < 0){
		perror("ioctl");
		close(sock);
		return -1;
	}

	printf("Mac= %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",
			(unsigned char)(ifr.ifr_hwaddr.sa_data[0]),
			(unsigned char)(ifr.ifr_hwaddr.sa_data[1]),
			(unsigned char)(ifr.ifr_hwaddr.sa_data[2]),
			(unsigned char)(ifr.ifr_hwaddr.sa_data[3]),
			(unsigned char)(ifr.ifr_hwaddr.sa_data[4]),
			(unsigned char)(ifr.ifr_hwaddr.sa_data[5]));

	close(sock);
	memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
	return 0;
}



bcstf_handle *bcstf_create_handle(const char *device, const char *ssid){

	bcstf_handle *ret = malloc(sizeof(bcstf_handle));

	// open a pcap handle
	char errbuf[PCAP_ERRBUF_SIZE] = {1};
	pcap_t *handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "error opening device %s: %s\n", device, errbuf);
		return NULL;
	}
	ret->pcaphandle = handle;

	// check datalink type
	int dlt = pcap_datalink(handle);
	int has_rtap = 0;
	printf("Data Link Type: %s\n", pcap_datalink_val_to_name(dlt));
	if (dlt == DLT_IEEE802_11_RADIO) has_rtap = 1;
	else if (dlt == DLT_IEEE802_11) has_rtap = 0;
	else{
    fprintf(stderr, "Data Link Type not supported\n");
		return NULL;
  }

	// create beacon frame
	printf("Creating Beacon Frame...\n");

	// TX mac
	unsigned char mac_tx[6] = {0};
	if(get_if_mac(device, mac_tx) != 0){
		fprintf(stderr, "Cannot get mac\n");
		return NULL;
	}

	// RX mac (broadcast)
	unsigned char mac_rx[6] = "\xFF\xFF\xFF\xFF\xFF\xFF";

	// use libwifi to create wifi beacon
	struct libwifi_beacon beacon = {0};
	libwifi_create_beacon(&beacon, mac_rx, mac_tx, mac_tx, ssid, 1);

	// copy beacon frame into buffer
	size_t beacon_len = libwifi_get_beacon_length(&beacon);
	unsigned char *beaconbuff = malloc(beacon_len);
	if(beaconbuff == NULL){
		fprintf(stderr, "error allocate beacon buffer\n");
		return NULL;
	}
	memset(beaconbuff,0,beacon_len);
	libwifi_dump_beacon(&beacon, beaconbuff, beacon_len);

	if(has_rtap){
		// create radiotap (if we need it)
		struct libwifi_radiotap_info rtap_info = {0};
		rtap_info.present = 0x0000002e;     // Flags, Rate, Channel, dBm Ant Signal
		rtap_info.channel.flags = 0x00a0;   // CCK, 2.4GHz (for channel 1)
		rtap_info.channel.freq = 2412;      // Channel 1 (2.4GHz)
		rtap_info.flags = 0x0000;           // No flags
		rtap_info.rate = 1;                 // 1 Mbit
		rtap_info.rate_raw = rtap_info.rate * 2; // 500kb/s increments
		rtap_info.signal = -20;             // Signal strength in dBm

		char *rtap = malloc(LIBWIFI_MAX_RADIOTAP_LEN);
		if (rtap == NULL){
			fprintf(stderr, "error allocate rtap buffer\n");
			return NULL;
		}
		memset(rtap,0,LIBWIFI_MAX_RADIOTAP_LEN);
		
		int rtap_len = libwifi_create_radiotap(&rtap_info, rtap);
		if (rtap_len == -1) {
			 fprintf(stderr, "error generating radiotap header\n");
			 free(rtap);
			 free(beaconbuff);
			 return NULL;
		}

		// combine radiotap and beacon frame
		size_t frame_len = rtap_len + beacon_len;
		unsigned char *frame = malloc(frame_len);
		if (frame == NULL) {
			perror("malloc failed");
			free(rtap);
			free(beaconbuff);
			return NULL;
		}
		memcpy(frame, rtap, rtap_len);
		memcpy(frame + rtap_len, beaconbuff, beacon_len);
		ret->frame = frame;
		ret->frame_len = rtap_len + beacon_len;
		free(beaconbuff);
		free(rtap);

	} else {
		ret->frame = beaconbuff;
		ret->frame_len = beacon_len;
	}

	return ret;
}

void bcstf_send(bcstf_handle *handle, unsigned char *stuff, size_t stuff_len){

	// allocate new buffer
	size_t total_len = handle->frame_len + 2*(stuff_len/MAX_TAG_LEN + 1) + stuff_len;
	unsigned char *buffer = malloc(total_len);
	if(buffer == NULL){
		fprintf(stderr, "error allocate buffer");
		return false;
	}

	memcpy(buffer, handle->frame, handle->frame_len);
	size_t offset = handle->frame_len;

	// collect original frame + frame
	int i;
	for(i=stuff_len; i>MAX_TAG_LEN; i-=MAX_TAG_LEN){
		buffer[offset++] = 0xDD;
		buffer[offset++] = MAX_TAG_LEN;
		memcpy(buffer+offset, stuff+(stuff_len-i), MAX_TAG_LEN);
		offset += MAX_TAG_LEN;
	}
	if (i > 0){
		buffer[offset++] = 0xDD;
		buffer[offset++] = i;
		memcpy(buffer+offset, stuff+(stuff_len-i), i);
	}

	// send the packet
	if (pcap_sendpacket(handle->pcaphandle, buffer, total_len) != 0) {
		fprintf(stderr, "Error sending packet: %s\n", pcap_geterr(handle->pcaphandle));
		return false;
	}
	return true;
}


void packet_handler(u_char *pcap_user, const struct pcap_pkthdr *header, const u_char *packet) {
	recv_callbacks *ctx = (recv_callbacks *)pcap_user;

  unsigned long data_len = header->caplen;
	unsigned char *data = (unsigned char *) packet;

	struct libwifi_frame frame = {0};
	struct libwifi_bss bss = {0};

	int ret = libwifi_get_wifi_frame(&frame, data, data_len, 1);
	if (ret != 0) {
		return;
	}

	if (frame.frame_control.type == TYPE_MANAGEMENT && frame.frame_control.subtype == SUBTYPE_BEACON) {
	
	int ret = libwifi_parse_beacon(&bss, &frame);
		if (ret != 0) {
			printf("Failed to parse beacon: %d\n", ret);
			return;
		}

		// find stuffed item
		printf("ESSID: %s\n", bss.hidden ? "(hidden)" : bss.ssid);

		if (bss.tags.length) {

			// initialize iterator
			struct libwifi_tag_iterator it;
			if (libwifi_tag_iterator_init(&it, bss.tags.parameters, bss.tags.length) != 0) {
					printf("couldn't initialise tag iterator\n");
					return;
			}

			// record vender-specific tags (there may be many)
			struct libwifi_tag_iterator *vs_tags = calloc(bss.tags.length, sizeof(struct libwifi_tag_iterator));
			int vs_num = 0;
			size_t recv_len = 0;

			// iterate through all tags
			do {
				if(strcmp(bss.ssid, "test") == 0)
					printf("\ttag #%d (size: %d)\n", it.tag_header->tag_num, it.tag_header->tag_len);

				// if it is a vender-specific tag, print the information
				if(it.tag_header->tag_num == 221){
					int max_size = MAX_TAG_LEN;
					if (it.tag_header->tag_len < MAX_TAG_LEN) {
						max_size = it.tag_header->tag_len;
					}
					// printf("\t%d bytes: ", max_size);
					//for (size_t i = 0; i < max_size; i++) {
					//	printf("%02x ", it.tag_data[i]);
					//}
					//printf("\n");

					// record the vender-specific tag
					vs_tags[vs_num++] = it;
					recv_len += max_size;
				}
			} while (libwifi_tag_iterator_next(&it) != -1);

			// save the vender-specific tags into recv
			u_char *recv;
			recv = malloc(recv_len);
			if (recv == NULL) {
				perror("recv: malloc failed\n");
			}
			int i = 0;
			unsigned char *recv_ptr = recv;
			while (i < vs_num){
				memcpy(recv_ptr, vs_tags[i].tag_data, vs_tags[i].tag_header->tag_len);
				recv_ptr += vs_tags[i].tag_header->tag_len;
				i++;
			}

			if(strcmp(bss.ssid, "test") == 0)ctx->callback(recv, recv_len, ctx->user);

	} else {
		// no tag
		printf("No tag\n");
	}

	printf("\n\n");

	}


	libwifi_free_bss(&bss);
	libwifi_free_wifi_frame(&frame);
}

void bcstf_recv(
bcstf_handle *handle, 
int count, 
void (*callback)(unsigned char *, size_t, unsigned char *), 
unsigned char *user){
	// initialzie user
	recv_callbacks pcap_user = {
		.callback = callback,
		.user = user,
	};

	// start capturing
	if (pcap_loop(handle->pcaphandle, count, packet_handler, (u_char *)(&pcap_user)) < 0) {
		fprintf(stderr, "Error capturing: %s\n", pcap_geterr(handle->pcaphandle));
		return;
	}

}

void bcstf_close(bcstf_handle *handle){
	pcap_close(handle->pcaphandle);
	free(handle->frame);
}
