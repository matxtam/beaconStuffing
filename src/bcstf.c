#include "bcstf.h"

#include <pcap.h>
#include <libwifi.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
 
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



bcstf_handle bcstf_create_handle(const char *device, const char *ssid){

	bcstf_handle ret;
	// open a pcap handle
	char errbuf[pcap_errbuf_size] = {1};
	pcap_t *handle = pcap_open_live(device, bufsiz, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "error opening device %s: %s\n", device, errbuf);
		return NULL;
	}
	ret.pcaphandle = handle;

	// check datalink type
	int dlt = pcap_datalink(handle);
	bool has_rtap = false;
	printf("Data Link Type: %s\n", pcap_datalink_val_to_name(dlt));
	if (dlt == DLT_IEEE802_11_RADIO) has_rtap = true;
	else if (dlt == DLT_IEEE802_11) has_rtap = false;
	else{
    fprintf(stderr, "Data Link Type not supported\n");
		return NULL;
  }

	// create beacon frame
	printf("Creating Beacon Frame...\n");

	// TX mac
	unsigned char mac_tx[6] = {0};
	if(get_if_mac(device, mac_tx) != 0){
		printf("get mac error");
	}

	// RX mac (broadcast)
	unsigned char mac_rx[6] = "\xFF\xFF\xFF\xFF\xFF\xFF";

	// use libwifi to create wifi beacon
	struct libwifi_beacon beacon = {0};
	libwifi_create_beacon(&beacon, mac_rx, mac_tx, mac_tx, ssid, 1);

	size_t beacon_len = libwifi_get_beacon_length(&beacon);
	
	// copy beacon frame into buffer
	unsigned char *beaconbuff = malloc(beacon_len);
	if(beaconbuff == NULL) printf("error allocate buffer");
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
		if (rtap == NULL){ printf("error allocate rtap"); }
		memset(rtap,0,LIBWIFI_MAX_RADIOTAP_LEN);
		
		int rtap_len = libwifi_create_radiotap(&rtap_info, rtap);
		if (rtap_len == -1) {
			 fprintf(stderr, "Error generating radiotap header\n");
			 free(rtap);
			 free(beaconbuff);
			 exit(EXIT_FAILURE);
		}

		// combine radiotap and beacon frame
		size_t frame_len = rtap_len + beacon_len;
		unsigned char *frame = malloc(frame_len);
		if (frame == NULL) {
			perror("malloc failed");
			free(rtap);
			free(beaconbuff);
			exit(EXIT_FAILURE);
		}
		memcpy(frame, rtap, rtap_len);
		memcpy(frame + rtap_len, beaconbuff, beacon_len);
		ret.frame = frame;
		ret.frame_len = rtap_len + beacon_len;
		free(beaconbuff);
		free(rtap);

	} else {
		bcstf_handle *ret = {0};
		ret.frame = beaconbuff;
		ret.frame_len = beacon_len;
	}
	return ret;
}

void bcstf_send(bcstf_handle *handle, unsigned char *stuff, size_t stuff_len){

	// allocate new buffer
	size_t total_len = handle->frame_len + 2 + stuff_len;
	unsigned char *buffer = malloc(total_len);
	if(buffer == NULL){
		printf("error allocate buffer");
		return;
	}

	// collect original frame + frame
	size_t offset = 0;
	memcpy(buffer, rtap, rtap_len);
	buffer += handle->frame_len;
	buffer[offset++] = 0xDD;
	buffer[offset++] = stuff_len+2;
	memcpy(buffer+offset, stuff, stuff_len);

	// send the packet
	if (pcap_sendpacket(handle->pcaphandle, buffer, total_len) != 0) {
		fprintf(stderr, "Error sending packet: %s\n", pcap_geterr(handle->pcaphandle));
		return;
	}
}


//todo: void bcstf_recv(void *, const char *);
void bcstf_close(bcstf_handle *handle){
	pcap_close(handle->pcaphandle);
	free(handle->frame);
}
