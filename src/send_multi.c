/* To run this program:
 *
 * gcc send_packet_raw_atxta.c -o send.o
 * sudo ./send.o
 *
 * Author: matxtam
 */

#include <libwifi.h>
#include <pcap.h>

#include <bits/types/struct_timeval.h>
#include <stddef.h>
#include <stdlib.h>

#include<stdio.h>
#include<string.h>
#include<malloc.h>
#include<errno.h>
#include <sys/time.h> // for pcap?

#include<sys/socket.h>
#include<sys/types.h>
#include<sys/ioctl.h>

#include<net/if.h>
#include<arpa/inet.h>

#include<unistd.h>

const char *ifn = "wlan1";

pcap_dumper_t *filedumper = NULL;
 
int get_if_index(const char *ifname) {
	int sock = socket(AF_INET,SOCK_DGRAM,0);
	if(sock < 0){
		perror("socket");
		return -1;
	}

	struct ifreq ifr;
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

	if((ioctl(sock, SIOCGIFINDEX, &ifr)) < 0){
		perror("ioctl");
		close(sock);
		return -1;
	}

	close(sock);
	printf("index = %d\n",ifr.ifr_ifindex);
	return ifr.ifr_ifindex;
}

 
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


void create_beacon(struct libwifi_beacon *refbeacon) {
	printf("Creating Beacon Frame...\n");

	// TX mac
	unsigned char mac_tx[6] = {0};
	if(get_if_mac(ifn, mac_tx) != 0){
		printf("get mac error");
	}

	// RX mac
	unsigned char mac_rx[6] = "\xFF\xFF\xFF\xFF\xFF\xFF";

	// use libwifi to create wifi beacon
	libwifi_create_beacon(refbeacon, mac_rx, mac_tx, mac_tx, "libwifi-beacon", 1);
	libwifi_quick_add_tag(&(refbeacon->tags), TAG_VENDOR_SPECIFIC,
			(unsigned char *) "libwifi-tag", strlen("libwifi-tag"));

}

void check_beacon(const unsigned char *packet, int len) {
	// print packet content
	printf("checking packet...\n");
	printf("packet content:");
	for(int i=0; i<len; i++){
			printf("%c", packet[i]);
		}
	printf("\n");

    if (len < 24) {  // Minimum beacon frame size
        printf("Packet too short to be a beacon.\n");
        return;
    }

    // Check if it's a beacon frame
    if ((packet[0] & 0xFC) == 0x80) {
        printf("[+] This is a WiFi Beacon Frame.\n");

        // Extract BSSID (bytes 16-21)
        printf("BSSID: %02X:%02X:%02X:%02X:%02X:%02X\n",
               packet[16], packet[17], packet[18],
               packet[19], packet[20], packet[21]);

        // Extract SSID (after fixed parameters)
        int ssid_len = packet[37];  // SSID length
        if (ssid_len > 0 && ssid_len < 32) {  // Valid SSID length
            printf("SSID: ");
        for (int i=0; i<ssid_len; i++) {
                printf("%c", packet[38 + i]);
            }
            printf("\n");
        } else {
            printf("SSID: <Hidden>\n");
        }
    } else {
        printf("[-] This is NOT a beacon frame.\n");
    }
}

int main()
{

	// create beacon frame
	struct libwifi_beacon beacon = {0};
	create_beacon(&beacon);
	size_t buf_len = libwifi_get_beacon_length(&beacon);
	
	// copy beacon frame into buffer
	unsigned char *sendbuff = malloc(buf_len);
	if (sendbuff == NULL){ printf("error allocate buffer"); }
	memset(sendbuff,0,buf_len);
	libwifi_dump_beacon(&beacon, sendbuff, buf_len);

	// check packet
	check_beacon(sendbuff, buf_len);

	// create radiotap
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
		 free(sendbuff);
		 exit(EXIT_FAILURE);
	}

	// combine radiotap and beacon frame
	size_t total_len = rtap_len + buf_len;
	unsigned char *frame = malloc(total_len);
	if (frame == NULL) {
		perror("malloc failed");
		free(rtap);
		free(sendbuff);
		exit(EXIT_FAILURE);
	}
	memcpy(frame, rtap, rtap_len);
	memcpy(frame + rtap_len, sendbuff, buf_len);

	// open a pcap handle
	char errbuf[PCAP_ERRBUF_SIZE] = {0};
	pcap_t *handle = pcap_open_live(ifn, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Error opening device %s: %s\n", ifn, errbuf);
		return -1;
	}

	// check datalink type
	int dlt = pcap_datalink(handle);
	printf("Data Link Type: %s\n", pcap_datalink_val_to_name(dlt));
	if (dlt != DLT_IEEE802_11_RADIO) {
    fprintf(stderr, "Warning: Expected DLT_IEEE802_11_RADIO, got %s\n", pcap_datalink_val_to_name(dlt));
    }

	// send packet
	printf("sending packets on %s...\n", ifn);
	while (1){
		if (pcap_sendpacket(handle, frame, total_len) != 0) {
			fprintf(stderr, "Error sending packet: %s\n", pcap_geterr(handle));
			pcap_close(handle);
			free(rtap);
			free(sendbuff);
			free(frame);
			return -1;
		}
		
		usleep(200 * 1000);

	}

  pcap_close(handle);
	free(rtap);
	free(sendbuff);
	free(frame);
	
	return 0;
}
