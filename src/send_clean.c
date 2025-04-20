/* To run this program:
 *
 * gcc send_packet_raw_atxta.c -o send.o
 * sudo ./send.o
 *
 * Author: matxtam
 * Inspired by: Subodh Saxena 
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
#include<netinet/in.h>
#include<netinet/ip.h>
#include<netinet/if_ether.h>
#include<netinet/udp.h>

#include<linux/if_packet.h>

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

/*int main()
{
	// for pcap
	pcap_t *handle = NULL;
	char errbuf[PCAP_ERRBUF_SIZE] = {0};
    	FILE *pcapfile = NULL;
   	pcapfile = fopen("beacon.pcap", "w+");
        if ((handle = pcap_open_dead(DLT_IEEE802_11, BUFSIZ)) == NULL) {
            fprintf(stderr, "[!] Error opening dead capture (%s)\n", errbuf);
            exit(EXIT_FAILURE);
        }
        if ((filedumper = pcap_dump_fopen(handle, pcapfile)) == NULL) {
            fprintf(stderr, "[!] Error opening file %s (%s)\n", "beacon.pcap", errbuf);
            exit(EXIT_FAILURE);
        }

	// open raw socket
	// family, type, protocol
	// sock_raw=socket(AF_PACKET,SOCK_RAW,IPPROTO_RAW);
	printf("Creating socket...");
	sock_raw=socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
	if(sock_raw == -1)
		printf("error in socket");
	get_eth_data();
	// open socket
	struct sockaddr_ll sadr_ll;
	sadr_ll.sll_family = AF_PACKET;  // added
	sadr_ll.sll_protocol = htons(ETH_P_ALL); // added
	sadr_ll.sll_ifindex = ifreq_i.ifr_ifindex;
	sadr_ll.sll_halen   = ETH_ALEN;
	
	create_beacon();

	size_t buf_len = libwifi_get_beacon_length(&beacon);
	sendbuff=(unsigned char*)malloc(buf_len);
	if (sendbuff == NULL)
		printf("error allocate buffer");
	memset(sendbuff,0,buf_len);
	libwifi_dump_beacon(&beacon, sendbuff, buf_len);

	printf("checking packet...\n");
	check_beacon(sendbuff, buf_len);
	for(int i=0; i<buf_len; i++){
		printf("%c", sendbuff[i]);
	}
	printf("\n");

	printf("[*] Writing Beacon Frame to pcap\n");
    	struct pcap_pkthdr pkt_hdr = {0};
    	struct timeval tv = {0};
    	pkt_hdr.caplen = buf_len;
    	pkt_hdr.len = buf_len;
    	gettimeofday(&tv, NULL);
    	pkt_hdr.ts = tv;
    	pcap_dump((unsigned char *) filedumper, &pkt_hdr, sendbuff);
	pcap_dump_close(filedumper);
    	pcap_close(handle);

	printf("sending packets...\n");
	while (1){
		
		usleep(500 * 1000);
		int send_len = sendto(
				sock_raw, // sockfd: file discriptor of the sending socket
				sendbuff, // buf: message content
				buf_len,       // message length
				0,        // flags
				(const struct sockaddr*)&sadr_ll, // destination address
				sizeof(struct sockaddr_ll)        // size of destination address
		);
		if(send_len<0) {
			printf("error in sending...sendlen=%d, errno=%d\n",send_len,errno);
			return -1;
		}
		// printf(".\n");

	}
	return 0;

}*/

int main()
{

	struct libwifi_beacon beacon = {0};
	create_beacon(&beacon);

	size_t buf_len = libwifi_get_beacon_length(&beacon);

	unsigned char *sendbuff;
	sendbuff=(unsigned char*)malloc(buf_len);
	if (sendbuff == NULL){
		printf("error allocate buffer");
	}
	memset(sendbuff,0,buf_len);
	libwifi_dump_beacon(&beacon, sendbuff, buf_len);

	printf("checking packet...\n");
	check_beacon(sendbuff, buf_len);

	for(int i=0; i<buf_len; i++){
		printf("%c", sendbuff[i]);
	}
	printf("\n");


	// opening a handle
	printf("sending packets...\n");
	pcap_t *handle = NULL;
	char errbuf[PCAP_ERRBUF_SIZE] = {0};
    	handle = pcap_open_live(ifn, BUFSIZ, 1, 1000, errbuf);

	// check datalink type
	int dlt = pcap_datalink(handle);
	printf("Data Link Type: %s\n", pcap_datalink_val_to_name(dlt));

	if (handle == NULL) {
		fprintf(stderr, "Error opening device %s: %s\n", ifn, errbuf);
		return -1;
	}
	while (1){
		if (pcap_sendpacket(handle, sendbuff, buf_len) != 0) {
			fprintf(stderr, "Error sending packet: %s\n", pcap_geterr(handle));
			return -1;
		}
		
		usleep(200 * 1000);

	}
    	pcap_close(handle);
	return 0;

}
