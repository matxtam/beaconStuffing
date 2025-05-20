#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcap/pcap.h>
#include <libwifi.h>

#define FILTER "type mgt subtype beacon"

int packets;
static unsigned long packet_num = 0;
const char *ifn = "wlan1";
int count = 10;
int has_radiotap;
static struct bpf_program *filter;
pcap_t *handle;

void packet_handler(u_char *, const struct pcap_pkthdr *, const u_char *);
void parse_beacon(struct libwifi_frame, unsigned char *, const struct pcap_pkthdr *, const unsigned char *);
void parse_radiotap(const struct libwifi_frame *);
void find_stuffed_beacon(struct libwifi_bss *);
void print_bss_info(struct libwifi_bss *);
void print_tag_info(unsigned char *, size_t );

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	++packet_num;
  unsigned long data_len = header->caplen;
	unsigned char *data = (unsigned char *) packet;

	struct libwifi_frame frame = {0};

	int ret = libwifi_get_wifi_frame(&frame, data, data_len, has_radiotap);
	if (ret != 0) {
		return;
	}

	// parse_radiotap(&frame);
	parse_beacon(frame, args, header, packet);

	libwifi_free_wifi_frame(&frame);
}

void parse_beacon(struct libwifi_frame frame, unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet) {
	struct libwifi_bss bss = {0};
	if (frame.frame_control.type == TYPE_MANAGEMENT && frame.frame_control.subtype == SUBTYPE_BEACON) {
		printf("Packet : %lu\n", packet_num);
		int ret = libwifi_parse_beacon(&bss, &frame);
		if (ret != 0) {
			printf("Failed to parse beacon: %d\n", ret);
			pcap_dump(args, header, packet);
			return;
		}

		// print_bss_info(&bss);
		find_stuffed_beacon(&bss);
	}
	libwifi_free_bss(&bss);
}

void find_stuffed_beacon(struct libwifi_bss *bss) {
	if (bss == NULL) {
			return;
	}

	printf("ESSID: %s\n", bss->hidden ? "(hidden)" : bss->ssid);

	if (bss->tags.length) {
		printf("Tagged Parameters:\n");
		struct libwifi_tag_iterator it;
		if (libwifi_tag_iterator_init(&it, bss->tags.parameters, bss->tags.length) != 0) {
				printf("couldn't initialise tag iterator\n");
				return;
		}
		do {
			printf("\ttag: %d (size: %d)\n", it.tag_header->tag_num, it.tag_header->tag_len);

			int max_size = 16;
			if (it.tag_header->tag_len < 16) {
				max_size = it.tag_header->tag_len;
			}
			printf("\t%d bytes of tag data: ", max_size);
			for (size_t i = 0; i < max_size; i++) {
				printf("%02x ", it.tag_data[i]);
			}
			printf("\n");
		} while (libwifi_tag_iterator_next(&it) != -1);

	} else {
			printf("Tagged Parameters: None\n");
	}

	printf("\n\n");
}



void print_bss_info(struct libwifi_bss *bss) {
    if (bss == NULL) {
        return;
    }

    printf("=== BSS Parsing ===\n");
    printf("ESSID: %s\n", bss->hidden ? "(hidden)" : bss->ssid);
    printf("BSSID: " MACSTR "\n", MAC2STR(bss->bssid));
    printf("Receiver: " MACSTR "\n", MAC2STR(bss->receiver));
    printf("Transmitter: " MACSTR "\n", MAC2STR(bss->transmitter));
    printf("Channel: %d\n", bss->channel);
    printf("WPS: %s\n", bss->wps ? "yes" : "no");

    char sec_buf[LIBWIFI_SECURITY_BUF_LEN];

    libwifi_get_security_type(bss, sec_buf);
    printf("Encryption: %s\n", sec_buf);

    libwifi_get_group_ciphers(bss, sec_buf);
    printf("\tGroup Ciphers: %s\n", sec_buf);

    libwifi_get_pairwise_ciphers(bss, sec_buf);
    printf("\tPairwise Ciphers: %s\n", sec_buf);

    libwifi_get_auth_key_suites(bss, sec_buf);
    printf("\tAuth Key Suites: %s\n", sec_buf);

    if (bss->rsn_info.rsn_capabilities & LIBWIFI_RSN_CAPAB_MFP_CAPABLE) {
        printf("\tMFP Capable: Yes\n");
    }
    if (bss->rsn_info.rsn_capabilities & LIBWIFI_RSN_CAPAB_MFP_REQUIRED) {
        printf("\tMFP Required: Yes\n");
    }

    if (bss->tags.length) {
        printf("Tagged Parameters:\n");
        print_tag_info(bss->tags.parameters, bss->tags.length);
    } else {
        printf("Tagged Parameters: None\n");
    }

    printf("=== BSS End ===\n");
    printf("\n\n");
}

void print_tag_info(unsigned char *data, size_t data_len) {
    struct libwifi_tag_iterator it;
    if (libwifi_tag_iterator_init(&it, data, data_len) != 0) {
        printf("Couldn't initialise tag iterator\n");
        return;
    }
    do {
        printf("\tTag: %d (Size: %d)\n", it.tag_header->tag_num, it.tag_header->tag_len);

        int max_size = 16;
        if (it.tag_header->tag_len < 16) {
            max_size = it.tag_header->tag_len;
        }
        printf("\t%d bytes of Tag Data: ", max_size);
        for (size_t i = 0; i < max_size; i++) {
            printf("%02x ", it.tag_data[i]);
        }
        printf("\n");
    } while (libwifi_tag_iterator_next(&it) != -1);
}

void parse_radiotap(const struct libwifi_frame *frame) {
    const struct libwifi_radiotap_info *rtap_info = frame->radiotap_info;

    printf("=== Radiotap Parsing ===\n");
    printf("Radiotap Channel Freq: %d MHz\n", rtap_info->channel.freq);
    printf("Radiotap Freq Band: ");
    if (rtap_info->channel.band & LIBWIFI_RADIOTAP_BAND_2GHZ) {
        printf("2.4 GHz\n");
    } else if (rtap_info->channel.band & LIBWIFI_RADIOTAP_BAND_5GHZ) {
        printf("5 GHz\n");
    } else if (rtap_info->channel.band & LIBWIFI_RADIOTAP_BAND_6GHZ) {
        printf("6 GHz\n");
    } else {
        printf("Unknown Band\n");
    }
    printf("Radiotap Channel: %d\n", rtap_info->channel.center);
    printf("Radiotap Channel Flags: 0x%04x\n", rtap_info->channel.flags);
    printf("Radiotap Rate: %.2f Mb/s\n", rtap_info->rate);
    printf("Radiotap Rate Raw: 0x%02x\n", rtap_info->rate_raw);
    printf("Radiotap Signal: %d dBm\n", rtap_info->signal);
    for (int i = 0; i < rtap_info->antenna_count; i++) {
        printf("Radiotap Antenna %d: %d dBm\n", rtap_info->antennas[i].antenna_number, rtap_info->antennas[i].signal);
    }
    printf("Radiotap Flags: 0x%04x\n", rtap_info->flags);
    printf("Radiotap Extended Flags: 0x%08x\n", rtap_info->extended_flags);
    printf("Radiotap RX Flags: 0x%04x\n", rtap_info->rx_flags);
    printf("Radiotap TX Flags: 0x%04x\n", rtap_info->tx_flags);
    printf("Radiotap TX Power: %d\n", rtap_info->tx_power);
    printf("Radiotap RTS Retries: %d\n", rtap_info->rts_retries);
    printf("Radiotap Data Retries: %d\n", rtap_info->data_retries);
    printf("=== Radiotap End ===\n");
}

int main(){
	packet_num = 0;

	// open a pcap handle
	char errbuf[PCAP_ERRBUF_SIZE] = {0};
	pcap_t *handle = pcap_open_live(ifn, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Error opening device %s: %s\n", ifn, errbuf);
		return -1;
	}

	// check datalink type
	int linktype = pcap_datalink(handle);
	if (linktype == DLT_IEEE802_11_RADIO) {
		has_radiotap = 1;
	} else if (linktype == DLT_IEEE802_11) {
		has_radiotap = 0;
	} else {
		fprintf(stderr, "802.11 and radiotap headers not provided (%d)\n", pcap_datalink(handle));
		pcap_close(handle);
		exit(EXIT_FAILURE);
	}

	// apply filter
	if ((filter = malloc(sizeof(struct bpf_program))) == NULL) {
		perror("Malloc failure");
		pcap_close(handle);
		exit(EXIT_FAILURE);
	}
	printf("[*] Compiling and optimizing frame filter, this can take a second\n");
	if (pcap_compile(handle, filter, FILTER, 0, 0) != 0) {
		fprintf(stderr, "[!] Couldn't compile filter: %s\n", pcap_geterr(handle));
		pcap_close(handle);
		free(filter);
		exit(EXIT_FAILURE);
	}
	if (pcap_setfilter(handle, filter) != 0) {
		fprintf(stderr, "[!] Couldn't set filter: %s\n", pcap_geterr(handle));
		pcap_close(handle);
		free(filter);
		exit(EXIT_FAILURE);
	}

	// start capturing
	if (pcap_loop(handle, count, packet_handler, (u_char *)NULL) < 0) {
		fprintf(stderr, "Error capturing: %s\n", pcap_geterr(handle));
		return -1;
	}

}


