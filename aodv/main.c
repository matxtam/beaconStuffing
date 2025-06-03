#include "../bcstf/bcstf.h"
#include <string.h>  // for memset, strlen
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <stdbool.h>

struct send_arg {
	bcstf_handle *handle;
	char name[6];
};

enum msg_type {
	RREQ,
	RREP
};

struct msg {
	enum msg_type type;
	char from[6];
	char to[6];
};

void *msg2buf(struct msg *m){
	void *buf = malloc(sizeof(struct msg));
	if (!buf) return NULL;
	memcpy(buf, m, sizeof(struct msg));
	return buf;
}

struct msg *buf2msg(void *buf) {
	struct msg *m = malloc(sizeof(struct msg));
	if (!m) return NULL;
	memcpy(m, buf, sizeof(struct msg));
	return m;
}

void *send_t(void *_arg){
	struct send_arg *arg = (struct send_arg *)_arg;
	char dest[7];

	while(true){
		// read a string
		scanf("%6s", dest);
		
		// convert the string to msg buffer
		struct msg *m = malloc(sizeof(struct msg));
		m->type = RREQ;
		memcpy(m->from, arg->name, 6);
		memcpy(m->to, dest, 6);
		void *buf = msg2buf(m);

		// send the msg
		printf("send RREQ\n");
		bcstf_send(arg->handle, (unsigned char *)buf, sizeof(struct msg), 3, 200*1000);
	}
}

void callback(unsigned char *recv, size_t recv_len, bcstf_info info, unsigned char *user){
	// printf("Receive from ssid: \"%s\"\n", info.ssid);
	if(strcmp(info.ssid, "test") == 0){
		printf("Receive a ");
		struct msg *m = buf2msg(recv);
		if(m->type == RREQ)printf("RREQ: ");
		if(m->type == RREP)printf("RREP: ");
		printf("\n\tfrom: %s", m->from);
		printf("\n\tto: %s", m->to);

		// discard RREQ
		// resend RREQ
		// send RREP

		for(int i=0; i<recv_len; i++){
			printf("%02x ", recv[i]);
		}
	}
}



int main(int argc, char *argv[]) {
	// turn argv into int
	if (argc != 2) {
		fprintf(stderr, "Usage: %s <name>\n", argv[0]);
		return 1;
	}

	char name[7];
	strncpy(name, argv[1], 6);
	name[6] = '\0';

	const char *device = "wlan1";
	const char *ssid = "test";
	bcstf_handle *handle = bcstf_create_handle(device, ssid);
	if(handle == NULL){
		printf("initialization error\n");
		return 1;
	}

	struct send_arg *arg = malloc(sizeof(struct send_arg));
	arg->handle = handle;
	memcpy(arg->name, name, 6);
	
	pthread_t send_thread;
	pthread_create(&send_thread, NULL, send_t, (void *)arg);

	bcstf_recv(handle, -1, callback, NULL);
	bcstf_close(handle);
}
