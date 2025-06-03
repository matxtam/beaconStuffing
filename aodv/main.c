#include "../bcstf/bcstf.h"
#include <string.h>  // for memset, strlen
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <stdbool.h>
#define TABLE_LEN 10

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

struct entry {
	char from[6];
	char to[6];
};

struct callback_user {
	char name[6];
	bcstf_handle *handle;
};

struct entry table[TABLE_LEN] = {0};
int table_index = 0;

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

bool is_in_table(char *from, char*to){
	for (int i=0; i<table_index; i++){
		if((strcmp(from, table[i].from) == 0) && (strcmp(to, table[i].to) == 0)){
			return true;
		}
	}
	return false;
}

void table_insert(char *from, char *to){
	table_index++;
	if(table_index == TABLE_LEN){
		printf("table index exceed max len\n");
		return;
	}
	strcpy(table[table_index-1].from, from);
	strcpy(table[table_index-1].to, to);
}

void *send_t(void *_arg){
	struct send_arg *arg = (struct send_arg *)_arg;
	char dest[7];

	while(true){
		// read a string
		scanf("%6s", dest);
		
		if(strcmp(dest, arg->name) == 0){
			printf("destination = myself\n");
			continue;
		}
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

void callback(unsigned char *recv, size_t recv_len, bcstf_info info, unsigned char *_user){
	// printf("Receive from ssid: \"%s\"\n", info.ssid);
	struct callback_user *user = (struct callback_user*)_user;
	
	if(strcmp(info.ssid, "test") == 0){
		printf("Receive ");
		struct msg *m = buf2msg(recv);
		if(m->type == RREQ)printf("RREQ: ");
		if(m->type == RREP)printf("RREP: ");
		printf("\t%s -> %s", m->from, m->to);

		// ignore RREQ
		if(is_in_table(m->from, m->to)){
			printf("\tIgnore (recorded path)\n");
		} else if(strcmp(m->from, (const char *)user->name) == 0){
			printf("\tIgnore (origin is myself)\n");
		} else {
			table_insert(m->from, m->to);

			// prepare to send a message
			struct msg *ms = malloc(sizeof(struct msg));
			memcpy(ms->from, m->from, 6);
			memcpy(ms->to, m->to, 6);

			if(strcmp((const char *)user->name, m->to) == 0){
				// send RREP
				ms->type = RREP;
				void *buf = msg2buf(ms);
				printf("\tSend RREP\n");
				bcstf_send(user->handle, (unsigned char *)buf, sizeof(struct msg), 3, 200*1000);

			} else {
				// resend
				ms->type = m->type;
				void *buf = msg2buf(ms);
				printf("\tResend\n");
				bcstf_send(user->handle, (unsigned char *)buf, sizeof(struct msg), 3, 200*1000);
			}
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

	struct callback_user *user = malloc(sizeof(struct callback_user));
	user->handle = handle;
	strcpy(user->name, name);
	bcstf_recv(handle, -1, callback, (unsigned char*)user);
	bcstf_close(handle);
}
