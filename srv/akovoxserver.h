#ifndef AKOVOXSERVER_H
#define AKOVOXSERVER_H

#include <arpa/inet.h>
#include <cstring>

typedef uint32_t id_t;

enum __attribute__((__packed__)) header_type {
	HDR_FULL_DATA = 1,
	HDR_SHORT_DATA = 2,
};

struct __attribute__((__packed__)) header {
	uint8_t null[8];
	id_t id;
	in_addr_t dip;
	in_port_t dport;
	uint16_t page_no;
	header_type type;
	uint8_t flags;    // 1 == not last page
};

struct __attribute__((__packed__)) udp_peer {
	uint64_t valid_until; // unixtime ms in GMT+0
	id_t id;
	in_addr_t ip;
	in_port_t port;
};

void hton_peer(const udp_peer * const host, udp_peer * const network) {
	network->valid_until = htobe64(host->valid_until);
	network->id = htobe32(host->id);
	network->ip = host->ip;
	network->port = host->port;
}

void ntoh_peer(const udp_peer * const network, udp_peer * const host) {
	host->valid_until = be64toh(network->valid_until);
	host->id = be32toh(network->id);
	host->ip = network->ip;
	host->port = network->port;
}

enum __attribute__((__packed__)) request_type {
	REQ_LOGIN = 0,
	REQ_KEEP_ALIVE = 1,
	REQ_REQ_IDS = 2,
};

struct __attribute__((__packed__)) request {
	uint8_t null[8];       // padding
	uint64_t valid_until;  // unixtime ms in GMT+0
	uint32_t salt;         // some random u32
	id_t requestor_id;     // id of a sender, ignored for login
	uint16_t vsize;        // signature length - 1
	request_type req_type; // payload type
};

void hton_request(request * const host, request * const network) {
	memcpy(host->null, network->null, 8);
	network->valid_until = htobe64(host->valid_until);
	network->salt = htobe32(host->salt);
	network->requestor_id = htobe32(host->requestor_id);
	network->vsize = htons(host->vsize);
	network->req_type = host->req_type;
}

void ntoh_request(request * const network, request * const host) {
	memcpy(network->null, host->null, 8);
	host->valid_until = be64toh(network->valid_until);
	host->salt = be32toh(network->salt);
	host->requestor_id = be32toh(network->requestor_id);
	host->vsize = ntohs(network->vsize);
	host->req_type = network->req_type;
}

// payload type 0
struct __attribute__((__packed__)) login_data {
	uint16_t csize;        // encryption PK length - 1
	uint16_t ssize;        // signing PK length - 1
	uint16_t nsize;        // name length - 1
	unsigned char tail[0]; // binary data: sig PK, crypt PK, name, signature in exactly that order tightly packed
};

// payload type 1
struct __attribute__((__packed__)) keep_alive {
	unsigned char signature[0];
};

// payload type 2
struct __attribute__((__packed__)) request_ids {
	uint8_t size;          // amount of ids
	unsigned char tail[0]; // binary data: [size] ids, then signature in exactly that order tightly packed
};

#endif
