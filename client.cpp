//
// Created by Glenn Smith on 10/10/18.
//

#include <stdint.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include "needham-schroeder.h"
#include "net.h"

#define KDC_ADDR "127.0.0.1"
#define KDC_PORT 12345

int ns_starter(sockaddr_in server_addr, int client_sock, std::bitset<10> key);
int ns_receiver(int server_sock, std::bitset<10> key);

int main(int argc, const char **argv) {
	sockaddr_in server_addr{};
	int server_sock;
	if (get_server_sock(INADDR_ANY, 0, server_sock, server_addr) < 0) {
		return EXIT_FAILURE;
	}

	autoclose_sock server_sock_closer{server_sock};

	srand(time(NULL));
	std::bitset<10> key{static_cast<U64>(rand())};

	//Send that off to the key server
	int client_sock;
	sockaddr_in client_addr;
	if (get_client_sock(KDC_ADDR, KDC_PORT, client_sock, client_addr) < 0) {
		return EXIT_FAILURE;
	}

	autoclose_sock client_sock_closer{client_sock};

	//Register ourselves immediately
	{
		//TODO: Diffie-Hellman
		CharStream str;
		str.push<U8>(0); //Register
		str.push<ID>(server_addr);
		str.push<10>(key);
		if (send_stream(client_sock, str) < 0) {
			return EXIT_FAILURE;
		}
	}

	while (true) {
		fd_set fds;
		FD_ZERO(&fds);
		FD_SET(fileno(stdin), &fds);
		FD_SET(server_sock, &fds);
		int max_fd = std::max(fileno(stdin), server_sock);

		//Being fun and writing only one client... either reads from stdin or from the socket
		if (select(max_fd + 1, &fds, NULL, NULL, NULL) < 0) {
			perror("select");
			if (errno == EINTR) {
				continue;
			} else {
				break;
			}
		}

		if (FD_ISSET(fileno(stdin), &fds)) {
			//We're going to be sending out the start of the handshake
			int ns_status = ns_starter(server_addr, client_sock, key);
			if (ns_status < 0) {
				if (errno != EINTR) {
					break;
				}
			} else if (ns_status == 0) {
				printf("NS handshake success\n");
			} else if (ns_status > 0) {
				printf("Error with NS handshake\n");
			}
		} else if (FD_ISSET(server_sock, &fds)) {
			//Receiving a handshake on our socket
			int ns_status = ns_receiver(server_sock, key);
			if (ns_status < 0) {
				if (errno != EINTR) {
					break;
				}
			} else if (ns_status == 0) {
				printf("NS handshake success\n");
			} else if (ns_status > 0) {
				printf("Error with NS handshake\n");
			}
		}
	}

	return 0;
}

int ns_starter(sockaddr_in server_addr, int client_sock, std::bitset<10> key) {
	char addr[128];
	short port;
	fscanf(stdin, "%s %hd", addr, &port);

	NS1 ns1{};
	ns1.id_a = server_addr;
	inet_pton(AF_INET, addr, &ns1.id_b.sin_addr);
	ns1.id_b.sin_port = htons(port);
	ns1.nonce_1 = static_cast<uint8_t>(rand());

	{
		CharStream str;
		str.push<U8>(1);
		str.push(ns1);

		if (send_stream(client_sock, str) < 0) {
			return -1;
		}
	}

	//Expect a NS2 message back
	CharStream resp;
	if (recv_stream(client_sock, resp) < 0) {
		return -1;
	}
	if (resp.pop<U8>() != 2) {
		printf("Did not get a NS2 response\n");
		return 1;
	}
	encrypt_buf buf = resp.pop<encrypt_buf>();

	NS2 ns2 = decrypt<NS2>(buf, key);
	if (ns1.nonce_1 != ns2.nonce_1) {
		printf("Nonce mismatch\n");
		return 1;
	}

	std::bitset<10> session_key = ns2.session_key;
	printf("Got session key: %d\n", session_key.to_ullong());

	//Now we gotta talk to b
	int b_sock;
	sockaddr_in b_addr;
	if (get_client_sock(inet_ntoa(ns2.id_b.sin_addr), ntohs(ns2.id_b.sin_port),
	                    b_sock, b_addr) < 0) {
		return -1;
	}

	//To cleanup the b socket when we're done with it
	autoclose_sock b_sock_closer{b_sock};

	{
		CharStream str;
		str.push<U8>(3);
		str.push<encrypt_buf>(ns2.encrypt_ns3);

		if (send_stream(b_sock, str) < 0) {
			return -1;
		}
	}

	//Await NS4 response
	CharStream resp2;
	if (recv_stream(b_sock, resp2) < 0) {
		return -1;
	}

	if (resp2.pop<U8>() != 4) {
		printf("Did not get a NS4 response\n");
		return 1;
	}
	encrypt_buf encrypt_ns4 = resp2.pop<encrypt_buf>();
	NS4 ns4 = decrypt<NS4>(encrypt_ns4, session_key);

	printf("Established connection, got NS4 nonce: %d\n", ns4.nonce_2);

	NS5 ns5;
	ns5.f_nonce_2 = nonce_2_fn(ns4.nonce_2);

	encrypt_buf encrypt_ns5 = encrypt<NS5>(ns5, session_key);
	{
		CharStream str;
		str.push<U8>(5);
		str.push<encrypt_buf>(encrypt_ns5);

		if (send_stream(b_sock, str) < 0) {
			return -1;
		}
	}

	//Encrypted communication happens here???
	return 0;
}

int ns_receiver(int server_sock, std::bitset<10> key) {
	socklen_t len = sizeof(sockaddr_in);
	sockaddr_in a_addr;
	int a_sock = accept(server_sock, (sockaddr *)&a_addr, &len);
	if (a_sock < 0) {
		perror("accept");
		return -1;
	}

	//To clean up the socket when we're done with it
	autoclose_sock a_sock_closer{a_sock};

	CharStream str;
	if (recv_stream(a_sock, str) < 0) {
		return -1;
	}

	U8 cmd = str.pop<U8>();
	if (cmd != 3) {
		printf("Did not get a NS3 response\n");
		return 1;
	}

	encrypt_buf encrypt_ns3 = str.pop<encrypt_buf>();
	NS3 ns3 = decrypt<NS3>(encrypt_ns3, key);
	std::bitset<10> session_key = ns3.session_key;

	printf("Got session key: %d\n", session_key.to_ullong());

	//Better send an NS4
	NS4 ns4;
	ns4.nonce_2 = rand();
	printf("Send NS4 nonce: %d\n", ns4.nonce_2);
	encrypt_buf encrypt_ns4 = encrypt<NS4>(ns4, session_key);

	CharStream resp;
	resp.push<U8>(4);
	resp.push<encrypt_buf>(encrypt_ns4);
	if (send_stream(a_sock, resp) < 0) {
		return -1;
	}

	//Expecting a NS5
	CharStream str2;
	if (recv_stream(a_sock, str2) < 0) {
		return -1;
	}

	cmd = str2.pop<U8>();
	if (cmd != 5) {
		printf("Did not get a NS5 response\n");
		return 1;
	}

	encrypt_buf encrypt_ns5 = str2.pop<encrypt_buf>();
	NS5 ns5 = decrypt<NS5>(encrypt_ns5, session_key);

	if (ns5.f_nonce_2 != nonce_2_fn(ns4.nonce_2)) {
		printf("f(nonce2) mismatch!\n");
		return 1;
	}
	printf("Established connection, NS5 f(nonce2) match!\n");

	//Encrypted communication happens here???
	return 0;
}
