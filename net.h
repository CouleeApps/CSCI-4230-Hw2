//
// Created by Glenn Smith on 10/11/18.
//

#ifndef CRYPTO2_NET_H
#define CRYPTO2_NET_H

#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include "charStream.h"

int get_server_sock(int bind_addr, short bind_port, int &sock, sockaddr_in &addr) {
	socklen_t len = sizeof(sockaddr_in);

	sock = socket(PF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		perror("tcp socket()");
		return -1;
	}

	addr.sin_family = PF_INET;
	addr.sin_addr.s_addr = htonl(bind_addr);
	addr.sin_port = htons(bind_port);
	if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("tcp bind()");
		return -1;
	}

	//Don't clog up the port
	int value = 1;
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const void *)&value , sizeof(int));

	listen(sock, 100);

	if (getsockname(sock, (sockaddr *)&addr, &len) < 0) {
		perror("getsockname()");
		return -1;
	}
	return 0;
}

int get_client_sock(const char *bind_addr, short bind_port, int &sock, sockaddr_in &addr) {
	socklen_t len = sizeof(sockaddr_in);

	sock = socket(PF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		perror("tcp socket()");
		return -1;
	}

	addr.sin_family = PF_INET;
	inet_pton(AF_INET, bind_addr, &addr.sin_addr);
	addr.sin_port = htons(bind_port);
	if (connect(sock, (sockaddr *)&addr, len) < 0) {
		perror("connect");
		return -1;
	}

	//Don't clog up the port
	int value = 1;
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const void *)&value , sizeof(int));

	if (getsockname(sock, (sockaddr *)&addr, &len) < 0) {
		perror("getsockname()");
		return -1;
	}

	return 0;
}

int send_stream(int sock, const CharStream &str) {
	if (send(sock, str.getBuffer().data(), str.size(), 0) < 0) {
		perror("send");
		return -1;
	}
	return 0;
}

int recv_stream(int sock, CharStream &str) {
	//What do we get?
	char buffer[1024];
	ssize_t nrecv = recv(sock, buffer, 1024, 0);
	if (nrecv < 0) {
		perror("recv");
		return -1;
	}

	str = CharStream((U8 *)buffer, nrecv);
	return 0;
}

#endif //CRYPTO2_NET_H
