//
// Created by Glenn Smith on 10/10/18.
//

#include <stdlib.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <vector>
#include <errno.h>
#include "net.h"
#include "charStream.h"
#include "needham-schroeder.h"
#include "diffie-hellman.h"
#include "util.h"

#define KDC_PORT 12345

struct client {
	int sock;
	sockaddr_in addr;
	std::bitset<10> key;
};

int main(int argc, const char **argv) {
	short server_port = KDC_PORT;
	sockaddr_in server_addr{};
	int server_sock;

	if (get_server_sock(INADDR_ANY, server_port, server_sock, server_addr) < 0) {
		return EXIT_FAILURE;
	}

	on_scope_exit server_sock_closer{[server_sock]() {
		close(server_sock);
	}};

	dh_key server_key{};
	server_key.x = static_cast<uint16_t>(rand_u64() % global_dh.q);
	server_key.y = exp_mod_16(global_dh.alpha, server_key.x, global_dh.q);

	std::vector<client> clients;

	while (true) {
		fd_set fds;
		int max_fd = server_sock;
		FD_ZERO(&fds);
		FD_SET(server_sock, &fds);

		for (auto client : clients) {
			FD_SET(client.sock, &fds);
			if (client.sock > max_fd) {
				max_fd = client.sock;
			}
		}

		if (select(max_fd + 1, &fds, nullptr, nullptr, nullptr) < 0) {
			perror("select");
			if (errno == EINTR) {
				continue;
			} else {
				break;
			}
		}

		if (FD_ISSET(server_sock, &fds)) {
			//New connection
			client c;
			socklen_t len = sizeof(sockaddr_in);
			c.sock = accept(server_sock, (sockaddr *)&c.addr, &len);
			if (c.sock < 0) {
				perror("accept");
				if (errno == EINTR) {
					continue;
				} else {
					break;
				}
			}

			CharStream str;
			str.push<U8>(0);
			str.push<U16>(server_key.y);
			if (send_stream(c.sock, str) < 0) {
				if (errno == EINTR) {
					continue;
				} else {
					break;
				}
			}

			clients.push_back(c);
		}

		for (auto it = clients.begin(); it != clients.end(); ) {
			client &client_a = *it;
			if (FD_ISSET(client_a.sock, &fds)) {
				//That sock read some data
				char buffer[1024];
				ssize_t nrecv = recv(client_a.sock, buffer, 1024, 0);
				if (nrecv < 0) {
					perror("recv");
					if (errno == EINTR) {
						continue;
					} else {
						goto done;
					}
				}
				if (nrecv == 0) {
					//They disconnected
					printf("Disconnect: %s:%d\n", inet_ntoa(client_a.addr.sin_addr), ntohs(client_a.addr.sin_port));
					close(client_a.sock);
					it = clients.erase(it);
					continue;
				}

				CharStream cs((U8 *)buffer, nrecv);
				U8 cmd = cs.pop<U8>();

				if (cmd == 0) {
					//Copy the correct listening port for this client
					sockaddr_in addr = cs.pop<ID>();
					client_a.addr.sin_port = addr.sin_port;

					//Generate and register session key
					uint16_t pub_key = cs.pop<U16>();
					uint16_t session_key = exp_mod_16(pub_key, server_key.x, global_dh.q);
					client_a.key = std::bitset<10>{static_cast<uint64_t>(session_key)};

					printf("Client %s:%d registers with pubkey %d\n", inet_ntoa(client_a.addr.sin_addr),
					       ntohs(client_a.addr.sin_port), static_cast<int>(pub_key));
				} else if (cmd == 1) {
					NS1 ns1 = cs.pop<NS1>();

					printf("Client %s:%d requesting info for %s:%d\n",
					       inet_ntoa(client_a.addr.sin_addr),
					       ntohs(client_a.addr.sin_port), inet_ntoa(ns1.id_b.sin_addr),
					       ntohs(ns1.id_b.sin_port));
					//Better try to get them their NS2

					for (auto client_b : clients) {
						if (client_b.addr.sin_addr.s_addr == ns1.id_b.sin_addr.s_addr &&
						    client_b.addr.sin_port == ns1.id_b.sin_port) {
							//Here we go
							NS2 ns2;
							ns2.nonce_1 = ns1.nonce_1;
							ns2.id_b = ns1.id_b;
							ns2.session_key = std::bitset<10>(rand_u64());
							ns2.timestamp = current_timestamp();

							NS3 ns3;
							ns3.session_key = ns2.session_key;
							ns3.id_a = ns1.id_a;
							ns3.timestamp = current_timestamp();

							ns2.encrypt_ns3 = encrypt<NS3>(ns3, client_b.key);

							encrypt_buf encrypt_ns2 = encrypt<NS2>(ns2, client_a.key);

							CharStream resp;
							resp.push<U8>(2);
							resp.push<encrypt_buf>(encrypt_ns2);

							if (send_stream(client_a.sock, resp) < 0) {
								if (errno != EINTR) {
									goto done;
								}
							}
							break;
						}
					}
				}
			}
			++it;
		}
	}

done:
	return 0;
}