//
// Created by Glenn Smith on 10/10/18.
//

#ifndef CRYPTO2_NEEDHAM_SCHROEDER_H
#define CRYPTO2_NEEDHAM_SCHROEDER_H

#include <arpa/inet.h>
#include <bitset>
#include "des.h"
#include "charStream.h"

typedef struct sockaddr_in ID;
typedef std::vector<U8> encrypt_buf;

struct NS1 {
	ID id_a;
	ID id_b;
	uint8_t nonce_1;
};

struct NS2 {
	std::bitset<10> session_key;
	ID id_b;
	uint8_t nonce_1;
	encrypt_buf encrypt_ns3;
};

struct NS3 {
	std::bitset<10> session_key;
	ID id_a;
};

struct NS4 {
	uint8_t nonce_2;
};

struct NS5 {
	uint8_t f_nonce_2;
};

uint8_t nonce_2_fn(uint8_t nonce_2) {
	return ~nonce_2;
}

template<>
encrypt_buf CharStream::push(const encrypt_buf &value) {
	push<uint16_t>(value.size());
	for (U8 byte : value) {
		push<uint8_t>(byte);
	}
	return value;
}

template<>
encrypt_buf CharStream::pop() {
	encrypt_buf value;
	uint16_t size = pop<uint16_t>();
	value.reserve(size);
	for (int i = 0; i < size; i ++) {
		value.push_back(pop<uint8_t>());
	}
	return value;
}

template<>
NS1 CharStream::push(const NS1 &value) {
	push<sockaddr_in>(value.id_a);
	push<sockaddr_in>(value.id_b);
	push<uint8_t>(value.nonce_1);
	return value;
}

template<>
NS1 CharStream::pop() {
	NS1 value{};
	value.id_a = pop<sockaddr_in>();
	value.id_b = pop<sockaddr_in>();
	value.nonce_1 = pop<uint8_t>();
	return value;
}

template<>
NS2 CharStream::push(const NS2 &value) {
	push<10>(value.session_key);
	push<ID>(value.id_b);
	push<uint8_t>(value.nonce_1);
	push<encrypt_buf>(value.encrypt_ns3);
	return value;
}

template<>
NS2 CharStream::pop() {
	NS2 value{};
	value.session_key = pop<10>();
	value.id_b = pop<ID>();
	value.nonce_1 = pop<uint8_t>();
	value.encrypt_ns3 = pop<encrypt_buf>();
	return value;
}

template<>
NS3 CharStream::push(const NS3 &value) {
	push<10>(value.session_key);
	push<ID>(value.id_a);
	return value;
}

template<>
NS3 CharStream::pop() {
	NS3 value{};
	value.session_key = pop<10>();
	value.id_a = pop<ID>();
	return value;
}

template<>
NS4 CharStream::push(const NS4 &value) {
	push<uint8_t>(value.nonce_2);
	return value;
}

template<>
NS4 CharStream::pop() {
	NS4 value{};
	value.nonce_2 = pop<uint8_t>();
	return value;
}

template<>
NS5 CharStream::push(const NS5 &value) {
	push<uint8_t>(value.f_nonce_2);
	return value;
}

template<>
NS5 CharStream::pop() {
	NS5 value{};
	value.f_nonce_2 = pop<uint8_t>();
	return value;
}

template<typename T>
encrypt_buf encrypt(const T &thing, const std::bitset<10> &key) {
	CharStream str;
	str.push<T>(thing);

	std::vector<U8> bytes = str.getBuffer();
	encrypt_buf encrypted{};
	for (U8 byte : bytes) {
		encrypted.push_back(static_cast<U8>(des_encrypt(std::bitset<8>{byte}, key).to_ullong()));
	}

	return encrypted;
}

template<typename T>
T decrypt(const encrypt_buf &encrypted, const std::bitset<10> &key) {
	std::vector<U8> bytes;
	for (U8 byte : encrypted) {
		bytes.push_back(static_cast<U8>(des_decrypt(std::bitset<8>{byte}, key).to_ullong()));
	}

	CharStream str(bytes.data(), bytes.size());
	return str.pop<T>();
}

#endif //CRYPTO2_NEEDHAM_SCHROEDER_H
