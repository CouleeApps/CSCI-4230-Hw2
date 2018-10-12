//
// Created by Glenn Smith on 10/11/18.
//

#ifndef CRYPTO2_DIFFIE_HELLMAN_H
#define CRYPTO2_DIFFIE_HELLMAN_H

#include <stdint.h>
#include "util.h"

struct dh {
	uint16_t q;
	uint16_t alpha;

	dh(uint16_t q, uint16_t alpha) : q(q), alpha(alpha) {}
};

//Global params are hard coded for JUSTICE
dh global_dh{15373, 129};

struct dh_key {
	uint16_t x; //Private key
	uint16_t y; //Public key
};

//x^n mod q
uint16_t exp_mod_16(uint16_t x, uint16_t n, uint16_t q) {
	//This is pretty awful but again, just needs to work
	uint64_t result = 1;
	for (uint64_t i = 0; i < n; i ++) {
		result *= x;
		result %= q;
	}
	return static_cast<uint16_t>(result);
}

#endif //CRYPTO2_DIFFIE_HELLMAN_H
