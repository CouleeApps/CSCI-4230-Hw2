//
// Created by Glenn Smith on 10/11/18.
//

#ifndef CRYPTO2_UTIL_H
#define CRYPTO2_UTIL_H

#include <functional>
#include <random>

struct on_scope_exit {
	typedef std::function<void()> exit_fn;
	exit_fn fn;

	explicit on_scope_exit(exit_fn fn) : fn(fn) {}
	~on_scope_exit() {
		fn();
	}
};

uint64_t rand_u64() {
	std::uniform_int_distribution<uint64_t> distribution;
	std::random_device rd;
	std::mt19937_64 generator{rd()};
	return distribution(generator);
}

#endif //CRYPTO2_UTIL_H
