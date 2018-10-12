//
// Created by Glenn Smith on 10/11/18.
//

#ifndef CRYPTO2_UTIL_H
#define CRYPTO2_UTIL_H

#include <functional>
#include <random>
#include <sys/time.h>

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

uint64_t current_timestamp() {
	return static_cast<uint64_t>(time(nullptr));
}

bool is_valid_timestamp(uint64_t timestamp) {
	//10 seconds is the valid window
	time_t current = time(nullptr);
	return current < timestamp + 10;
}

#endif //CRYPTO2_UTIL_H
