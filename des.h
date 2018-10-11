//
// Created by Glenn Smith on 10/10/18.
//

#ifndef CRYPTO2_DES_H
#define CRYPTO2_DES_H

#include <bitset>
#include <array>
#include <vector>

/**
 * Permute and optionally expand/contract a bitset using an array of permuted locations
 */
template<size_t input_size, size_t output_size = input_size>
std::bitset<output_size> permute(const std::bitset<input_size> &input, const std::array<int, output_size> &locations) {
	std::bitset<output_size> output;
	//For each bit in the output, find its corresponding bit in the input
	for (size_t i = 0; i < output_size; i ++) {
		output[i] = input[locations[i] - 1];
	}
	return output;
}

/**
 * Split one bitset into two smaller bitsets
 */
template<size_t full, size_t half = full / 2>
void split(const std::bitset<full> &input, std::bitset<half> &low, std::bitset<half> &high) {
	//First half move bits into the low output, second half goes into high output
	for (size_t i = 0; i < full; i ++) {
		if (i < half) {
			low[i] = input[i];
		} else {
			high[i - half] = input[i];
		}
	}
}

/**
 * Combine two bitsets into one larger bitset
 */
template<size_t half, size_t full = half * 2>
std::bitset<full> combine(const std::bitset<half> &low, const std::bitset<half> &high) {
	std::bitset<full> output;
	//First half of the output is the lower bits, second half is the upper bits
	for (size_t i = 0; i < full; i ++) {
		if (i < half) {
			output[i] = low[i];
		} else {
			output[i] = high[i - half];
		}
	}
	return output;
}

/**
 * Left shift all the bits in the input (with wrapping around)
 */
template<size_t size>
std::bitset<size> left_shift(const std::bitset<size> &input) {
	std::bitset<size> output = input;
	//This will clobber the high bit so make sure we pick it back up
	output <<= 1;
	output[0] = input[size - 1];
	return output;
}

/**
 * Swap two bitsets by reference
 */
template<size_t size>
void swap(std::bitset<size> &a, std::bitset<size> &b) {
	std::bitset<size> tmp = a;
	a = b;
	b = tmp;
}

/**
 * Evaluate an S-box specific to the F-function
 */
std::bitset<2> F_sbox(const std::bitset<4> &input, const std::array<std::array<int, 4>, 4> &matrix) {
	//Get column and row indices from the bits of the input
	int column = input[1] | (input[2] << 1);
	int row = input[0] | (input[3] << 1);
	//Output is the value in the S-box at that cell
	return matrix[column][row];
}

/**
 * Evaluates the "F" function as defined in the slides, containing permutations and S-boxes
 */
std::bitset<4> F_fn(const std::bitset<4> &input, const std::bitset<8> &key) {
	//Expansions / permutations
	std::array<int, 8> F_expansion = {{4, 1, 2, 3, 2, 3, 4, 1}};
	std::array<int, 4> P4 = {{2, 4, 3, 1}};

	//S-Boxes
	std::array<std::array<int, 4>, 4> S_0 = {{ {{1, 0, 3, 2}}, {{3, 2, 1, 0}}, {{0, 2, 1, 3}}, {{3, 1, 3, 2}} }};
	std::array<std::array<int, 4>, 4> S_1 = {{ {{0, 1, 2, 3}}, {{2, 0, 1, 3}}, {{3, 0, 1, 0}}, {{2, 1, 0, 3}} }};

	//Expand input to 8 bits and xor with the key
	std::bitset<8> expanded = permute(input, F_expansion);
	expanded ^= key;

	//Then split the expanded input into halves to run through the S-boxes
	std::bitset<4> low, high;
	split(expanded, low, high);

	//Run each side through its respective S-box
	std::bitset<2> low_subbed = F_sbox(low, S_0);
	std::bitset<2> high_subbed = F_sbox(high, S_1);

	//Then combine them together and permute the bits to get the result
	std::bitset<4> combined = combine(low_subbed, high_subbed);
	std::bitset<4> permuted = permute(combined, P4);
	return permuted;
}

/**
 * Subkey generation function, takes a 10-bit initial key and outputs to two 8-bit subkeys
 */
void generate_key(const std::bitset<10> &initial_key, std::bitset<8> &K1, std::bitset<8> &K2) {
	//Permutations as defined in the lecture slides
	std::array<int, 10> P10 = {{3, 5, 2, 7, 4, 10, 1, 9, 8, 6}};
	std::array<int, 8> P8 = {{6, 3, 7, 4, 8, 5, 10, 9}};

	//Initial permutation
	std::bitset<10> permuted_key = permute(initial_key, P10);

	//Split into high and low key bits
	std::bitset<5> klow, khigh;
	split(permuted_key, klow, khigh);

	//Then left shift both
	std::bitset<5> sklow_1 = left_shift(klow);
	std::bitset<5> skhigh_1 = left_shift(khigh);

	//Combine together and permute to generate K1
	std::bitset<10> key_combined_1 = combine(sklow_1, skhigh_1);
	K1 = permute(key_combined_1, P8);

	//Shift left both sets of bits again
	std::bitset<5> sklow_2 = left_shift(sklow_1);
	std::bitset<5> skhigh_2 = left_shift(skhigh_1);

	//Then combine and permute those to generate K2
	std::bitset<10> key_combined_2 = combine(sklow_2, skhigh_2);
	K2 = permute(key_combined_2, P8);
}

/**
 * Perform toy DES encryption on an 8-bit piece of plaintext
 */
std::bitset<8> des_encrypt(const std::bitset<8> &plaintext,
                           const std::bitset<10> &initial_key) {
	//Generate K1 and K2 using the subkey generation function
	std::bitset<8> K1, K2;
	generate_key(initial_key, K1, K2);

	//Permutations as defined in the lecture slides
	std::array<int, 8> initial_permutation = {{2, 6, 3, 1, 4, 8, 5, 7}};
	std::array<int, 8> inverse_initial_permutation = {{4, 1, 3, 5, 7, 2, 8, 6}};

	//Permute the bits according to the initial permutation layout
	std::bitset<8> permuted = permute(plaintext, initial_permutation);

	//Splitting into low and high bits for Feistel Cipher
	std::bitset<4> low, high;
	split(permuted, low, high);

	//Round one of Feistel Cipher: xor the low bits with the result of the F function applied
	// to the high bits and the first 8 bits of the subkey and swap
	low ^= F_fn(high, K1);
	swap(low, high);
	//Round 2, no more swapping because this is the last round
	low ^= F_fn(high, K2);

	//Combine low and high bits and permute with the inverse initial permutation to obtain
	// final ciphertext
	std::bitset<8> combined = combine(low, high);
	std::bitset<8> ciphertext = permute(combined, inverse_initial_permutation);

	return ciphertext;
}

/**
 * Perform toy DES decryption on an 8-bit piece of ciphertext
 */
std::bitset<8> des_decrypt(const std::bitset<8> &ciphertext,
                           const std::bitset<10> &initial_key) {
	//Generate K1 and K2 using the subkey generation function
	std::bitset<8> K1, K2;
	generate_key(initial_key, K1, K2);

	//Permutations as defined in the lecture slides
	std::array<int, 8> initial_permutation = {{2, 6, 3, 1, 4, 8, 5, 7}};
	std::array<int, 8> inverse_initial_permutation = {{4, 1, 3, 5, 7, 2, 8, 6}};

	//Permute the bits according to the initial permutation layout
	std::bitset<8> permuted = permute(ciphertext, initial_permutation);

	//Splitting into low and high bits for Feistel Cipher
	std::bitset<4> low, high;
	split(permuted, low, high);

	//Round one of Feistel Cipher: xor the low bits with the result of the F function applied
	// to the high bits and the last 8 bits of the subkey (because we are decrypting instead)
	low ^= F_fn(high, K2);
	swap(low, high);
	//Round 2, no more swapping because this is the last round
	low ^= F_fn(high, K1);

	//Combine low and high bits and permute with the inverse initial permutation to obtain
	// final plaintext
	std::bitset<8> combined = combine(low, high);
	std::bitset<8> plaintext = permute(combined, inverse_initial_permutation);

	return plaintext;
}


#endif //CRYPTO2_DES_H
