//The more you look the more you'll see me using this file everywhere.
// It's just so useful (performance notwithstanding)

#ifndef _CHARSTREAM_H_
#define _CHARSTREAM_H_

#include <assert.h>
#include <vector>
#include <deque>
#include <stdint.h>
#include <string>
#include <string.h>
#include <bitset>
#include <arpa/inet.h>

typedef uint8_t U8;
typedef uint16_t U16;
typedef uint32_t U32;
typedef uint64_t U64;
typedef int8_t S8;
typedef int16_t S16;
typedef int32_t S32;
typedef int64_t S64;

class CharStream {
	std::vector<U8> mData;
public:
	CharStream() {

	}
	CharStream(const U8 *data, const U32 &length) {
		for (U32 i = 0; i < length; i ++) {
			mData.push_back(data[i]);
		}
	}

	template <typename T>
	T push(const T &value);

	template <typename T>
	T pop();

	std::vector<U8> getBuffer() const {
		std::vector<U8> data;
		data.insert(data.end(), mData.begin(), mData.end());
		return data;
	}

	size_t size() const {
		return mData.size();
	}

	template<size_t N>
	std::bitset<N> push(const std::bitset<N> &value) {
		//LSB first, I think that makes this big endian?
		for (int i = 0; i < N; i += 8) {
			U8 byte = (value >> i).to_ullong() & 0xFF;
			push<U8>(byte);
		}
		return value;
	}

	template<size_t N>
	std::bitset<N> pop() {
		std::bitset<N> value;
		for (int i = 0; i < N; i += 8) {
			value |= (std::bitset<N>(pop<U8>()) << i);
		}
		return value;
	}
};

//-----------------------------------------------------------------------------
// U8 datatype. Represents the base type for pushing and popping data off of
// the stream
//-----------------------------------------------------------------------------

template<>
inline U8 CharStream::push(const U8 &value) {
	mData.push_back(value);
	return value;
}

template<>
inline U8 CharStream::pop() {
	if (mData.size() == 0) {
		assert(false);
		return 0;
	}

	//Like a queue, pop front
	U8 value = mData.front();
	mData.erase(mData.begin());
	return value;
}

//Signed integer support, casting just assumes it works
template<>
inline S8 CharStream::push(const S8 &value) {
	return push<U8>(value);
}
template<>
inline S8 CharStream::pop() {
	return pop<U8>();
}

//-----------------------------------------------------------------------------
// U16 datatype
//-----------------------------------------------------------------------------

template<>
inline U16 CharStream::push(const U16 &value) {
	//Neat little trick to convert U16 to U8
	union {
		U16 u16;
		U8 u8[2];
	} data;
	data.u16 = value;

	push<U8>(data.u8[0]);
	push<U8>(data.u8[1]);
	return value;
}

template<>
inline U16 CharStream::pop() {
	union {
		U16 u16;
		U8 u8[2];
	} data;
	data.u8[0] = pop<U8>();
	data.u8[1] = pop<U8>();
	return data.u16;
}

template<>
inline S16 CharStream::push(const S16 &value) {
	return push<U16>(value);
}
template<>
inline S16 CharStream::pop() {
	return pop<U16>();
}

//-----------------------------------------------------------------------------
// U32 datatype
//-----------------------------------------------------------------------------

template<>
inline U32 CharStream::push(const U32 &value) {
	//Neat little trick to convert U32 to U8
	union {
		U32 u32;
		U8 u8[4];
	} data;
	data.u32 = value;

	push<U8>(data.u8[0]);
	push<U8>(data.u8[1]);
	push<U8>(data.u8[2]);
	push<U8>(data.u8[3]);
	return value;
}

template<>
inline U32 CharStream::pop() {
	union {
		U32 u32;
		U8 u8[4];
	} data;
	data.u8[0] = pop<U8>();
	data.u8[1] = pop<U8>();
	data.u8[2] = pop<U8>();
	data.u8[3] = pop<U8>();
	return data.u32;
}

template<>
inline S32 CharStream::push(const S32 &value) {
	return push<U32>(value);
}
template<>
inline S32 CharStream::pop() {
	return pop<U32>();
}

//-----------------------------------------------------------------------------
// U64 datatype
//-----------------------------------------------------------------------------

template<>
inline U64 CharStream::push(const U64 &value) {
	//Neat little trick to convert U64 to U8
	union {
		U64 u64;
		U8 u8[8];
	} data;
	data.u64 = value;

	push<U8>(data.u8[0]);
	push<U8>(data.u8[1]);
	push<U8>(data.u8[2]);
	push<U8>(data.u8[3]);
	push<U8>(data.u8[4]);
	push<U8>(data.u8[5]);
	push<U8>(data.u8[6]);
	push<U8>(data.u8[7]);
	return value;
}

template<>
inline U64 CharStream::pop() {
	union {
		U64 u64;
		U8 u8[8];
	} data;
	data.u8[0] = pop<U8>();
	data.u8[1] = pop<U8>();
	data.u8[2] = pop<U8>();
	data.u8[3] = pop<U8>();
	data.u8[4] = pop<U8>();
	data.u8[5] = pop<U8>();
	data.u8[6] = pop<U8>();
	data.u8[7] = pop<U8>();
	return data.u64;
}

template<>
inline S64 CharStream::push(const S64 &value) {
	return push<U64>(value);
}
template<>
inline S64 CharStream::pop() {
	return pop<U64>();
}

//-----------------------------------------------------------------------------
// Strings

template<>
inline std::string CharStream::push(const std::string &value) {
	for (int i = 0; i < value.size(); i ++) {
		push<U8>(value[i]);
	}
	push<U8>(0);
	return value;
}

template<>
inline std::string CharStream::pop() {
	std::vector<char> bytes;
	while (true) {
		char byte = pop<S8>();
		if (byte == 0) {
			break;
		}

		bytes.push_back(byte);
	}
	//Null terminate
	bytes.push_back(0);

	return std::string(bytes.data());
}

template<>
inline const char *CharStream::push(const char *const &value) {
	push<std::string>(value);
	return value;
}

template<>
inline char *CharStream::pop() {
	std::string str = pop<std::string>();

	//This is a memory leak but not much we can do about returning a char ptr
	char *buffer = new char[str.size() + 1];
	strcpy(buffer, str.data());
	return buffer;
}

template<>
inline sockaddr_in CharStream::push(const sockaddr_in &value) {
	for (int i = 0; i < sizeof(value); i ++) {
		push<uint8_t>(((uint8_t *)&value)[i]);
	}
	return value;
}

template<>
inline sockaddr_in CharStream::pop() {
	sockaddr_in value;
	for (int i = 0; i < sizeof(value); i ++) {
		((uint8_t *)&value)[i] = pop<uint8_t>();
	}
	return value;
}

#endif // _CHARSTREAM_H_
