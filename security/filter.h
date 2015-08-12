//
// The MIT License(MIT)
//
// Copyright(c) 2014 Eijah
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//

#ifndef _EJA_FILTER_
#define _EJA_FILTER_

#include <string>
#include <cryptopp/base64.h>
#include <cryptopp/integer.h>
#include <cryptopp/hex.h>
#include <cryptopp/secblock.h>

#include "security.h"

namespace eja
{
	// Using
	template <typename E, typename D> class filter;
	using base64 = filter<CryptoPP::Base64Encoder, CryptoPP::Base64Decoder>;
	using hex = filter<CryptoPP::HexEncoder, CryptoPP::HexDecoder>;

	template <typename E, typename D>
	class filter final
	{
	public:
		static const size_t default_size = 16;

	private:
		filter() = delete;
		filter(const filter&) = delete;
		~filter() = delete;

		// Operator
		filter& operator=(const filter&) = delete;

	public:
		// Random
		static std::string random(const size_t output_size = default_size) { return encode(security::random(output_size)); }

		// Encode		
		static std::string encode(const byte* input, const size_t input_size);				
		static std::string encode(const CryptoPP::SecByteBlock& input) { return encode(input.data(), input.size()); }
		static std::string encode(const CryptoPP::SecByteBlock& input, const size_t input_size) { return encode(input.data(), std::min(input.size(), input_size)); }
		static std::string encode(const std::string& input, const size_t input_size) { return encode(reinterpret_cast<const byte*>(input.c_str()), std::min(input.size(), input_size)); }
		static std::string encode(const std::string& input) { return encode(reinterpret_cast<const byte*>(input.c_str()), input.size()); }
		static std::string encode(const char* input, const size_t input_size) { return encode(reinterpret_cast<const byte*>(input), std::min(strlen(input), input_size)); }
		static std::string encode(const char* input) { return encode(reinterpret_cast<const byte*>(input), strlen(input)); }
		static std::string encode(const CryptoPP::Integer& input) { return encode(security::str(input)); }

		// Decode
		static std::string decode(const byte* input, const size_t input_size);
		static std::string decode(const CryptoPP::SecByteBlock& input) { return decode(input.data(), input.size()); }
		static std::string decode(const CryptoPP::SecByteBlock& input, const size_t input_size) { return decode(input.data(), std::min(input.size(), input_size)); }
		static std::string decode(const std::string& input, const size_t input_size) { return decode(reinterpret_cast<const byte*>(input.c_str()), std::min(input.size(), input_size)); }
		static std::string decode(const std::string& input) { return decode(reinterpret_cast<const byte*>(input.c_str()), input.size()); }
		static std::string decode(const char* input, const size_t input_size) { return decode(reinterpret_cast<const byte*>(input), std::min(strlen(input), input_size)); }
		static std::string decode(const char* input) { return decode(reinterpret_cast<const byte*>(input), strlen(input)); }
		static std::string decode(const CryptoPP::Integer& input) { return decode(security::str(input)); }
	};

	// Encoder
	template <typename E, typename D>
	std::string filter<E, D>::encode(const byte* input, const size_t input_size)
	{
		//assert(input && input_size);

		E encoder(NULL, false);
		std::string output;
		encoder.Attach(new CryptoPP::StringSink(output));
		encoder.Put(input, input_size);
		encoder.MessageEnd();
		return output;
	}

	// Decode
	template <typename E, typename D>
	std::string filter<E, D>::decode(const byte* input, const size_t input_size)
	{
		//assert(input && input_size);

		D decoder;
		std::string output;
		decoder.Attach(new CryptoPP::StringSink(output));
		decoder.Put(input, input_size);
		decoder.MessageEnd();
		return output;
	}
}

#endif