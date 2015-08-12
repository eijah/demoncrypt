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

#ifndef _EJA_SECURITY_
#define _EJA_SECURITY_

#include <cassert>
#include <string>
#include <cryptopp/aes.h>
#include <cryptopp/integer.h>
#include <cryptopp/osrng.h>
#include <cryptopp/secblock.h>

namespace eja
{
	// Type
	enum class cipher_type;
	enum class hash_type;
	enum class hmac_type;
	enum class pbkdf_type;

	// Algorithm
	class block_cipher;
	class hash;
	class hmac;
	class pbkdf;

	class security final
	{
	public:
		static const char* empty; 
		static const char* signature;

	private:
		security() = delete;
		security(const security&) = delete;
		~security() = delete;

		// Operator
		security& operator=(const security&) = delete;

	public:
		// Random
		static std::string random(const size_t output_size) { return random<CryptoPP::AES>(output_size); }
		template <typename T> static std::string random(const size_t output_size);

		// Utility
		static std::string str(const byte* input, const size_t input_size);
		static std::string str(const CryptoPP::SecByteBlock& input);
		static std::string str(const CryptoPP::Integer& input);

		// Cipher		
		static std::shared_ptr<block_cipher> get_cipher(const cipher_type type);
		static std::shared_ptr<block_cipher> get_cipher(const std::string& name) { return get_cipher(name.c_str()); }
		static std::shared_ptr<block_cipher> get_cipher(const char* name);

		static const char* get_cipher_name(const cipher_type type);
		static const char* get_cipher_name(const size_t type) { return get_cipher_name(static_cast<cipher_type>(type)); }
		
		// Hash
		static std::shared_ptr<hash> get_hash(const hash_type type);
		static std::shared_ptr<hash> get_hash(const std::string& name) { return get_hash(name.c_str()); }
		static std::shared_ptr<hash> get_hash(const char* name);

		static const char* get_hash_name(const hash_type type);
		static const char* get_hash_name(const size_t type) { return get_hash_name(static_cast<hash_type>(type)); }

		// HMAC
		static std::shared_ptr<hmac> get_hmac(const hmac_type type);
		static std::shared_ptr<hmac> get_hmac(const std::string& name) { return get_hmac(name.c_str()); }
		static std::shared_ptr<hmac> get_hmac(const char* name);

		static const char* get_hmac_name(const hmac_type type);
		static const char* get_hmac_name(const size_t type) { return get_hmac_name(static_cast<hmac_type>(type)); }

		// PBKDF		
		static std::shared_ptr<pbkdf> get_pbkdf(const pbkdf_type type);
		static std::shared_ptr<pbkdf> get_pbkdf(const std::string& name) { return get_pbkdf(name.c_str()); }
		static std::shared_ptr<pbkdf> get_pbkdf(const char* name);

		static const char* get_pbkdf_name(const pbkdf_type type);
		static const char* get_pbkdf_name(const size_t type) { return get_pbkdf_name(static_cast<pbkdf_type>(type)); }
	};

	// Random
	template <typename T>
	std::string security::random(const size_t output_size)
	{
		assert(output_size);

		CryptoPP::AutoSeededX917RNG<T> rng;
		CryptoPP::SecByteBlock block(output_size);
		rng.GenerateBlock(block, block.size());
		return str(block);
	}
}

#endif


