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

#ifndef _EJA_CIPHER_
#define _EJA_CIPHER_

#include <memory>
#include <string>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/secblock.h>

// AES
#include <cryptopp/aes.h>
#include <cryptopp/cast.h>
#include <cryptopp/mars.h>
#include <cryptopp/rc6.h>
#include <cryptopp/rijndael.h>
#include <cryptopp/serpent.h>
#include <cryptopp/twofish.h>

// Other
#include <cryptopp/blowfish.h>
#include <cryptopp/camellia.h>
#include <cryptopp/des.h>
#include <cryptopp/idea.h>
#include <cryptopp/rc5.h>
#include <cryptopp/seed.h>
#include <cryptopp/shacal2.h>
#include <cryptopp/skipjack.h>
#include <cryptopp/tea.h>

// Legacy
#include <cryptopp/3way.h>
#include <cryptopp/gost.h>
#include <cryptopp/rc2.h>
#include <cryptopp/safer.h>
#include <cryptopp/shark.h>
#include <cryptopp/cast.h>
#include <cryptopp/square.h>

#include "security.h"
#include "system/type.h"

namespace eja
{	
	// Using
	template <typename T, typename U = CryptoPP::CBC_Mode<T>> 
	class block_cipher_impl;

	// AES	
	using mars = block_cipher_impl<CryptoPP::MARS>;
	using rc6 = block_cipher_impl<CryptoPP::RC6>;
	using rijndael = block_cipher_impl<CryptoPP::Rijndael>;
	using serpent = block_cipher_impl<CryptoPP::Serpent>;
	using twofish = block_cipher_impl<CryptoPP::Twofish>;
	using aes = rijndael;

	// Other
	using blowfish = block_cipher_impl<CryptoPP::Blowfish>;
	using camellia = block_cipher_impl<CryptoPP::Camellia>;
	using cast256 = block_cipher_impl<CryptoPP::CAST256>;
	using des_ede2 = block_cipher_impl<CryptoPP::DES_EDE2>;
	using des_ede3 = block_cipher_impl<CryptoPP::DES_EDE3>;
	using idea = block_cipher_impl<CryptoPP::IDEA>;
	using rc5 = block_cipher_impl<CryptoPP::RC5>;
	using seed = block_cipher_impl<CryptoPP::SEED>;
	using shacal2 = block_cipher_impl<CryptoPP::SHACAL2>;
	using skipjack = block_cipher_impl<CryptoPP::SKIPJACK>;
	using tea = block_cipher_impl<CryptoPP::TEA>;
	using xtea = block_cipher_impl<CryptoPP::XTEA>;

	// Legacy
	using cast128 = block_cipher_impl<CryptoPP::CAST128>;
	using des = block_cipher_impl<CryptoPP::DES>;
	using des_xex3 = block_cipher_impl<CryptoPP::DES_XEX3>;
	using gost = block_cipher_impl<CryptoPP::GOST>;
	using rc2 = block_cipher_impl<CryptoPP::RC2>;
	using safer_k = block_cipher_impl<CryptoPP::SAFER_K>;
	using safer_sk = block_cipher_impl<CryptoPP::SAFER_SK>;
	using shark = block_cipher_impl<CryptoPP::SHARK>;
	using square = block_cipher_impl<CryptoPP::Square>;
	using threeway = block_cipher_impl<CryptoPP::ThreeWay>;

	// Type
	enum class cipher_type { aes, mars, rc6, serpent, twofish };

	// Cipher
	class block_cipher
	{
	protected:
		CryptoPP::SecByteBlock m_key; 

	public:
		using ptr = std::shared_ptr<block_cipher>;

	public:
		block_cipher() { }
		block_cipher(const byte* key, const size_t key_size) { set_key(key, key_size); }
		block_cipher(const CryptoPP::SecByteBlock& key) { set_key(key); }
		block_cipher(const std::string& key, const size_t key_size) { set_key(key, key_size); }
		block_cipher(const std::string& key) { set_key(key); }
		block_cipher(const char* key, const size_t key_size) { set_key(key, key_size); }
		block_cipher(const char* key) { set_key(key); }
		virtual ~block_cipher() { }

		// Interface
		void clear() { m_key.resize(0); }

		// Utility
		bool empty() const { return !m_key.size(); }

		// Random
		virtual std::string random(const size_t output_size) const = 0;

		// Encrypt
		virtual std::string encrypt(const byte* input, const size_t input_size) const = 0;
		std::string encrypt(const CryptoPP::SecByteBlock& input) const { return encrypt(input.data(), input.size()); }
		std::string encrypt(const std::string& input) const { return encrypt(reinterpret_cast<const byte*>(input.c_str()), input.size()); }
		std::string encrypt(const char* input) const { return encrypt(reinterpret_cast<const byte*>(input), strlen(input)); }

		// Decrypt
		virtual std::string decrypt(const byte* input, const size_t input_size) const = 0; 
		std::string decrypt(const CryptoPP::SecByteBlock& input) const { return decrypt(input.data(), input.size()); }
		std::string decrypt(const std::string& input) const { return decrypt(reinterpret_cast<const byte*>(input.c_str()), input.size()); }
		std::string decrypt(const char* input) const { return decrypt(reinterpret_cast<const byte*>(input), strlen(input)); }

		// Mutator
		void set_key(const byte* key, const size_t key_size);
		void set_key(const CryptoPP::SecByteBlock& key) { set_key(key.data(), key.size()); }
		void set_key(const std::string& key, const size_t key_size) { set_key(reinterpret_cast<const byte*>(key.c_str()), key_size); }
		void set_key(const std::string& key) { set_key(reinterpret_cast<const byte*>(key.c_str()), key.size()); }
		void set_key(const char* key, const size_t key_size) { set_key(reinterpret_cast<const byte*>(key), key_size); }
		void set_key(const char* key) { set_key(reinterpret_cast<const byte*>(key), strlen(key)); }

		// Accessor
		std::string get_key() const{ return security::str(m_key); }
		size_t size() { return m_key.size(); }
	};

	template <typename T, typename U>
	class block_cipher_impl final : public block_cipher
	{
	private:
		T m_routine;
		CryptoPP::SecByteBlock m_iv;

	public:
		block_cipher_impl() : m_iv(T::BLOCKSIZE) { set_iv(); }
		block_cipher_impl(const byte* key, const size_t key_size) : block_cipher(key, key_size) { set_iv(); }
		block_cipher_impl(const CryptoPP::SecByteBlock& key) : block_cipher(key), m_iv(T::BLOCKSIZE) { set_iv(); }
		block_cipher_impl(const std::string& key, const size_t key_size) : block_cipher(key, key_size), m_iv(T::BLOCKSIZE) { set_iv(); }
		block_cipher_impl(const std::string& key) : block_cipher(key), m_iv(T::BLOCKSIZE) { set_iv(); }
		block_cipher_impl(const char* key, const size_t key_size) : block_cipher(key, key_size), m_iv(T::BLOCKSIZE) { set_iv(); }
		block_cipher_impl(const char* key) : block_cipher(key), m_iv(T::BLOCKSIZE) { set_iv(); }
		virtual ~block_cipher_impl() override { }

		// Operator
		std::string operator()(const size_t output_size = T::DEFAULT_KEYLENGTH) const { return block_cipher_impl().random(output_size); }

		// Random
		virtual std::string random(const size_t output_size = T::DEFAULT_KEYLENGTH) const override { return security::random<T>(output_size); }

		// Encrypt
		using block_cipher::encrypt;
		virtual std::string encrypt(const byte* input, const size_t input_size) const override; 

		// Decrypt
		using block_cipher::decrypt;
		virtual std::string decrypt(const byte* input, const size_t input_size) const override;

		// Mutator
		void set_iv() { memset(m_iv, 0, T::BLOCKSIZE); }
		void set_iv(const byte* iv, const size_t iv_size);
		void set_iv(const CryptoPP::SecByteBlock& iv) { set_iv(iv.data(), iv.size()); }
		void set_iv(const std::string& iv) { set_iv(reinterpret_cast<const byte*>(iv.c_str()), iv.size()); }
		void set_iv(const char* iv) { set_iv(reinterpret_cast<const byte*>(iv), strlen(iv)); }

		// Accessor
		std::string get_iv() const { return security::str(m_iv); }

		// Static
		static size_t get_min_size() { return T::MIN_KEYLENGTH; }
		static size_t get_max_size() { return T::MAX_KEYLENGTH; }
		static size_t get_default_size() { return T::DEFAULT_KEYLENGTH; }

		static ptr create() { return std::make_shared<block_cipher_impl<T, U>>(); }
		static ptr create(const byte* key, const size_t key_size) { return std::make_shared<block_cipher_impl<T, U>>(key, key_size); }
		static ptr create(const CryptoPP::SecByteBlock& key) { return std::make_shared<block_cipher_impl<T, U>>(key); }
		static ptr create(const std::string& key, const size_t key_size) { return std::make_shared<block_cipher_impl<T, U>>(key, key_size); }
		static ptr create(const std::string& key) { return std::make_shared<block_cipher_impl<T, U>>(key); }
		static ptr create(const char* key, const size_t key_size) { return std::make_shared<block_cipher_impl<T, U>>(key, key_size); }
		static ptr create(const char* key) { return std::make_shared<block_cipher_impl<T, U>>(key); }
	};

	// Encrypt	
	template <typename T, typename U>
	std::string block_cipher_impl<T, U>::encrypt(const byte* input, const size_t input_size) const
	{
		assert(input && input_size);

		std::string output;
		typename U::Encryption encryptor(m_key, m_key.size(), m_iv);
		CryptoPP::StreamTransformationFilter filter(encryptor, new CryptoPP::StringSink(output));
		filter.Put(input, input_size);
		filter.MessageEnd();
		return output;
	}

	// Decrypt	
	template <typename T, typename U>
	std::string block_cipher_impl<T, U>::decrypt(const byte* input, const size_t input_size) const
	{
		assert(input && input_size);

		std::string output;
		typename U::Decryption decryptor(m_key, m_key.size(), m_iv);
		CryptoPP::StreamTransformationFilter filter(decryptor, new CryptoPP::StringSink(output));
		filter.Put(input, input_size);
		filter.MessageEnd();
		return output;
	}

	// Mutator		
	template <typename T, typename U>
	void block_cipher_impl<T, U>::set_iv(const byte* iv, const size_t iv_size)
	{
		assert(iv && (iv_size >= T::BLOCKSIZE));

		m_iv.Assign(iv, iv_size); 
	}
}

#endif
