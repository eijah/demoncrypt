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

#ifndef _EJA_HMAC_
#define _EJA_HMAC_

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

#include <memory>
#include <string>
#include <cryptopp/hmac.h>
#include <cryptopp/md5.h>
#include <cryptopp/osrng.h>
#include <cryptopp/secblock.h>
#include <cryptopp/sha.h>

#include "hash.h"
#include "security.h"

namespace eja
{
	// Using
	template <typename T> 
	class hmac_impl;	

	// MD	
	using hmac_md5 = hmac_impl<CryptoPP::HMAC<CryptoPP::Weak::MD5>>;
	using hmac_md = hmac_md5;

	// SHA1
	using hmac_sha1 = hmac_impl<CryptoPP::HMAC<CryptoPP::SHA1>>;
	using hmac_sha = hmac_sha1;

	// SHA2	
	using hmac_sha224 = hmac_impl<CryptoPP::HMAC<CryptoPP::SHA224>>;
	using hmac_sha256 = hmac_impl<CryptoPP::HMAC<CryptoPP::SHA256>>;
	using hmac_sha384 = hmac_impl<CryptoPP::HMAC<CryptoPP::SHA384>>;
	using hmac_sha512 = hmac_impl<CryptoPP::HMAC<CryptoPP::SHA512>>;

	// Type
	enum class hmac_type { md5, sha1, sha224, sha256, sha384, sha512 };

	// HMAC
	class hmac : public hash
	{
	public:
		using ptr = std::shared_ptr<hmac>;

	public:
		hmac() { }
		virtual ~hmac() override { }

		// Utility
		virtual void clear() { hash::clear(); }

		// Mutator
		virtual void set_key(const byte* key, const size_t key_size) = 0; 
		virtual void set_key(const CryptoPP::SecByteBlock& key) = 0;
		virtual void set_key(const std::string& key) = 0;
		virtual void set_key(const char* key) = 0;
	};

	template <typename T>
	class hmac_impl final : public hmac
	{
	private:
		T m_routine;

	public:
		hmac_impl() { clear(); }
		hmac_impl(const byte* key, const size_t key_size) { set_key(key, key_size); }
		hmac_impl(const CryptoPP::SecByteBlock& key) { set_key(key); }
		hmac_impl(const std::string& key) { set_key(key); }
		hmac_impl(const char* key) { set_key(key); }		
		virtual ~hmac_impl() override { };	

		// Operator
		std::string operator()() const { return hmac_impl().random(); }

		// Utility
		virtual void clear() override;

		// Random
		virtual std::string random() const override { return security::random(T::DIGESTSIZE); }

		// Compute
		using hmac::compute;
		virtual std::string compute() override;
		virtual std::string compute(const byte* input, const size_t input_size) override; 

		// Update
		using hmac::update;
		virtual void update(const byte* input, const size_t input_size) override { m_routine.Update(input, input_size); }

		// Accessor
		virtual size_t size() const override { return T::DIGESTSIZE; }

		// Mutator
		virtual void set_key(const byte* key, const size_t key_size) override { m_routine.SetKey(key, key_size); }
		virtual void set_key(const CryptoPP::SecByteBlock& key) override { m_routine.SetKey(key.data(), key.size()); }
		virtual void set_key(const std::string& key) override { m_routine.SetKey(reinterpret_cast<const byte*>(key.c_str()), key.size()); }
		virtual void set_key(const char* key) override { m_routine.SetKey(reinterpret_cast<const byte*>(key), strlen(key)); }

		// Static
		static ptr create() { return std::make_shared<hmac_impl<T>>(); }
		static ptr create(const byte* key, const size_t key_size) { return std::make_shared<hmac_impl<T>>(key, key_size); }
		static ptr create(const CryptoPP::SecByteBlock& key) { return std::make_shared<hmac_impl<T>>(key); }
		static ptr create(const std::string& key) { return std::make_shared<hmac_impl<T>>(key); }
		static ptr create(const char* key) { return std::make_shared<hmac_impl<T>>(key); }
	};

	// Utility
	template <typename T>
	void hmac_impl<T>::clear()
	{
		hmac::clear();

		byte key[T::DIGESTSIZE];
		memset(key, 0, T::DIGESTSIZE);
		set_key(key, T::DIGESTSIZE);
	}

	// Compute
	template <typename T>
	std::string hmac_impl<T>::compute()
	{
		byte digest[T::DIGESTSIZE];
		m_routine.Update(m_salt.data(), m_salt.size());
		m_routine.Final(digest);

		return security::str(digest, T::DIGESTSIZE);
	}

	template <typename T>
	std::string hmac_impl<T>::compute(const byte* input, const size_t input_size)
	{
		assert(input && input_size);

		byte digest[T::DIGESTSIZE];
		m_routine.Update(input, input_size);
		m_routine.Update(m_salt.data(), m_salt.size());
		m_routine.Final(digest);

		return security::str(digest, T::DIGESTSIZE);
	}
}

#endif
