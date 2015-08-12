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

#ifndef _EJA_HASH_
#define _EJA_HASH_

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

#include <memory>
#include <string>
#include <cryptopp/md2.h>
#include <cryptopp/md4.h>
#include <cryptopp/md5.h>
#include <cryptopp/osrng.h>
#include <cryptopp/secblock.h>
#include <cryptopp/sha.h>
#include <cryptopp/sha3.h>

#include "security.h"

namespace eja
{
	template <typename T> 
	class hash_impl; 	

	// MD	
	using md2 = hash_impl<CryptoPP::Weak::MD2>; 
	using md4 = hash_impl<CryptoPP::Weak::MD4>; 
	using md5 = hash_impl<CryptoPP::Weak::MD5>;
	using md = md5;

	// SHA1
	using sha1 = hash_impl<CryptoPP::SHA1>;
	using sha = sha1;

	// SHA2
	using sha224 = hash_impl<CryptoPP::SHA224>;
	using sha256 = hash_impl<CryptoPP::SHA256>;
	using sha384 = hash_impl<CryptoPP::SHA384>;
	using sha512 = hash_impl<CryptoPP::SHA512>;

	// SHA3
	using sha3_224 = hash_impl<CryptoPP::SHA3_224>;
	using sha3_256 = hash_impl<CryptoPP::SHA3_256>;
	using sha3_384 = hash_impl<CryptoPP::SHA3_384>;
	using sha3_512 = hash_impl<CryptoPP::SHA3_512>;

	// Type
	enum class hash_type { md5, sha1, sha224, sha256, sha384, sha512, sha3_224, sha3_256, sha3_384, sha3_512 };

	// Hash
	class hash
	{
	protected:
		CryptoPP::SecByteBlock m_salt;

	public:
		using ptr = std::shared_ptr<hash>;

	public:
		hash() { }
		virtual ~hash() { }

		// Interface
		void clear() { m_salt.resize(0); }

		// Utility
		bool empty() const { return !m_salt.size(); }

		// Random
		virtual std::string random() const = 0;

		// Compute
		virtual std::string compute() = 0;
		virtual std::string compute(const byte* input, const size_t input_size) = 0;
		std::string compute(const CryptoPP::SecByteBlock& input) { return compute(input.data(), input.size()); }
		std::string compute(const std::string& input) { return compute(reinterpret_cast<const byte*>(input.c_str()), input.size()); }
		std::string compute(const char* input) { return compute(reinterpret_cast<const byte*>(input), strlen(input)); }				

		// Update
		virtual void update(const byte* input, const size_t input_size) = 0;
		void update(const CryptoPP::SecByteBlock& input) { return update(input.data(), input.size()); }
		void update(const std::string& input) { update(reinterpret_cast<const byte*>(input.c_str()), input.size()); }
		void update(const char* input) { update(reinterpret_cast<const byte*>(input), strlen(input)); }		

		// Mutator
		void set_salt(const char* salt) { m_salt.Assign(reinterpret_cast<const byte*>(salt), strlen(salt)); }
		void set_salt(const CryptoPP::SecByteBlock& salt) { m_salt.Assign(salt.data(), salt.size()); }
		void set_salt(const std::string& salt) { m_salt.Assign(reinterpret_cast<const byte*>(salt.c_str()), salt.size()); }
		void set_salt(const byte* salt, const size_t salt_size) { m_salt.Assign(salt, salt_size); }

		// Accessor
		const CryptoPP::SecByteBlock& get_salt() const { return m_salt; }
		virtual size_t size() const = 0;
	};

	template <typename T>
	class hash_impl final : public hash
	{
	private:
		T m_routine;

	public:
		hash_impl() { }
		virtual ~hash_impl() override { }

		// Operator
		std::string operator()() const { return hash_impl().random(); }
		std::string operator()(const CryptoPP::SecByteBlock& input) const { return hash_impl().compute(input); }
		std::string operator()(const std::string& input) const { return hash_impl().compute(input); }
		std::string operator()(const char* input) const { return hash_impl().compute(input); }

		// Random
		virtual std::string random() const override { return security::random(T::DIGESTSIZE); }

		// Compute
		using hash::compute;
		virtual std::string compute() override;
		virtual std::string compute(const byte* input, const size_t input_size) override;
		
		// Update
		using hash::update;
		virtual void update(const byte* input, const size_t input_size) override { m_routine.Update(input, input_size); }

		// Accessor
		virtual size_t size() const override { return T::DIGESTSIZE; }

		// Static
		static ptr create() { return std::make_shared<hash_impl<T>>(); }
	};

	// Compute
	template <typename T>
	std::string hash_impl<T>::compute()
	{		
		byte digest[T::DIGESTSIZE];
		m_routine.Update(m_salt.data(), m_salt.size());
		m_routine.Final(digest);

		return security::str(digest, T::DIGESTSIZE);
	}

	template <typename T>
	std::string hash_impl<T>::compute(const byte* input, const size_t input_size)
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
