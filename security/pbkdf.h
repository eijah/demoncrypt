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

#ifndef _EJA_PASSWORD_
#define _EJA_PASSWORD_

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

#include <memory>
#include <string>
#include <cryptopp/md5.h>
#include <cryptopp/osrng.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/sha.h>
#include <cryptopp/sha3.h>
#include <cryptopp/secblock.h>

#include "security.h"
#include "system/type.h"

namespace eja
{
	template <typename T, typename U> 
	class pbkdf_impl; 	

	// PBKDF1 - MD
	using pbkdf1_md5 = pbkdf_impl<CryptoPP::PKCS5_PBKDF1<CryptoPP::Weak::MD5>, CryptoPP::Weak::MD5>;
	using pbkdf1_md = pbkdf1_md5;

	// PBKDF1 - SHA1
	using pbkdf1_sha1 = pbkdf_impl<CryptoPP::PKCS5_PBKDF1<CryptoPP::SHA1>, CryptoPP::SHA1>;

	// PBKDF1 - SHA2
	using pbkdf1_sha224 = pbkdf_impl<CryptoPP::PKCS5_PBKDF1<CryptoPP::SHA224>, CryptoPP::SHA224>;
	using pbkdf1_sha256 = pbkdf_impl<CryptoPP::PKCS5_PBKDF1<CryptoPP::SHA256>, CryptoPP::SHA256>;
	using pbkdf1_sha384 = pbkdf_impl<CryptoPP::PKCS5_PBKDF1<CryptoPP::SHA384>, CryptoPP::SHA384>;
	using pbkdf1_sha512 = pbkdf_impl<CryptoPP::PKCS5_PBKDF1<CryptoPP::SHA512>, CryptoPP::SHA512>;

	// PBKDF2 - MD
	using pbkdf2_hmac_md5 = pbkdf_impl<CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::Weak::MD5>, CryptoPP::Weak::MD5>;
	using pbkdf2_hmac_md = pbkdf2_hmac_md5;

	// PBKDF2 - SHA1
	using pbkdf2_hmac_sha1 = pbkdf_impl<CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA1>, CryptoPP::SHA1>;

	// PBKDF2 - SHA2
	using pbkdf2_hmac_sha224 = pbkdf_impl<CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA224>, CryptoPP::SHA224>;
	using pbkdf2_hmac_sha256 = pbkdf_impl<CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256>, CryptoPP::SHA256>;
	using pbkdf2_hmac_sha384 = pbkdf_impl<CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA384>, CryptoPP::SHA384>;
	using pbkdf2_hmac_sha512 = pbkdf_impl<CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA512>, CryptoPP::SHA512>;

	// Type
	enum class pbkdf_type { md5, sha1, sha224, sha256, sha384, sha512 };

	// PBKDF
	class pbkdf
	{
	protected:
		CryptoPP::SecByteBlock m_salt;
		size_t m_iterations;

		static const size_t default_iterations = (1 << 14);

	public:
		using ptr = std::shared_ptr<pbkdf>;

	public:
		pbkdf() : m_iterations(default_iterations) { }
		pbkdf(const char* salt, const size_t iterations) : m_iterations(iterations) { set_salt(salt); }
		pbkdf(const CryptoPP::SecByteBlock& salt, const size_t iterations) : m_iterations(iterations) { set_salt(salt); }
		pbkdf(const std::string& salt, const size_t iterations) : m_iterations(iterations) { set_salt(salt); }
		pbkdf(const byte* salt, const size_t salt_size, const size_t iterations) : m_iterations(iterations) { set_salt(salt, salt_size); }
		virtual ~pbkdf() { };

		// Interface
		void clear() { m_salt.resize(0); }

		// Utility
		bool empty() const { return !m_salt.size(); }

		// Random
		virtual std::string random(const size_t output_size) const = 0;

		// Compute
		virtual std::string compute(const byte* input, const size_t input_size, const size_t output_size) const = 0;
		virtual std::string compute(const CryptoPP::SecByteBlock& input, const size_t output_size) const = 0;
		virtual std::string compute(const std::string& input, const size_t output_size) const = 0;
		virtual std::string compute(const char* input, const size_t output_size) const = 0;

		virtual void compute(const byte* input, const size_t input_size, CryptoPP::SecByteBlock& output) const = 0;
		virtual void compute(const CryptoPP::SecByteBlock& input, CryptoPP::SecByteBlock& output) const = 0;
		virtual void compute(const std::string& input, CryptoPP::SecByteBlock& output) const = 0;
		virtual void compute(const char* input, CryptoPP::SecByteBlock& output) const = 0;

		// Mutator
		void set_salt(const char* salt) { m_salt.Assign(reinterpret_cast<const byte*>(salt), strlen(salt)); }
		void set_salt(const CryptoPP::SecByteBlock& salt) { m_salt.Assign(salt.data(), salt.size()); }
		void set_salt(const std::string& salt) { m_salt.Assign(reinterpret_cast<const byte*>(salt.c_str()), salt.size()); }
		void set_salt(const byte* salt, const size_t salt_size) { m_salt.Assign(salt, salt_size); }

		void set_iterations(size_t iterations) { m_iterations = iterations; }

		// Accessor
		const CryptoPP::SecByteBlock& get_salt() const { return m_salt; }
		size_t get_iterations() const { return m_iterations; }
		virtual size_t size() const = 0;
	};

	template <typename T, typename U>
	class pbkdf_impl final : public pbkdf
	{
	private:		
		T m_routine;

	public:
		pbkdf_impl() { }
		pbkdf_impl(const byte* salt, const size_t salt_size, const size_t iterations = default_iterations) : pbkdf(salt, salt_size, iterations) { }
		pbkdf_impl(const CryptoPP::SecByteBlock& salt, const size_t iterations = default_iterations) : pbkdf(salt, iterations) { }
		pbkdf_impl(const std::string& salt, const size_t iterations = default_iterations) : pbkdf(salt, iterations) { }
		pbkdf_impl(const char* salt, const size_t iterations = default_iterations) : pbkdf(salt, iterations) { }
		virtual ~pbkdf_impl() override { };

		// Operator
		std::string operator()(const size_t output_size = U::DIGESTSIZE) const { return pbkdf_impl().random(output_size); }

		// Random
		virtual std::string random(const size_t output_size = U::DIGESTSIZE) const override { return security::random(output_size); }

		// Compute
		virtual std::string compute(const byte* input, const size_t input_size, const size_t output_size = U::DIGESTSIZE) const override;
		virtual std::string compute(const CryptoPP::SecByteBlock& input, const size_t output_size = U::DIGESTSIZE) const override { return compute(input.data(), input.size(), output_size); }
		virtual std::string compute(const std::string& input, const size_t output_size = U::DIGESTSIZE) const override { return compute(reinterpret_cast<const byte*>(input.c_str()), input.size(), output_size); }
		virtual std::string compute(const char* input, const size_t output_size = U::DIGESTSIZE) const override { return compute(reinterpret_cast<const byte*>(input), strlen(input), output_size); }

		virtual void compute(const byte* input, const size_t input_size, CryptoPP::SecByteBlock& output) const override;
		virtual void compute(const CryptoPP::SecByteBlock& input, CryptoPP::SecByteBlock& output) const override { return compute(input.data(), input.size(), output); }
		virtual void compute(const std::string& input, CryptoPP::SecByteBlock& output) const override { return compute(reinterpret_cast<const byte*>(input.c_str()), input.size(), output); }
		virtual void compute(const char* input, CryptoPP::SecByteBlock& output) const override { return compute(reinterpret_cast<const byte*>(input), strlen(input), output); }

		// Static
		virtual size_t size() const override { return U::DIGESTSIZE; }

		// Static
		static ptr create() { return std::make_shared<pbkdf_impl<T, U>>(); }
		static ptr create(const byte* salt, const size_t salt_size, const size_t iterations = default_iterations) { return std::make_shared<pbkdf_impl<T, U>>(salt, salt_size, iterations); }
		static ptr create(const CryptoPP::SecByteBlock& salt, const size_t iterations = default_iterations) { return std::make_shared<pbkdf_impl<T, U>>(salt, iterations); }
		static ptr create(const std::string& salt, const size_t iterations = default_iterations) { return std::make_shared<pbkdf_impl<T, U>>(salt, iterations); }
		static ptr create(const char* salt, const size_t iterations = default_iterations) { return std::make_shared<pbkdf_impl<T, U>>(salt, iterations); }
	};

	// Compute
	template <typename T, typename U>
	std::string pbkdf_impl<T, U>::compute(const byte* input, const size_t input_size, size_t output_size /*= U::DIGESTSIZE*/) const
	{
		assert(output_size);

		CryptoPP::SecByteBlock block(output_size);
		m_routine.DeriveKey(block, block.size(), 0x00, input, input_size, m_salt, m_salt.size(), m_iterations, 0);
		return security::str(block);
	}

	template <typename T, typename U>
	void pbkdf_impl<T, U>::compute(const byte* input, const size_t input_size, CryptoPP::SecByteBlock& output) const
	{
		assert(output.size());

		m_routine.DeriveKey(output, output.size(), 0x00, input, input_size, m_salt, m_salt.size(), m_iterations, 0);
	}
}

#endif
