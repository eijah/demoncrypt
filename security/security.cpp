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

#ifdef _MSC_VER
#pragma warning(disable: 4996)
#endif

#include <sstream>
#include <boost/algorithm/string.hpp>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <cryptopp/secblock.h>

#include "hash.h"
#include "block_cipher.h"
#include "hmac.h"
#include "pbkdf.h"
#include "security.h"

namespace eja
{
	// Cipher	
	block_cipher::ptr security::get_cipher(const cipher_type type)
	{
		switch (type)
		{
			case cipher_type::aes:		return aes::create();
			case cipher_type::mars:		return mars::create();
			case cipher_type::rc6:		return rc6::create();
			case cipher_type::serpent:	return serpent::create();
			case cipher_type::twofish:	return twofish::create();
		}

		return nullptr;
	}

	block_cipher::ptr security::get_cipher(const char* name)
	{
		if (boost::iequals(name, "aes md5"))
			return aes::create();
		else if (boost::iequals(name, "mars"))
			return mars::create();
		else if (boost::iequals(name, "rc6"))
			return rc6::create();
		else if (boost::iequals(name, "serpent"))
			return serpent::create();
		else if (boost::iequals(name, "twofish"))
			return twofish::create();

		return nullptr;
	}

	const char* security::get_cipher_name(const cipher_type type)
	{
		switch (type)
		{
			case cipher_type::aes:		return "AES";
			case cipher_type::mars:		return "MARS";
			case cipher_type::rc6:		return "RC6";
			case cipher_type::serpent:	return "Serpent";
			case cipher_type::twofish:	return "Twofish";
			default:					return "";
		}
	}

	// Hash	
	hash::ptr security::get_hash(const hash_type type)
	{
		switch (type)
		{
			case hash_type::md5:		return md5::create();
			case hash_type::sha1:		return sha1::create();
			case hash_type::sha224:		return sha224::create();
			case hash_type::sha256:		return sha256::create();
			case hash_type::sha384:		return sha384::create();
			case hash_type::sha512:		return sha512::create();
			case hash_type::sha3_224:	return sha3_224::create();
			case hash_type::sha3_256:	return sha3_256::create();
			case hash_type::sha3_384:	return sha3_384::create();
			case hash_type::sha3_512:	return sha3_512::create();
		}

		return nullptr;
	}

	hash::ptr security::get_hash(const char* name)
	{
		if (boost::iequals(name, "md5"))
			return md5::create();
		else if (boost::iequals(name, "sha1"))
			return sha1::create();
		else if (boost::iequals(name, "sha224"))
			return sha224::create();
		else if (boost::iequals(name, "sha256"))
			return sha256::create();
		else if (boost::iequals(name, "sha384"))
			return sha384::create();
		else if (boost::iequals(name, "sha512"))
			return sha512::create();
		else if (boost::iequals(name, "sha3 224"))
			return sha3_224::create();
		else if (boost::iequals(name, "sha3 256"))
			return sha3_256::create();
		else if (boost::iequals(name, "sha3 384"))
			return sha3_384::create();
		else if (boost::iequals(name, "sha3 512"))
			return sha3_512::create();

		return nullptr;
	}

	const char* security::get_hash_name(const hash_type type)
	{
		switch (type)
		{
			case hash_type::md5:		return "MD5";
			case hash_type::sha1:		return "SHA1";
			case hash_type::sha224:		return "SHA224";
			case hash_type::sha256:		return "SHA256";
			case hash_type::sha384:		return "SHA384";
			case hash_type::sha512:		return "SHA512";
			case hash_type::sha3_224:	return "SHA3 224";
			case hash_type::sha3_256:	return "SHA3 256";
			case hash_type::sha3_384:	return "SHA3 384";
			case hash_type::sha3_512:	return "SHA3 512";
			default:					return "";
		}
	}

	// HMAC	
	hmac::ptr security::get_hmac(const hmac_type type)
	{
		switch (type)
		{
			case hmac_type::md5:		return hmac_md5::create();
			case hmac_type::sha1:		return hmac_sha1::create();
			case hmac_type::sha224:		return hmac_sha224::create();
			case hmac_type::sha256:		return hmac_sha256::create();
			case hmac_type::sha384:		return hmac_sha384::create();
			case hmac_type::sha512:		return hmac_sha512::create();
		}

		return nullptr;
	}

	hmac::ptr security::get_hmac(const char* name)
	{
		if (boost::iequals(name, "hmac md5"))
			return hmac_md5::create();
		else if (boost::iequals(name, "hmac sha1"))
			return hmac_sha1::create();
		else if (boost::iequals(name, "hmac sha224"))
			return hmac_sha224::create();
		else if (boost::iequals(name, "hmac sha256"))
			return hmac_sha256::create();
		else if (boost::iequals(name, "hmac sha384"))
			return hmac_sha384::create();
		else if (boost::iequals(name, "hmac sha512"))
			return hmac_sha512::create();

		return nullptr;
	}

	const char* security::get_hmac_name(const hmac_type type)
	{
		switch (type)
		{
			case hmac_type::md5:		return "HMAC MD5";
			case hmac_type::sha1:		return "HMAC SHA1";
			case hmac_type::sha224:		return "HMAC SHA224";
			case hmac_type::sha256:		return "HMAC SHA256";
			case hmac_type::sha384:		return "HMAC SHA384";
			case hmac_type::sha512:		return "HMAC SHA512";
			default:					return "";
		}
	}

	// PBKDF	
	pbkdf::ptr security::get_pbkdf(const pbkdf_type type)
	{
		switch (type)
		{
			case pbkdf_type::md5:		return pbkdf2_hmac_md5::create();
			case pbkdf_type::sha1:		return pbkdf2_hmac_sha1::create();
			case pbkdf_type::sha224:	return pbkdf2_hmac_sha224::create();
			case pbkdf_type::sha256:	return pbkdf2_hmac_sha256::create();
			case pbkdf_type::sha384:	return pbkdf2_hmac_sha384::create();
			case pbkdf_type::sha512:	return pbkdf2_hmac_sha512::create();
		}

		return nullptr;
	}

	pbkdf::ptr security::get_pbkdf(const char* name)
	{
		if (boost::iequals(name, "pbkdf2_hmac_md5"))
			return pbkdf2_hmac_md5::create();
		else if (boost::iequals(name, "pbkdf2_hmac_sha1"))
			return pbkdf2_hmac_sha1::create();
		else if (boost::iequals(name, "pbkdf2_hmac_sha224"))
			return pbkdf2_hmac_sha224::create();
		else if (boost::iequals(name, "pbkdf2_hmac_sha256"))
			return pbkdf2_hmac_sha256::create();
		else if (boost::iequals(name, "pbkdf2_hmac_sha384"))
			return pbkdf2_hmac_sha384::create();
		else if (boost::iequals(name, "pbkdf2_hmac_sha512"))
			return pbkdf2_hmac_sha512::create();

		return nullptr;
	}

	const char* security::get_pbkdf_name(const pbkdf_type type)
	{
		switch (type)
		{
			case pbkdf_type::md5:		return "PBKDF HMAC MD5";
			case pbkdf_type::sha1:		return "PBKDF HMAC SHA1";
			case pbkdf_type::sha224:	return "PBKDF HMAC SHA224";
			case pbkdf_type::sha256:	return "PBKDF HMAC SHA256";
			case pbkdf_type::sha384:	return "PBKDF HMAC SHA384";
			case pbkdf_type::sha512:	return "PBKDF HMAC SHA512";
			default:					return "";
		}
	}

	// Utility
	std::string security::str(const byte* input, const size_t input_size)
	{
		std::string output;
		CryptoPP::StringSink sink(output);
		sink.Put(input, input_size);
		return output;
	}

	std::string security::str(const CryptoPP::SecByteBlock& input)
	{
		std::string output;
		CryptoPP::StringSink sink(output);
		sink.Put(input, input.size());
		return output;
	}

	std::string security::str(const CryptoPP::Integer& input)
	{
		const auto input_size = input.MinEncodedSize();
		CryptoPP::SecByteBlock block(input_size);
		input.Encode(block.BytePtr(), input_size);

		return str(block);
		
		// NOTE: CryptoPP::Integer has a weird ostream format (uses prefixes to specify numeric base)
		//
		/*std::ostringstream oss;
		oss << std::hex << input;
		return oss.str();*/
	}
}
