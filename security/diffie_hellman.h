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

#ifndef _EJA_DIFFIE_HELLMAN_
#define _EJA_DIFFIE_HELLMAN_

#include <memory>
#include <string>
#include <cryptopp/dh.h>
#include <cryptopp/integer.h>
#include <cryptopp/secblock.h>

#include "system/type.h"

namespace eja
{
	class diffie_hellman final
	{
	private:
		static const size_t default_bits = 128;

	private:
		CryptoPP::DH m_dh;
		CryptoPP::SecByteBlock m_private;
		CryptoPP::SecByteBlock m_public;
		CryptoPP::SecByteBlock m_shared;

	public:
		using ptr = std::shared_ptr<diffie_hellman>;

	public:
		diffie_hellman(const size_t bits = default_bits) { init(bits); }
		diffie_hellman(const byte* prime, const size_t prime_size, const size_t base) { init(prime, prime_size, base); }
		diffie_hellman(const CryptoPP::Integer& prime, const CryptoPP::Integer& base) { init(prime, base); }
		diffie_hellman(const CryptoPP::Integer& prime, const size_t base) { init(prime, base); }		
		diffie_hellman(const std::string& prime, const size_t base) { init(prime, base); }
		diffie_hellman(const char* prime, const size_t base) { init(prime, base); }
		~diffie_hellman() { }

		// Interface
		void clear();

		// Utility
		bool empty() const { return !m_shared.size(); }

		// Init
		void init(const size_t bits = default_bits);
		void init(const byte* prime, const size_t prime_size, const size_t base) { init(CryptoPP::Integer(prime, prime_size), base); }
		void init(const CryptoPP::Integer& prime, const CryptoPP::Integer& base);
		void init(const CryptoPP::Integer& prime, const size_t base) { init(prime, CryptoPP::Integer(base)); }	
		void init(const std::string& prime, const size_t base) { init(reinterpret_cast<const byte*>(prime.c_str()), prime.size(), base); }
		void init(const char* prime, const size_t base) { init(reinterpret_cast<const byte*>(prime), strlen(prime), base); }

		// Compute		
		bool compute(const byte* input, const size_t input_size, const bool validate = true); 
		bool compute(const CryptoPP::SecByteBlock& input, const bool validate = true); 
		bool compute(const std::string& input, const bool validate = true);
		bool compute(const char* input, const bool validate = true);		

		// Accessor		
		size_t size() const { return m_shared.size(); }
		const CryptoPP::Integer& get_base() const { return m_dh.GetGroupParameters().GetGenerator(); }
		const CryptoPP::Integer& get_prime() const { return m_dh.GetGroupParameters().GetModulus(); }

		const CryptoPP::SecByteBlock& get_private_key() const { return m_private; }
		const CryptoPP::SecByteBlock& get_public_key() const { return m_public; }
		const CryptoPP::SecByteBlock& get_shared_key() const { return m_shared; }

		// Static
		static ptr create() { return std::make_shared<diffie_hellman>(); }
		static ptr create(const size_t bits) { return std::make_shared<diffie_hellman>(bits); }
		static ptr create(const byte* prime, const size_t prime_size, const size_t base) { return std::make_shared<diffie_hellman>(prime, prime_size, base); }
		static ptr create(const CryptoPP::Integer& prime, const CryptoPP::Integer& base) { return std::make_shared<diffie_hellman>(prime, base); }
		static ptr create(const CryptoPP::Integer& prime, const size_t base) { return std::make_shared<diffie_hellman>(prime, base); }
		static ptr create(const std::string& prime, const size_t base) { return std::make_shared<diffie_hellman>(prime, base); }
		static ptr create(const char* prime, const size_t base) { return std::make_shared<diffie_hellman>(prime, base); }
	};
}

#endif
