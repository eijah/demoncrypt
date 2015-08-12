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

#include <cassert>
#include <cryptopp/nbtheory.h>
#include <cryptopp/osrng.h>

#include "diffie_hellman.h"
#include "security.h"

// NOTE: Ideally, we always want to validate the base/prime
// Unfortunately, I ran into some compatibility problems when using C# & C++ versions.
// Most likely this was caused by a shitty crypto implementation. To maintain bakwards
// compatibility cross-language I had to disable this check in demonsaw v2.0. Boo.
#define VALIDATE (0)

namespace eja
{
	// Interface
	void diffie_hellman::clear()
	{
		m_private.resize(0);
		m_public.resize(0);
		m_shared.resize(0);
	}

	// Init
	void diffie_hellman::init(const size_t bits /*= default_bits*/)
	{
		// Initialize with random prime and base
		CryptoPP::AutoSeededX917RNG<CryptoPP::AES> rng;
		auto& group = m_dh.AccessGroupParameters();
		group.Initialize(rng, bits);

#if VALIDATE
		if (!m_dh.GetGroupParameters().ValidateGroup(rng, 3))
			throw std::runtime_error("Failed to validate base and prime");

		// Extract the prime and base
		const auto& parameters = m_dh.GetGroupParameters();
		const auto& g = parameters.GetGenerator();
		const auto& p = parameters.GetModulus();
		const auto& q = parameters.GetSubgroupOrder();

		// http://groups.google.com/group/sci.crypt/browse_thread/thread/7dc7eeb04a09f0ce
		const auto v = CryptoPP::ModularExponentiation(g, q, p);
		if (v != CryptoPP::Integer::One())
			throw std::runtime_error("Failed to verify order of the subgroup");
#endif
		m_private.resize(m_dh.PrivateKeyLength());
		m_public.resize(m_dh.PublicKeyLength());
		m_shared.resize(m_dh.AgreedValueLength());

		// Generate a pair of integers for Alice. The public integer is forwarded to Bob.
		m_dh.GenerateKeyPair(rng, m_private, m_public);
	}

	void diffie_hellman::init(const CryptoPP::Integer& p, const CryptoPP::Integer& g)
	{
		CryptoPP::AutoSeededX917RNG<CryptoPP::AES> rng;
		auto& group = m_dh.AccessGroupParameters();
		group.Initialize(p, g);

#if VALIDATE
		if (!m_dh.GetGroupParameters().ValidateGroup(rng, 3))
			throw std::runtime_error("Failed to validate base and prime");
#endif
		m_private.resize(m_dh.PrivateKeyLength());
		m_public.resize(m_dh.PublicKeyLength());
		m_shared.resize(m_dh.AgreedValueLength());

		// Generate a pair of integers
		m_dh.GenerateKeyPair(rng, m_private, m_public);
	}

	// Compute
	bool diffie_hellman::compute(const CryptoPP::SecByteBlock& input, const bool validate /*= true*/)
	{
		assert(!input.empty());

		return m_dh.Agree(m_shared, m_private, reinterpret_cast<const byte*>(input.data()), validate);
	}

	bool diffie_hellman::compute(const char* input, const bool validate /*= true*/)
	{
		assert(input);

		return m_dh.Agree(m_shared, m_private, reinterpret_cast<const byte*>(input), validate);
	}

	bool diffie_hellman::compute(const std::string& input, const bool validate /*= true*/)
	{
		assert(!input.empty());

		return m_dh.Agree(m_shared, m_private, reinterpret_cast<const byte*>(input.c_str()), validate);
	}

	bool diffie_hellman::compute(const byte* input, const size_t input_size, const bool validate /*= true*/)
	{
		assert(input && input_size);

		return m_dh.Agree(m_shared, m_private, input, validate);
	}
}
