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

#ifndef _EJA_CHECKSUM_
#define _EJA_CHECKSUM_

#include <memory>
#include <string>
#include <cryptopp/adler32.h>
#include <cryptopp/crc.h>
#include <cryptopp/osrng.h>
#include <cryptopp/secblock.h>

namespace eja
{
	template <typename T> 
	class checksum_impl;

	// Adler	
	using adler32 = checksum_impl<CryptoPP::Adler32>;
	using adler = adler32;

	// CRC
	using crc32 = checksum_impl<CryptoPP::CRC32>;
	using crc = crc32;

	class checksum
	{
	public:
		using ptr = std::shared_ptr<checksum>;

	public:
		checksum() { }
		virtual ~checksum() { }

		// Random
		virtual CryptoPP::word random() = 0;

		// Compute
		virtual CryptoPP::word compute() = 0;
		virtual CryptoPP::word compute(const byte* input, const size_t input_size) = 0;
		CryptoPP::word compute(const CryptoPP::SecByteBlock& input) { return compute(input.data(), input.size()); }
		CryptoPP::word compute(const std::string& input) { return compute(reinterpret_cast<const byte*>(input.c_str()), input.size()); }
		CryptoPP::word compute(const char* input) { return compute(reinterpret_cast<const byte*>(input), strlen(input)); }

		// Update
		virtual void update(const byte* input, const size_t input_size) = 0;
		void update(const CryptoPP::SecByteBlock& input) { update(input.data(), input.size()); }
		void update(const std::string& input) { update(reinterpret_cast<const byte*>(input.c_str()), input.size()); }
		void update(const char* input) { update(reinterpret_cast<const byte*>(input), strlen(input)); }		

		// Accessor
		virtual size_t size() const = 0;
	};

	template <typename T>
	class checksum_impl final : public checksum
	{
	private:
		T m_routine;

	public:
		checksum_impl() { }
		virtual ~checksum_impl() override { }

		// Operator
		CryptoPP::word operator()() const { return checksum_impl().random(); }
		std::string operator()(const CryptoPP::SecByteBlock& input) const { return checksum_impl().compute(input); }
		std::string operator()(const std::string& input) const { return checksum_impl().compute(input); }
		std::string operator()(const char* input) const { return checksum_impl().compute(input); }

		// Random
		virtual CryptoPP::word random() override;

		// Compute
		using checksum::compute;
		virtual CryptoPP::word compute() override;
		virtual CryptoPP::word compute(const byte* input, const size_t input_size) override;

		// Update
		using checksum::update;
		virtual void update(const byte* input, const size_t input_size) override { m_routine.Update(input, input_size); }

		// Accessor
		virtual size_t size() const override { return T::DIGESTSIZE; }

		// Static
		static ptr create() { return std::make_shared<checksum_impl<T>>(); }
	};

	// Random
	template <typename T>
	CryptoPP::word checksum_impl<T>::random()
	{
		CryptoPP::word output;
		CryptoPP::AutoSeededX917RNG<CryptoPP::AES> rng;
		rng.GenerateBlock(reinterpret_cast<byte*>(&output), T::DIGESTSIZE);
		return output;
	}

	// Compute
	template <typename T>
	CryptoPP::word checksum_impl<T>::compute()
	{
		CryptoPP::word output;
		m_routine.Final(reinterpret_cast<byte*>(&output));
		return output;
	}

	template <typename T>
	CryptoPP::word checksum_impl<T>::compute(const byte* input, const size_t input_size)
	{
		CryptoPP::word output;
		m_routine.CalculateDigest(reinterpret_cast<byte*>(&output), input, input_size);
		return output;
	}
}

#endif
