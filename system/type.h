
#ifndef _EJA_TYPE_
#define _EJA_TYPE_

#include <limits>
#include <boost/cstdint.hpp>

// Int (signed)
using s8 = boost::int_fast8_t;
#define s8_max std::numeric_limits<s8>::max()

using s16 = boost::int_fast16_t;
#define s16_max std::numeric_limits<s16>::max()

using s32 = boost::int_fast32_t;
#define s32_max std::numeric_limits<s32>::max()

using s64 = boost::int_fast64_t;
#define s64_max std::numeric_limits<s64>::max()

// Int (unsigned)
using u8 = boost::uint_fast8_t;
using byte = boost::uint_fast8_t;
#define u8_max std::numeric_limits<u8>::max()

using u16 = boost::uint_fast16_t;
#define u16_max std::numeric_limits<u16>::max()

using u32 = boost::uint_fast32_t;
#define u32_max std::numeric_limits<u32>::max()

using u64 = boost::uint_fast64_t;
#define u64_max std::numeric_limits<u64>::max()

// Long (unsigned)
using ulong = unsigned long;

// Real
#if SIZE_MAX == 0xffffffff
using real = float;
#define real_max std::numeric_limits<real>::max()
#else
using real = double;
#define real_max std::numeric_limits<real>::max()
#endif

#endif
