
//  (C) Copyright John maddock 1999. 
//  (C) David Abrahams 2002.  Distributed under the Boost
//  Software License, Version 1.0. (See accompanying file
//  LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// use this header as a workaround for missing <limits>

//  See http://www.boost.org/libs/compatibility/index.html for documentation.

#ifndef NDNBOOST_LIMITS
#define NDNBOOST_LIMITS

#include <ndnboost/config.hpp>

#ifdef NDNBOOST_NO_LIMITS
#  error "There is no std::numeric_limits suppport available."
#else
# include <limits>
#endif

#if (defined(NDNBOOST_HAS_LONG_LONG) && defined(NDNBOOST_NO_LONG_LONG_NUMERIC_LIMITS)) \
      || (defined(NDNBOOST_HAS_MS_INT64) && defined(NDNBOOST_NO_MS_INT64_NUMERIC_LIMITS))
// Add missing specializations for numeric_limits:
#ifdef NDNBOOST_HAS_MS_INT64
#  define NDNBOOST_LLT __int64
#  define NDNBOOST_ULLT unsigned __int64
#else
#  define NDNBOOST_LLT  ::ndnboost::long_long_type
#  define NDNBOOST_ULLT  ::ndnboost::ulong_long_type
#endif

#include <climits>  // for CHAR_BIT

namespace std
{
  template<>
  class numeric_limits<NDNBOOST_LLT> 
  {
   public:

      NDNBOOST_STATIC_CONSTANT(bool, is_specialized = true);
#ifdef NDNBOOST_HAS_MS_INT64
      static NDNBOOST_LLT min NDNBOOST_PREVENT_MACRO_SUBSTITUTION (){ return 0x8000000000000000i64; }
      static NDNBOOST_LLT max NDNBOOST_PREVENT_MACRO_SUBSTITUTION (){ return 0x7FFFFFFFFFFFFFFFi64; }
#elif defined(LLONG_MAX)
      static NDNBOOST_LLT min NDNBOOST_PREVENT_MACRO_SUBSTITUTION (){ return LLONG_MIN; }
      static NDNBOOST_LLT max NDNBOOST_PREVENT_MACRO_SUBSTITUTION (){ return LLONG_MAX; }
#elif defined(LONGLONG_MAX)
      static NDNBOOST_LLT min NDNBOOST_PREVENT_MACRO_SUBSTITUTION (){ return LONGLONG_MIN; }
      static NDNBOOST_LLT max NDNBOOST_PREVENT_MACRO_SUBSTITUTION (){ return LONGLONG_MAX; }
#else
      static NDNBOOST_LLT min NDNBOOST_PREVENT_MACRO_SUBSTITUTION (){ return 1LL << (sizeof(NDNBOOST_LLT) * CHAR_BIT - 1); }
      static NDNBOOST_LLT max NDNBOOST_PREVENT_MACRO_SUBSTITUTION (){ return ~(min)(); }
#endif
      NDNBOOST_STATIC_CONSTANT(int, digits = sizeof(NDNBOOST_LLT) * CHAR_BIT -1);
      NDNBOOST_STATIC_CONSTANT(int, digits10 = (CHAR_BIT * sizeof (NDNBOOST_LLT) - 1) * 301L / 1000);
      NDNBOOST_STATIC_CONSTANT(bool, is_signed = true);
      NDNBOOST_STATIC_CONSTANT(bool, is_integer = true);
      NDNBOOST_STATIC_CONSTANT(bool, is_exact = true);
      NDNBOOST_STATIC_CONSTANT(int, radix = 2);
      static NDNBOOST_LLT epsilon() throw() { return 0; };
      static NDNBOOST_LLT round_error() throw() { return 0; };

      NDNBOOST_STATIC_CONSTANT(int, min_exponent = 0);
      NDNBOOST_STATIC_CONSTANT(int, min_exponent10 = 0);
      NDNBOOST_STATIC_CONSTANT(int, max_exponent = 0);
      NDNBOOST_STATIC_CONSTANT(int, max_exponent10 = 0);

      NDNBOOST_STATIC_CONSTANT(bool, has_infinity = false);
      NDNBOOST_STATIC_CONSTANT(bool, has_quiet_NaN = false);
      NDNBOOST_STATIC_CONSTANT(bool, has_signaling_NaN = false);
      NDNBOOST_STATIC_CONSTANT(bool, has_denorm = false);
      NDNBOOST_STATIC_CONSTANT(bool, has_denorm_loss = false);
      static NDNBOOST_LLT infinity() throw() { return 0; };
      static NDNBOOST_LLT quiet_NaN() throw() { return 0; };
      static NDNBOOST_LLT signaling_NaN() throw() { return 0; };
      static NDNBOOST_LLT denorm_min() throw() { return 0; };

      NDNBOOST_STATIC_CONSTANT(bool, is_iec559 = false);
      NDNBOOST_STATIC_CONSTANT(bool, is_bounded = true);
      NDNBOOST_STATIC_CONSTANT(bool, is_modulo = true);

      NDNBOOST_STATIC_CONSTANT(bool, traps = false);
      NDNBOOST_STATIC_CONSTANT(bool, tinyness_before = false);
      NDNBOOST_STATIC_CONSTANT(float_round_style, round_style = round_toward_zero);
      
  };

  template<>
  class numeric_limits<NDNBOOST_ULLT> 
  {
   public:

      NDNBOOST_STATIC_CONSTANT(bool, is_specialized = true);
#ifdef NDNBOOST_HAS_MS_INT64
      static NDNBOOST_ULLT min NDNBOOST_PREVENT_MACRO_SUBSTITUTION (){ return 0ui64; }
      static NDNBOOST_ULLT max NDNBOOST_PREVENT_MACRO_SUBSTITUTION (){ return 0xFFFFFFFFFFFFFFFFui64; }
#elif defined(ULLONG_MAX) && defined(ULLONG_MIN)
      static NDNBOOST_ULLT min NDNBOOST_PREVENT_MACRO_SUBSTITUTION (){ return ULLONG_MIN; }
      static NDNBOOST_ULLT max NDNBOOST_PREVENT_MACRO_SUBSTITUTION (){ return ULLONG_MAX; }
#elif defined(ULONGLONG_MAX) && defined(ULONGLONG_MIN)
      static NDNBOOST_ULLT min NDNBOOST_PREVENT_MACRO_SUBSTITUTION (){ return ULONGLONG_MIN; }
      static NDNBOOST_ULLT max NDNBOOST_PREVENT_MACRO_SUBSTITUTION (){ return ULONGLONG_MAX; }
#else
      static NDNBOOST_ULLT min NDNBOOST_PREVENT_MACRO_SUBSTITUTION (){ return 0uLL; }
      static NDNBOOST_ULLT max NDNBOOST_PREVENT_MACRO_SUBSTITUTION (){ return ~0uLL; }
#endif
      NDNBOOST_STATIC_CONSTANT(int, digits = sizeof(NDNBOOST_LLT) * CHAR_BIT);
      NDNBOOST_STATIC_CONSTANT(int, digits10 = (CHAR_BIT * sizeof (NDNBOOST_LLT)) * 301L / 1000);
      NDNBOOST_STATIC_CONSTANT(bool, is_signed = false);
      NDNBOOST_STATIC_CONSTANT(bool, is_integer = true);
      NDNBOOST_STATIC_CONSTANT(bool, is_exact = true);
      NDNBOOST_STATIC_CONSTANT(int, radix = 2);
      static NDNBOOST_ULLT epsilon() throw() { return 0; };
      static NDNBOOST_ULLT round_error() throw() { return 0; };

      NDNBOOST_STATIC_CONSTANT(int, min_exponent = 0);
      NDNBOOST_STATIC_CONSTANT(int, min_exponent10 = 0);
      NDNBOOST_STATIC_CONSTANT(int, max_exponent = 0);
      NDNBOOST_STATIC_CONSTANT(int, max_exponent10 = 0);

      NDNBOOST_STATIC_CONSTANT(bool, has_infinity = false);
      NDNBOOST_STATIC_CONSTANT(bool, has_quiet_NaN = false);
      NDNBOOST_STATIC_CONSTANT(bool, has_signaling_NaN = false);
      NDNBOOST_STATIC_CONSTANT(bool, has_denorm = false);
      NDNBOOST_STATIC_CONSTANT(bool, has_denorm_loss = false);
      static NDNBOOST_ULLT infinity() throw() { return 0; };
      static NDNBOOST_ULLT quiet_NaN() throw() { return 0; };
      static NDNBOOST_ULLT signaling_NaN() throw() { return 0; };
      static NDNBOOST_ULLT denorm_min() throw() { return 0; };

      NDNBOOST_STATIC_CONSTANT(bool, is_iec559 = false);
      NDNBOOST_STATIC_CONSTANT(bool, is_bounded = true);
      NDNBOOST_STATIC_CONSTANT(bool, is_modulo = true);

      NDNBOOST_STATIC_CONSTANT(bool, traps = false);
      NDNBOOST_STATIC_CONSTANT(bool, tinyness_before = false);
      NDNBOOST_STATIC_CONSTANT(float_round_style, round_style = round_toward_zero);
      
  };
}
#endif 

#endif

