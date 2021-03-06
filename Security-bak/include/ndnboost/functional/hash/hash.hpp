
// Copyright 2005-2014 Daniel James.
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)

//  Based on Peter Dimov's proposal
//  http://www.open-std.org/JTC1/SC22/WG21/docs/papers/2005/n1756.pdf
//  issue 6.18. 
//
//  This also contains public domain code from MurmurHash. From the
//  MurmurHash header:

// MurmurHash3 was written by Austin Appleby, and is placed in the public
// domain. The author hereby disclaims copyright to this source code.

#if !defined(NDNBOOST_FUNCTIONAL_HASH_HASH_HPP)
#define NDNBOOST_FUNCTIONAL_HASH_HASH_HPP

#include <ndnboost/functional/hash/hash_fwd.hpp>
#include <functional>
#include <ndnboost/functional/hash/detail/hash_float.hpp>
#include <string>
#include <ndnboost/limits.hpp>
#include <ndnboost/type_traits/is_enum.hpp>
#include <ndnboost/type_traits/is_integral.hpp>
#include <ndnboost/utility/enable_if.hpp>
#include <ndnboost/cstdint.hpp>

#if defined(NDNBOOST_NO_TEMPLATE_PARTIAL_SPECIALIZATION)
#include <ndnboost/type_traits/is_pointer.hpp>
#endif

#if !defined(NDNBOOST_NO_CXX11_HDR_TYPEINDEX)
#include <typeindex>
#endif

#if defined(NDNBOOST_MSVC)
#pragma warning(push)

#if NDNBOOST_MSVC >= 1400
#pragma warning(disable:6295) // Ill-defined for-loop : 'unsigned int' values
                              // are always of range '0' to '4294967295'.
                              // Loop executes infinitely.
#endif

#endif

#if NDNBOOST_WORKAROUND(__GNUC__, < 3) \
    && !defined(__SGI_STL_PORT) && !defined(_STLPORT_VERSION)
#define NDNBOOST_HASH_CHAR_TRAITS string_char_traits
#else
#define NDNBOOST_HASH_CHAR_TRAITS char_traits
#endif

#if defined(_MSC_VER)
#   define NDNBOOST_FUNCTIONAL_HASH_ROTL32(x, r) _rotl(x,r)
#else
#   define NDNBOOST_FUNCTIONAL_HASH_ROTL32(x, r) (x << r) | (x >> (32 - r))
#endif

namespace pkiboost
{
    namespace hash_detail
    {
        struct enable_hash_value { typedef std::size_t type; };

        template <typename T> struct basic_numbers {};
        template <typename T> struct long_numbers;
        template <typename T> struct ulong_numbers;
        template <typename T> struct float_numbers {};

        template <> struct basic_numbers<bool> :
            ndnboost::hash_detail::enable_hash_value {};
        template <> struct basic_numbers<char> :
            ndnboost::hash_detail::enable_hash_value {};
        template <> struct basic_numbers<unsigned char> :
            ndnboost::hash_detail::enable_hash_value {};
        template <> struct basic_numbers<signed char> :
            ndnboost::hash_detail::enable_hash_value {};
        template <> struct basic_numbers<short> :
            ndnboost::hash_detail::enable_hash_value {};
        template <> struct basic_numbers<unsigned short> :
            ndnboost::hash_detail::enable_hash_value {};
        template <> struct basic_numbers<int> :
            ndnboost::hash_detail::enable_hash_value {};
        template <> struct basic_numbers<unsigned int> :
            ndnboost::hash_detail::enable_hash_value {};
        template <> struct basic_numbers<long> :
            ndnboost::hash_detail::enable_hash_value {};
        template <> struct basic_numbers<unsigned long> :
            ndnboost::hash_detail::enable_hash_value {};

#if !defined(NDNBOOST_NO_INTRINSIC_WCHAR_T)
        template <> struct basic_numbers<wchar_t> :
            ndnboost::hash_detail::enable_hash_value {};
#endif

        // long_numbers is defined like this to allow for separate
        // specialization for long_long and int128_type, in case
        // they conflict.
        template <typename T> struct long_numbers2 {};
        template <typename T> struct ulong_numbers2 {};
        template <typename T> struct long_numbers : long_numbers2<T> {};
        template <typename T> struct ulong_numbers : ulong_numbers2<T> {};

#if !defined(NDNBOOST_NO_LONG_LONG)
        template <> struct long_numbers<ndnboost::long_long_type> :
            ndnboost::hash_detail::enable_hash_value {};
        template <> struct ulong_numbers<ndnboost::ulong_long_type> :
            ndnboost::hash_detail::enable_hash_value {};
#endif

#if defined(NDNBOOST_HAS_INT128)
        template <> struct long_numbers2<ndnboost::int128_type> :
            ndnboost::hash_detail::enable_hash_value {};
        template <> struct ulong_numbers2<ndnboost::uint128_type> :
            ndnboost::hash_detail::enable_hash_value {};
#endif

        template <> struct float_numbers<float> :
            ndnboost::hash_detail::enable_hash_value {};
        template <> struct float_numbers<double> :
            ndnboost::hash_detail::enable_hash_value {};
        template <> struct float_numbers<long double> :
            ndnboost::hash_detail::enable_hash_value {};
    }

    template <typename T>
    typename ndnboost::hash_detail::basic_numbers<T>::type hash_value(T);
    template <typename T>
    typename ndnboost::hash_detail::long_numbers<T>::type hash_value(T);
    template <typename T>
    typename ndnboost::hash_detail::ulong_numbers<T>::type hash_value(T);

    template <typename T>
    typename ndnboost::enable_if<ndnboost::is_enum<T>, std::size_t>::type
        hash_value(T);

#if !NDNBOOST_WORKAROUND(__DMC__, <= 0x848)
    template <class T> std::size_t hash_value(T* const&);
#else
    template <class T> std::size_t hash_value(T*);
#endif

#if !defined(NDNBOOST_NO_FUNCTION_TEMPLATE_ORDERING)
    template< class T, unsigned N >
    std::size_t hash_value(const T (&x)[N]);

    template< class T, unsigned N >
    std::size_t hash_value(T (&x)[N]);
#endif

    template <class Ch, class A>
    std::size_t hash_value(
        std::basic_string<Ch, std::NDNBOOST_HASH_CHAR_TRAITS<Ch>, A> const&);

    template <typename T>
    typename ndnboost::hash_detail::float_numbers<T>::type hash_value(T);

#if !defined(NDNBOOST_NO_CXX11_HDR_TYPEINDEX)
    std::size_t hash_value(std::type_index);
#endif

    // Implementation

    namespace hash_detail
    {
        template <class T>
        inline std::size_t hash_value_signed(T val)
        {
             const int size_t_bits = std::numeric_limits<std::size_t>::digits;
             // ceiling(std::numeric_limits<T>::digits / size_t_bits) - 1
             const int length = (std::numeric_limits<T>::digits - 1)
                 / size_t_bits;

             std::size_t seed = 0;
             T positive = val < 0 ? -1 - val : val;

             // Hopefully, this loop can be unrolled.
             for(unsigned int i = length * size_t_bits; i > 0; i -= size_t_bits)
             {
                 seed ^= (std::size_t) (positive >> i) + (seed<<6) + (seed>>2);
             }
             seed ^= (std::size_t) val + (seed<<6) + (seed>>2);

             return seed;
        }

        template <class T>
        inline std::size_t hash_value_unsigned(T val)
        {
             const int size_t_bits = std::numeric_limits<std::size_t>::digits;
             // ceiling(std::numeric_limits<T>::digits / size_t_bits) - 1
             const int length = (std::numeric_limits<T>::digits - 1)
                 / size_t_bits;

             std::size_t seed = 0;

             // Hopefully, this loop can be unrolled.
             for(unsigned int i = length * size_t_bits; i > 0; i -= size_t_bits)
             {
                 seed ^= (std::size_t) (val >> i) + (seed<<6) + (seed>>2);
             }
             seed ^= (std::size_t) val + (seed<<6) + (seed>>2);

             return seed;
        }

        template <typename SizeT>
        inline void hash_combine_impl(SizeT& seed, SizeT value)
        {
            seed ^= value + 0x9e3779b9 + (seed<<6) + (seed>>2);
        }

        template <typename SizeT>
        inline void hash_combine_impl(ndnboost::uint32_t& h1,
                ndnboost::uint32_t k1)
        {
            const uint32_t c1 = 0xcc9e2d51;
            const uint32_t c2 = 0x1b873593;

            k1 *= c1;
            k1 = NDNBOOST_FUNCTIONAL_HASH_ROTL32(k1,15);
            k1 *= c2;

            h1 ^= k1;
            h1 = NDNBOOST_FUNCTIONAL_HASH_ROTL32(h1,13);
            h1 = h1*5+0xe6546b64;
        }


// Don't define 64-bit hash combine on platforms with 64 bit integers,
// and also not for 32-bit gcc as it warns about the 64-bit constant.
#if !defined(NDNBOOST_NO_INT64_T) && \
        !(defined(__GNUC__) && ULONG_MAX == 0xffffffff)

        template <typename SizeT>
        inline void hash_combine_impl(ndnboost::uint64_t& h,
                ndnboost::uint64_t k)
        {
            const uint64_t m = UINT64_C(0xc6a4a7935bd1e995);
            const int r = 47;

            k *= m;
            k ^= k >> r;
            k *= m;

            h ^= k;
            h *= m;
        }

#endif // NDNBOOST_NO_INT64_T
    }

    template <typename T>
    typename ndnboost::hash_detail::basic_numbers<T>::type hash_value(T v)
    {
        return static_cast<std::size_t>(v);
    }

    template <typename T>
    typename ndnboost::hash_detail::long_numbers<T>::type hash_value(T v)
    {
        return hash_detail::hash_value_signed(v);
    }

    template <typename T>
    typename ndnboost::hash_detail::ulong_numbers<T>::type hash_value(T v)
    {
        return hash_detail::hash_value_unsigned(v);
    }

    template <typename T>
    typename ndnboost::enable_if<ndnboost::is_enum<T>, std::size_t>::type
        hash_value(T v)
    {
        return static_cast<std::size_t>(v);
    }

    // Implementation by Alberto Barbati and Dave Harris.
#if !NDNBOOST_WORKAROUND(__DMC__, <= 0x848)
    template <class T> std::size_t hash_value(T* const& v)
#else
    template <class T> std::size_t hash_value(T* v)
#endif
    {
#if defined(__VMS) && __INITIAL_POINTER_SIZE == 64
    // for some reason ptrdiff_t on OpenVMS compiler with
    // 64 bit is not 64 bit !!!
        std::size_t x = static_cast<std::size_t>(
           reinterpret_cast<long long int>(v));
#else
        std::size_t x = static_cast<std::size_t>(
           reinterpret_cast<std::ptrdiff_t>(v));
#endif
        return x + (x >> 3);
    }

#if defined(NDNBOOST_MSVC)
#pragma warning(push)
#if NDNBOOST_MSVC <= 1400
#pragma warning(disable:4267) // 'argument' : conversion from 'size_t' to
                              // 'unsigned int', possible loss of data
                              // A misguided attempt to detect 64-bit
                              // incompatability.
#endif
#endif

    template <class T>
    inline void hash_combine(std::size_t& seed, T const& v)
    {
        ndnboost::hash<T> hasher;
        return ndnboost::hash_detail::hash_combine_impl(seed, hasher(v));
    }

#if defined(NDNBOOST_MSVC)
#pragma warning(pop)
#endif

    template <class It>
    inline std::size_t hash_range(It first, It last)
    {
        std::size_t seed = 0;

        for(; first != last; ++first)
        {
            hash_combine(seed, *first);
        }

        return seed;
    }

    template <class It>
    inline void hash_range(std::size_t& seed, It first, It last)
    {
        for(; first != last; ++first)
        {
            hash_combine(seed, *first);
        }
    }

#if NDNBOOST_WORKAROUND(__BORLANDC__, NDNBOOST_TESTED_AT(0x551))
    template <class T>
    inline std::size_t hash_range(T* first, T* last)
    {
        std::size_t seed = 0;

        for(; first != last; ++first)
        {
            ndnboost::hash<T> hasher;
            seed ^= hasher(*first) + 0x9e3779b9 + (seed<<6) + (seed>>2);
        }

        return seed;
    }

    template <class T>
    inline void hash_range(std::size_t& seed, T* first, T* last)
    {
        for(; first != last; ++first)
        {
            ndnboost::hash<T> hasher;
            seed ^= hasher(*first) + 0x9e3779b9 + (seed<<6) + (seed>>2);
        }
    }
#endif

#if !defined(NDNBOOST_NO_FUNCTION_TEMPLATE_ORDERING)
    template< class T, unsigned N >
    inline std::size_t hash_value(const T (&x)[N])
    {
        return hash_range(x, x + N);
    }

    template< class T, unsigned N >
    inline std::size_t hash_value(T (&x)[N])
    {
        return hash_range(x, x + N);
    }
#endif

    template <class Ch, class A>
    inline std::size_t hash_value(
        std::basic_string<Ch, std::NDNBOOST_HASH_CHAR_TRAITS<Ch>, A> const& v)
    {
        return hash_range(v.begin(), v.end());
    }

    template <typename T>
    typename ndnboost::hash_detail::float_numbers<T>::type hash_value(T v)
    {
        return ndnboost::hash_detail::float_hash_value(v);
    }

#if !defined(NDNBOOST_NO_CXX11_HDR_TYPEINDEX)
    inline std::size_t hash_value(std::type_index v)
    {
        return v.hash_code();
    }
#endif

    //
    // ndnboost::hash
    //
    
    // Define the specializations required by the standard. The general purpose
    // ndnboost::hash is defined later in extensions.hpp if
    // NDNBOOST_HASH_NO_EXTENSIONS is not defined.
    
    // NDNBOOST_HASH_SPECIALIZE - define a specialization for a type which is
    // passed by copy.
    //
    // NDNBOOST_HASH_SPECIALIZE_REF - define a specialization for a type which is
    // passed by copy.
    //
    // These are undefined later.

#define NDNBOOST_HASH_SPECIALIZE(type) \
    template <> struct hash<type> \
         : public std::unary_function<type, std::size_t> \
    { \
        std::size_t operator()(type v) const \
        { \
            return ndnboost::hash_value(v); \
        } \
    };

#define NDNBOOST_HASH_SPECIALIZE_REF(type) \
    template <> struct hash<type> \
         : public std::unary_function<type, std::size_t> \
    { \
        std::size_t operator()(type const& v) const \
        { \
            return ndnboost::hash_value(v); \
        } \
    };

    NDNBOOST_HASH_SPECIALIZE(bool)
    NDNBOOST_HASH_SPECIALIZE(char)
    NDNBOOST_HASH_SPECIALIZE(signed char)
    NDNBOOST_HASH_SPECIALIZE(unsigned char)
#if !defined(NDNBOOST_NO_INTRINSIC_WCHAR_T)
    NDNBOOST_HASH_SPECIALIZE(wchar_t)
#endif
    NDNBOOST_HASH_SPECIALIZE(short)
    NDNBOOST_HASH_SPECIALIZE(unsigned short)
    NDNBOOST_HASH_SPECIALIZE(int)
    NDNBOOST_HASH_SPECIALIZE(unsigned int)
    NDNBOOST_HASH_SPECIALIZE(long)
    NDNBOOST_HASH_SPECIALIZE(unsigned long)

    NDNBOOST_HASH_SPECIALIZE(float)
    NDNBOOST_HASH_SPECIALIZE(double)
    NDNBOOST_HASH_SPECIALIZE(long double)

    NDNBOOST_HASH_SPECIALIZE_REF(std::string)
#if !defined(NDNBOOST_NO_STD_WSTRING)
    NDNBOOST_HASH_SPECIALIZE_REF(std::wstring)
#endif

#if !defined(NDNBOOST_NO_LONG_LONG)
    NDNBOOST_HASH_SPECIALIZE(ndnboost::long_long_type)
    NDNBOOST_HASH_SPECIALIZE(ndnboost::ulong_long_type)
#endif

#if defined(NDNBOOST_HAS_INT128)
    NDNBOOST_HASH_SPECIALIZE(ndnboost::int128_type)
    NDNBOOST_HASH_SPECIALIZE(ndnboost::uint128_type)
#endif

#if !defined(NDNBOOST_NO_CXX11_HDR_TYPEINDEX)
    NDNBOOST_HASH_SPECIALIZE(std::type_index)
#endif

#undef NDNBOOST_HASH_SPECIALIZE
#undef NDNBOOST_HASH_SPECIALIZE_REF

// Specializing ndnboost::hash for pointers.

#if !defined(NDNBOOST_NO_TEMPLATE_PARTIAL_SPECIALIZATION)

    template <class T>
    struct hash<T*>
        : public std::unary_function<T*, std::size_t>
    {
        std::size_t operator()(T* v) const
        {
#if !NDNBOOST_WORKAROUND(__SUNPRO_CC, <= 0x590)
            return ndnboost::hash_value(v);
#else
            std::size_t x = static_cast<std::size_t>(
                reinterpret_cast<std::ptrdiff_t>(v));

            return x + (x >> 3);
#endif
        }
    };

#else

    // For compilers without partial specialization, we define a
    // ndnboost::hash for all remaining types. But hash_impl is only defined
    // for pointers in 'extensions.hpp' - so when NDNBOOST_HASH_NO_EXTENSIONS
    // is defined there will still be a compile error for types not supported
    // in the standard.

    namespace hash_detail
    {
        template <bool IsPointer>
        struct hash_impl;

        template <>
        struct hash_impl<true>
        {
            template <class T>
            struct inner
                : public std::unary_function<T, std::size_t>
            {
                std::size_t operator()(T val) const
                {
#if !NDNBOOST_WORKAROUND(__SUNPRO_CC, <= 590)
                    return ndnboost::hash_value(val);
#else
                    std::size_t x = static_cast<std::size_t>(
                        reinterpret_cast<std::ptrdiff_t>(val));

                    return x + (x >> 3);
#endif
                }
            };
        };
    }

    template <class T> struct hash
        : public ndnboost::hash_detail::hash_impl<ndnboost::is_pointer<T>::value>
            ::NDNBOOST_NESTED_TEMPLATE inner<T>
    {
    };

#endif
}

#undef NDNBOOST_HASH_CHAR_TRAITS
#undef NDNBOOST_FUNCTIONAL_HASH_ROTL32

#if defined(NDNBOOST_MSVC)
#pragma warning(pop)
#endif

#endif // NDNBOOST_FUNCTIONAL_HASH_HASH_HPP

// Include this outside of the include guards in case the file is included
// twice - once with NDNBOOST_HASH_NO_EXTENSIONS defined, and then with it
// undefined.

#if !defined(NDNBOOST_HASH_NO_EXTENSIONS) \
    && !defined(NDNBOOST_FUNCTIONAL_HASH_EXTENSIONS_HPP)
#include <ndnboost/functional/hash/extensions.hpp>
#endif
