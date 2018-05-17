
//  (C) Copyright John Maddock 2007.
//  Use, modification and distribution are subject to the Boost Software License,
//  Version 1.0. (See accompanying file LICENSE_1_0.txt or copy at
//  http://www.boost.org/LICENSE_1_0.txt).
//
//  See http://www.boost.org/libs/type_traits for most recent version including documentation.

#ifndef NDNBOOST_TT_MAKE_UNSIGNED_HPP_INCLUDED
#define NDNBOOST_TT_MAKE_UNSIGNED_HPP_INCLUDED

#include <ndnboost/mpl/if.hpp>
#include <ndnboost/type_traits/is_integral.hpp>
#include <ndnboost/type_traits/is_signed.hpp>
#include <ndnboost/type_traits/is_unsigned.hpp>
#include <ndnboost/type_traits/is_enum.hpp>
#include <ndnboost/type_traits/is_same.hpp>
#include <ndnboost/type_traits/remove_cv.hpp>
#include <ndnboost/type_traits/is_const.hpp>
#include <ndnboost/type_traits/is_volatile.hpp>
#include <ndnboost/type_traits/add_const.hpp>
#include <ndnboost/type_traits/add_volatile.hpp>
#include <ndnboost/type_traits/detail/ice_or.hpp>
#include <ndnboost/type_traits/detail/ice_and.hpp>
#include <ndnboost/type_traits/detail/ice_not.hpp>
#include <ndnboost/static_assert.hpp>

// should be the last #include
#include <ndnboost/type_traits/detail/type_trait_def.hpp>

namespace pkiboost {

namespace detail {

template <class T>
struct make_unsigned_imp
{
   NDNBOOST_STATIC_ASSERT(
      (::ndnboost::type_traits::ice_or< ::ndnboost::is_integral<T>::value, ::ndnboost::is_enum<T>::value>::value));
   NDNBOOST_STATIC_ASSERT(
      (::ndnboost::type_traits::ice_not< ::ndnboost::is_same<
         typename remove_cv<T>::type, bool>::value>::value));

   typedef typename remove_cv<T>::type t_no_cv;
   typedef typename mpl::if_c<
      (::ndnboost::type_traits::ice_and< 
         ::ndnboost::is_unsigned<T>::value,
         ::ndnboost::is_integral<T>::value,
         ::ndnboost::type_traits::ice_not< ::ndnboost::is_same<t_no_cv, char>::value>::value,
         ::ndnboost::type_traits::ice_not< ::ndnboost::is_same<t_no_cv, wchar_t>::value>::value,
         ::ndnboost::type_traits::ice_not< ::ndnboost::is_same<t_no_cv, bool>::value>::value >::value),
      T,
      typename mpl::if_c<
         (::ndnboost::type_traits::ice_and< 
            ::ndnboost::is_integral<T>::value,
            ::ndnboost::type_traits::ice_not< ::ndnboost::is_same<t_no_cv, char>::value>::value,
            ::ndnboost::type_traits::ice_not< ::ndnboost::is_same<t_no_cv, wchar_t>::value>::value,
            ::ndnboost::type_traits::ice_not< ::ndnboost::is_same<t_no_cv, bool>::value>::value>
         ::value),
         typename mpl::if_<
            is_same<t_no_cv, signed char>,
            unsigned char,
            typename mpl::if_<
               is_same<t_no_cv, short>,
               unsigned short,
               typename mpl::if_<
                  is_same<t_no_cv, int>,
                  unsigned int,
                  typename mpl::if_<
                     is_same<t_no_cv, long>,
                     unsigned long,
#if defined(NDNBOOST_HAS_LONG_LONG)
#ifdef NDNBOOST_HAS_INT128
                     typename mpl::if_c<
                        sizeof(t_no_cv) == sizeof(ndnboost::ulong_long_type), 
                        ndnboost::ulong_long_type, 
                        ndnboost::uint128_type
                     >::type
#else
                     ndnboost::ulong_long_type
#endif
#elif defined(NDNBOOST_HAS_MS_INT64)
                     unsigned __int64
#else
                     unsigned long
#endif
                  >::type
               >::type
            >::type
         >::type,
         // Not a regular integer type:
         typename mpl::if_c<
            sizeof(t_no_cv) == sizeof(unsigned char),
            unsigned char,
            typename mpl::if_c<
               sizeof(t_no_cv) == sizeof(unsigned short),
               unsigned short,
               typename mpl::if_c<
                  sizeof(t_no_cv) == sizeof(unsigned int),
                  unsigned int,
                  typename mpl::if_c<
                     sizeof(t_no_cv) == sizeof(unsigned long),
                     unsigned long,
#if defined(NDNBOOST_HAS_LONG_LONG)
#ifdef NDNBOOST_HAS_INT128
                     typename mpl::if_c<
                        sizeof(t_no_cv) == sizeof(ndnboost::ulong_long_type), 
                        ndnboost::ulong_long_type, 
                        ndnboost::uint128_type
                     >::type
#else
                     ndnboost::ulong_long_type
#endif
#elif defined(NDNBOOST_HAS_MS_INT64)
                     unsigned __int64
#else
                     unsigned long
#endif
                  >::type
               >::type
            >::type
         >::type
      >::type
   >::type base_integer_type;
   
   // Add back any const qualifier:
   typedef typename mpl::if_<
      is_const<T>,
      typename add_const<base_integer_type>::type,
      base_integer_type
   >::type const_base_integer_type;
   
   // Add back any volatile qualifier:
   typedef typename mpl::if_<
      is_volatile<T>,
      typename add_volatile<const_base_integer_type>::type,
      const_base_integer_type
   >::type type;
};


} // namespace detail

NDNBOOST_TT_AUX_TYPE_TRAIT_DEF1(make_unsigned,T,typename ndnboost::detail::make_unsigned_imp<T>::type)

} // namespace pkiboost

#include <ndnboost/type_traits/detail/type_trait_undef.hpp>

#endif // NDNBOOST_TT_ADD_REFERENCE_HPP_INCLUDED
