//  (c) Copyright Fernando Luis Cacciola Carballal 2000-2004
//  Use, modification, and distribution is subject to the Boost Software
//  License, Version 1.0. (See accompanying file LICENSE_1_0.txt or copy at
//  http://www.boost.org/LICENSE_1_0.txt)

//  See library home page at http://www.boost.org/libs/numeric/conversion
//
// Contact the author at: fernando_cacciola@hotmail.com
// 
#ifndef NDNBOOST_NUMERIC_CONVERSION_CONVERTER_FLC_12NOV2002_HPP
#define NDNBOOST_NUMERIC_CONVERSION_CONVERTER_FLC_12NOV2002_HPP

#include "ndnboost/numeric/conversion/conversion_traits.hpp"
#include "ndnboost/numeric/conversion/converter_policies.hpp"

#include "ndnboost/numeric/conversion/detail/converter.hpp"

namespace pkiboost { namespace numeric 
{

template<class T,
         class S,
         class Traits           = conversion_traits<T,S>,
         class OverflowHandler  = def_overflow_handler,
         class Float2IntRounder = Trunc< NDNBOOST_DEDUCED_TYPENAME Traits::source_type>  ,
         class RawConverter     = raw_converter<Traits>,
         class UserRangeChecker = UseInternalRangeChecker
        >
struct converter : convdetail::get_converter_impl<Traits,
                                                  OverflowHandler,
                                                  Float2IntRounder,
                                                  RawConverter,
                                                  UserRangeChecker
                                                 >::type
{
  typedef Traits traits ;

  typedef typename Traits::argument_type argument_type ;
  typedef typename Traits::result_type   result_type   ;

  result_type operator() ( argument_type s ) const { return this->convert(s) ; }
} ;



template<class S,
         class OverflowHandler  = def_overflow_handler,
         class Float2IntRounder = Trunc<S>  ,
         class UserRangeChecker = UseInternalRangeChecker
        >
struct make_converter_from
{
  template<class T,
           class Traits       = conversion_traits<T,S>,
           class RawConverter = raw_converter<Traits>
          > 
  struct to
  {
    typedef converter<T,S,Traits,OverflowHandler,Float2IntRounder,RawConverter,UserRangeChecker> type ;
  } ;

} ;

} } // namespace pkiboost::numeric

#endif


