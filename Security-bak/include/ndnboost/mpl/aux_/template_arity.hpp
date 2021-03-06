
#if !defined(NDNBOOST_PP_IS_ITERATING)

///// header body

#ifndef NDNBOOST_MPL_AUX_TEMPLATE_ARITY_HPP_INCLUDED
#define NDNBOOST_MPL_AUX_TEMPLATE_ARITY_HPP_INCLUDED

// Copyright Aleksey Gurtovoy 2001-2004
//
// Distributed under the Boost Software License, Version 1.0. 
// (See accompanying file LICENSE_1_0.txt or copy at 
// http://www.boost.org/LICENSE_1_0.txt)
//
// See http://www.boost.org/libs/mpl for documentation.

// $Id$
// $Date$
// $Revision$

#include <ndnboost/mpl/aux_/config/ttp.hpp>
#include <ndnboost/mpl/aux_/config/lambda.hpp>

#if !defined(NDNBOOST_MPL_PREPROCESSING_MODE)
#   include <ndnboost/mpl/aux_/template_arity_fwd.hpp>
#   include <ndnboost/mpl/int.hpp>
#   if !defined(NDNBOOST_MPL_CFG_NO_FULL_LAMBDA_SUPPORT)
#   if defined(NDNBOOST_MPL_CFG_EXTENDED_TEMPLATE_PARAMETERS_MATCHING)
#       include <ndnboost/mpl/aux_/type_wrapper.hpp>
#   endif
#   else
#       include <ndnboost/mpl/aux_/has_rebind.hpp>
#   endif
#endif

#include <ndnboost/mpl/aux_/config/static_constant.hpp>
#include <ndnboost/mpl/aux_/config/use_preprocessed.hpp>

#if !defined(NDNBOOST_MPL_CFG_NO_PREPROCESSED_HEADERS) \
    && !defined(NDNBOOST_MPL_PREPROCESSING_MODE)

#   define NDNBOOST_MPL_PREPROCESSED_HEADER template_arity.hpp
#   include <ndnboost/mpl/aux_/include_preprocessed.hpp>

#else

#   if !defined(NDNBOOST_MPL_CFG_NO_FULL_LAMBDA_SUPPORT)
#   if defined(NDNBOOST_MPL_CFG_EXTENDED_TEMPLATE_PARAMETERS_MATCHING)

#   include <ndnboost/mpl/limits/arity.hpp>
#   include <ndnboost/mpl/aux_/preprocessor/range.hpp>
#   include <ndnboost/mpl/aux_/preprocessor/repeat.hpp>
#   include <ndnboost/mpl/aux_/preprocessor/params.hpp>
#   include <ndnboost/mpl/aux_/nttp_decl.hpp>

#   include <ndnboost/preprocessor/seq/fold_left.hpp>
#   include <ndnboost/preprocessor/comma_if.hpp>
#   include <ndnboost/preprocessor/iterate.hpp>
#   include <ndnboost/preprocessor/inc.hpp>
#   include <ndnboost/preprocessor/cat.hpp>

#   define AUX778076_ARITY NDNBOOST_PP_INC(NDNBOOST_MPL_LIMIT_METAFUNCTION_ARITY)

namespace pkiboost { namespace mpl { namespace aux {

template< NDNBOOST_MPL_AUX_NTTP_DECL(int, N) > struct arity_tag
{
    typedef char (&type)[N + 1];
};

#   define AUX778076_MAX_ARITY_OP(unused, state, i_) \
    ( NDNBOOST_PP_CAT(C,i_) > 0 ? NDNBOOST_PP_CAT(C,i_) : state ) \
/**/

template<
      NDNBOOST_MPL_PP_PARAMS(AUX778076_ARITY, NDNBOOST_MPL_AUX_NTTP_DECL(int, C))
    >
struct max_arity
{
    NDNBOOST_STATIC_CONSTANT(int, value = 
          NDNBOOST_PP_SEQ_FOLD_LEFT(
              AUX778076_MAX_ARITY_OP
            , -1
            , NDNBOOST_MPL_PP_RANGE(1, AUX778076_ARITY)
            )
        );
};

#   undef AUX778076_MAX_ARITY_OP

arity_tag<0>::type arity_helper(...);

#   define NDNBOOST_PP_ITERATION_LIMITS (1, AUX778076_ARITY)
#   define NDNBOOST_PP_FILENAME_1 <ndnboost/mpl/aux_/template_arity.hpp>
#   include NDNBOOST_PP_ITERATE()

template< typename F, NDNBOOST_MPL_AUX_NTTP_DECL(int, N) >
struct template_arity_impl
{
    NDNBOOST_STATIC_CONSTANT(int, value = 
          sizeof(::ndnboost::mpl::aux::arity_helper(type_wrapper<F>(),arity_tag<N>())) - 1
        );
};

#   define AUX778076_TEMPLATE_ARITY_IMPL_INVOCATION(unused, i_, F) \
    NDNBOOST_PP_COMMA_IF(i_) template_arity_impl<F,NDNBOOST_PP_INC(i_)>::value \
/**/

template< typename F >
struct template_arity
{
    NDNBOOST_STATIC_CONSTANT(int, value = (
          max_arity< NDNBOOST_MPL_PP_REPEAT(
              AUX778076_ARITY
            , AUX778076_TEMPLATE_ARITY_IMPL_INVOCATION
            , F
            ) >::value
        ));
        
    typedef mpl::int_<value> type;
};

#   undef AUX778076_TEMPLATE_ARITY_IMPL_INVOCATION

#   undef AUX778076_ARITY

}}}

#   endif // NDNBOOST_MPL_CFG_EXTENDED_TEMPLATE_PARAMETERS_MATCHING
#   else // NDNBOOST_MPL_CFG_NO_FULL_LAMBDA_SUPPORT

#   include <ndnboost/mpl/aux_/config/eti.hpp>

namespace pkiboost { namespace mpl { namespace aux {

template< bool >
struct template_arity_impl
{
    template< typename F > struct result_
        : mpl::int_<-1>
    {
    };
};

template<>
struct template_arity_impl<true>
{
    template< typename F > struct result_
        : F::arity
    {
    };
};

template< typename F >
struct template_arity
    : template_arity_impl< ::ndnboost::mpl::aux::has_rebind<F>::value >
        ::template result_<F>
{
};

#if defined(NDNBOOST_MPL_CFG_MSVC_ETI_BUG)
template<>
struct template_arity<int>
    : mpl::int_<-1>
{
};
#endif

}}}

#   endif // NDNBOOST_MPL_CFG_NO_FULL_LAMBDA_SUPPORT

#endif // NDNBOOST_MPL_CFG_NO_PREPROCESSED_HEADERS
#endif // NDNBOOST_MPL_AUX_TEMPLATE_ARITY_HPP_INCLUDED

///// iteration

#else
#define i_ NDNBOOST_PP_FRAME_ITERATION(1)

template<
      template< NDNBOOST_MPL_PP_PARAMS(i_, typename P) > class F
    , NDNBOOST_MPL_PP_PARAMS(i_, typename T)
    >
typename arity_tag<i_>::type
arity_helper(type_wrapper< F<NDNBOOST_MPL_PP_PARAMS(i_, T)> >, arity_tag<i_>);

#undef i_
#endif // NDNBOOST_PP_IS_ITERATING
