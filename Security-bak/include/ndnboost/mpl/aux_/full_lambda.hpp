
#if !defined(NDNBOOST_PP_IS_ITERATING)

///// header body

#ifndef NDNBOOST_MPL_AUX_FULL_LAMBDA_HPP_INCLUDED
#define NDNBOOST_MPL_AUX_FULL_LAMBDA_HPP_INCLUDED

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

#if !defined(NDNBOOST_MPL_PREPROCESSING_MODE)
#   include <ndnboost/mpl/lambda_fwd.hpp>
#   include <ndnboost/mpl/bind_fwd.hpp>
#   include <ndnboost/mpl/protect.hpp>
#   include <ndnboost/mpl/quote.hpp>
#   include <ndnboost/mpl/arg.hpp>
#   include <ndnboost/mpl/bool.hpp>
#   include <ndnboost/mpl/int_fwd.hpp>
#   include <ndnboost/mpl/aux_/template_arity.hpp>
#   include <ndnboost/mpl/aux_/na_spec.hpp>
#   include <ndnboost/mpl/aux_/config/ttp.hpp>
#   if defined(NDNBOOST_MPL_CFG_EXTENDED_TEMPLATE_PARAMETERS_MATCHING)
#       include <ndnboost/mpl/if.hpp>
#   endif
#endif

#include <ndnboost/mpl/aux_/lambda_arity_param.hpp>
#include <ndnboost/mpl/aux_/config/use_preprocessed.hpp>

#if !defined(NDNBOOST_MPL_CFG_NO_PREPROCESSED_HEADERS) \
    && !defined(NDNBOOST_MPL_PREPROCESSING_MODE)

#   define NDNBOOST_MPL_PREPROCESSED_HEADER full_lambda.hpp
#   include <ndnboost/mpl/aux_/include_preprocessed.hpp>

#else

#   include <ndnboost/mpl/limits/arity.hpp>
#   include <ndnboost/mpl/aux_/preprocessor/default_params.hpp>
#   include <ndnboost/mpl/aux_/preprocessor/params.hpp>
#   include <ndnboost/mpl/aux_/preprocessor/enum.hpp>
#   include <ndnboost/mpl/aux_/preprocessor/repeat.hpp>
#   include <ndnboost/mpl/aux_/config/dmc_ambiguous_ctps.hpp>

#   include <ndnboost/preprocessor/iterate.hpp>
#   include <ndnboost/preprocessor/comma_if.hpp>
#   include <ndnboost/preprocessor/inc.hpp>
#   include <ndnboost/preprocessor/cat.hpp>

namespace pkiboost { namespace mpl {

// local macros, #undef-ined at the end of the header
#   define AUX778076_LAMBDA_PARAMS(i_, param) \
    NDNBOOST_MPL_PP_PARAMS(i_, param) \
    /**/

#   define AUX778076_BIND_PARAMS(param) \
    NDNBOOST_MPL_PP_PARAMS( \
          NDNBOOST_MPL_LIMIT_METAFUNCTION_ARITY \
        , param \
        ) \
    /**/

#   define AUX778076_BIND_N_PARAMS(i_, param) \
    NDNBOOST_PP_COMMA_IF(i_) \
    NDNBOOST_MPL_PP_PARAMS(i_, param) \
    /**/

#   define AUX778076_ARITY_PARAM(param) \
    NDNBOOST_MPL_AUX_LAMBDA_ARITY_PARAM(param) \
    /**/


#define n_ NDNBOOST_MPL_LIMIT_METAFUNCTION_ARITY
namespace aux {

template<
      NDNBOOST_MPL_PP_DEFAULT_PARAMS(n_,bool C,false)
    >
struct lambda_or
    : true_
{
};

template<>
struct lambda_or< NDNBOOST_MPL_PP_ENUM(n_,false) >
    : false_
{
};

} // namespace aux
#undef n_

template<
      typename T
    , typename Tag
    AUX778076_ARITY_PARAM(typename Arity)
    >
struct lambda
{
    typedef false_ is_le;
    typedef T result_;
    typedef T type;
};

template<
      typename T
    >
struct is_lambda_expression
    : lambda<T>::is_le
{
};


template< int N, typename Tag >
struct lambda< arg<N>,Tag AUX778076_ARITY_PARAM(int_<-1>) >
{
    typedef true_ is_le;
    typedef mpl::arg<N> result_; // qualified for the sake of MIPSpro 7.41
    typedef mpl::protect<result_> type; 
};


#define NDNBOOST_PP_ITERATION_PARAMS_1 \
    (3,(0, NDNBOOST_MPL_LIMIT_METAFUNCTION_ARITY, <ndnboost/mpl/aux_/full_lambda.hpp>))
#include NDNBOOST_PP_ITERATE()

/// special case for 'protect'
template< typename T, typename Tag >
struct lambda< mpl::protect<T>,Tag AUX778076_ARITY_PARAM(int_<1>) >
{
    typedef false_ is_le;
    typedef mpl::protect<T> result_;
    typedef result_ type;
};

/// specializations for the main 'bind' form
template<
      typename F, AUX778076_BIND_PARAMS(typename T)
    , typename Tag
    >
struct lambda<
          bind<F,AUX778076_BIND_PARAMS(T)>
        , Tag
        AUX778076_ARITY_PARAM(int_<NDNBOOST_PP_INC(NDNBOOST_MPL_LIMIT_METAFUNCTION_ARITY)>)
        >
{
    typedef false_ is_le;
    typedef bind<F, AUX778076_BIND_PARAMS(T)> result_;
    typedef result_ type;
};


#if defined(NDNBOOST_MPL_CFG_EXTENDED_TEMPLATE_PARAMETERS_MATCHING)

template<
      typename F
    , typename Tag1
    , typename Tag2
    , typename Arity
    >
struct lambda<
          lambda<F,Tag1,Arity>
        , Tag2
        , int_<3>
        >
{
    typedef lambda< F,Tag2 > l1;
    typedef lambda< Tag1,Tag2 > l2;

    typedef typename l1::is_le is_le;
    typedef bind1< quote1<aux::template_arity>, typename l1::result_ > arity_;
    typedef lambda< typename if_<is_le,arity_,Arity>::type,Tag2 > l3;
    
    typedef aux::le_result3<is_le, Tag2, mpl::lambda, l1, l2, l3> le_result_;
    typedef typename le_result_::result_ result_;
    typedef typename le_result_::type type;
};

#elif !defined(NDNBOOST_MPL_CFG_DMC_AMBIGUOUS_CTPS)

/// workaround for MWCW 8.3+/EDG < 303, leads to ambiguity on Digital Mars
template<
      typename F, typename Tag1, typename Tag2
    >
struct lambda<
          lambda< F,Tag1 >
        , Tag2
        >
{
    typedef lambda< F,Tag2 > l1;
    typedef lambda< Tag1,Tag2 > l2;
    
    typedef typename l1::is_le is_le;
    typedef aux::le_result2<is_le, Tag2, mpl::lambda, l1, l2> le_result_;
    typedef typename le_result_::result_ result_;
    typedef typename le_result_::type type;
};

#endif

#   undef AUX778076_ARITY_PARAM
#   undef AUX778076_BIND_N_PARAMS
#   undef AUX778076_BIND_PARAMS
#   undef AUX778076_LAMBDA_PARAMS

#if !defined(NDNBOOST_MPL_CFG_EXTENDED_TEMPLATE_PARAMETERS_MATCHING)
NDNBOOST_MPL_AUX_NA_SPEC(2, lambda)
#else
NDNBOOST_MPL_AUX_NA_SPEC2(2, 3, lambda)
#endif

}}

#endif // NDNBOOST_MPL_CFG_NO_PREPROCESSED_HEADERS
#endif // NDNBOOST_MPL_AUX_FULL_LAMBDA_HPP_INCLUDED

///// iteration, depth == 1

// For gcc 4.4 compatability, we must include the
// NDNBOOST_PP_ITERATION_DEPTH test inside an #else clause.
#else // NDNBOOST_PP_IS_ITERATING
#if NDNBOOST_PP_ITERATION_DEPTH() == 1
#define i_ NDNBOOST_PP_FRAME_ITERATION(1)

#if i_ > 0

namespace aux {

#   define AUX778076_RESULT(unused, i_, T) \
    NDNBOOST_PP_COMMA_IF(i_) \
    typename NDNBOOST_PP_CAT(T, NDNBOOST_PP_INC(i_))::result_ \
    /**/

#   define AUX778076_TYPE(unused, i_, T) \
    NDNBOOST_PP_COMMA_IF(i_) \
    typename NDNBOOST_PP_CAT(T, NDNBOOST_PP_INC(i_))::type \
    /**/

template<
      typename IsLE, typename Tag
    , template< AUX778076_LAMBDA_PARAMS(i_, typename P) > class F
    , AUX778076_LAMBDA_PARAMS(i_, typename L)
    >
struct NDNBOOST_PP_CAT(le_result,i_)
{
    typedef F<
          NDNBOOST_MPL_PP_REPEAT(i_, AUX778076_TYPE, L)
        > result_;
    
    typedef result_ type;
};

template<
      typename Tag
    , template< AUX778076_LAMBDA_PARAMS(i_, typename P) > class F
    , AUX778076_LAMBDA_PARAMS(i_, typename L)
    >
struct NDNBOOST_PP_CAT(le_result,i_)< true_,Tag,F,AUX778076_LAMBDA_PARAMS(i_, L) >
{
    typedef NDNBOOST_PP_CAT(bind,i_)<
          NDNBOOST_PP_CAT(quote,i_)<F,Tag>
        , NDNBOOST_MPL_PP_REPEAT(i_, AUX778076_RESULT, L)
        > result_;

    typedef mpl::protect<result_> type;
};

#   undef AUX778076_TYPE
#   undef AUX778076_RESULT

} // namespace aux


#   define AUX778076_LAMBDA_TYPEDEF(unused, i_, T) \
    typedef lambda< NDNBOOST_PP_CAT(T, NDNBOOST_PP_INC(i_)), Tag > \
        NDNBOOST_PP_CAT(l,NDNBOOST_PP_INC(i_)); \
/**/

#   define AUX778076_IS_LE_TYPEDEF(unused, i_, unused2) \
    typedef typename NDNBOOST_PP_CAT(l,NDNBOOST_PP_INC(i_))::is_le \
        NDNBOOST_PP_CAT(is_le,NDNBOOST_PP_INC(i_)); \
/**/

#   define AUX778076_IS_LAMBDA_EXPR(unused, i_, unused2) \
    NDNBOOST_PP_COMMA_IF(i_) \
    NDNBOOST_PP_CAT(is_le,NDNBOOST_PP_INC(i_))::value \
/**/

template<
      template< AUX778076_LAMBDA_PARAMS(i_, typename P) > class F
    , AUX778076_LAMBDA_PARAMS(i_, typename T)
    , typename Tag
    >
struct lambda< 
          F<AUX778076_LAMBDA_PARAMS(i_, T)>
        , Tag
        AUX778076_ARITY_PARAM(int_<i_>)
        >
{
    NDNBOOST_MPL_PP_REPEAT(i_, AUX778076_LAMBDA_TYPEDEF, T)
    NDNBOOST_MPL_PP_REPEAT(i_, AUX778076_IS_LE_TYPEDEF, unused)

    typedef typename aux::lambda_or<
          NDNBOOST_MPL_PP_REPEAT(i_, AUX778076_IS_LAMBDA_EXPR, unused)
        >::type is_le;

    typedef aux::NDNBOOST_PP_CAT(le_result,i_)<
          is_le, Tag, F, AUX778076_LAMBDA_PARAMS(i_, l)
        > le_result_;
    
    typedef typename le_result_::result_ result_;
    typedef typename le_result_::type type;
};


#   undef AUX778076_IS_LAMBDA_EXPR
#   undef AUX778076_IS_LE_TYPEDEF
#   undef AUX778076_LAMBDA_TYPEDEF

#endif // i_ > 0

template<
      typename F AUX778076_BIND_N_PARAMS(i_, typename T)
    , typename Tag
    >
struct lambda<
          NDNBOOST_PP_CAT(bind,i_)<F AUX778076_BIND_N_PARAMS(i_, T)>
        , Tag
        AUX778076_ARITY_PARAM(int_<NDNBOOST_PP_INC(i_)>)
        >
{
    typedef false_ is_le;
    typedef NDNBOOST_PP_CAT(bind,i_)<
          F
        AUX778076_BIND_N_PARAMS(i_, T)
        > result_;
        
    typedef result_ type;
};

#undef i_
#endif // NDNBOOST_PP_ITERATION_DEPTH()
#endif // NDNBOOST_PP_IS_ITERATING
