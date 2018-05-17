
// Copyright Aleksey Gurtovoy 2000-2004
//
// Distributed under the Boost Software License, Version 1.0. 
// (See accompanying file LICENSE_1_0.txt or copy at 
// http://www.boost.org/LICENSE_1_0.txt)
//

// Preprocessed version of "ndnboost/mpl/plus.hpp" header
// -- DO NOT modify by hand!

namespace pkiboost { namespace mpl {

template<
      typename Tag1
    , typename Tag2
    >
struct plus_impl
    : if_c<
          ( NDNBOOST_MPL_AUX_NESTED_VALUE_WKND(int, Tag1)
              > NDNBOOST_MPL_AUX_NESTED_VALUE_WKND(int, Tag2)
            )

        , aux::cast2nd_impl< plus_impl< Tag1,Tag1 >,Tag1, Tag2 >
        , aux::cast1st_impl< plus_impl< Tag2,Tag2 >,Tag1, Tag2 >
        >::type
{
};

/// for Digital Mars C++/compilers with no CTPS/TTP support
template<> struct plus_impl< na,na >
{
    template< typename U1, typename U2 > struct apply
    {
        typedef apply type;
        NDNBOOST_STATIC_CONSTANT(int, value  = 0);
    };
};

template<> struct plus_impl< na,integral_c_tag >
{
    template< typename U1, typename U2 > struct apply
    {
        typedef apply type;
        NDNBOOST_STATIC_CONSTANT(int, value  = 0);
    };
};

template<> struct plus_impl< integral_c_tag,na >
{
    template< typename U1, typename U2 > struct apply
    {
        typedef apply type;
        NDNBOOST_STATIC_CONSTANT(int, value  = 0);
    };
};

template< typename T > struct plus_tag
{
    typedef typename T::tag type;
};

/// forward declaration

template<
      typename NDNBOOST_MPL_AUX_NA_PARAM(N1)
    , typename NDNBOOST_MPL_AUX_NA_PARAM(N2)
    >
struct plus2;

template<
      typename NDNBOOST_MPL_AUX_NA_PARAM(N1)
    , typename NDNBOOST_MPL_AUX_NA_PARAM(N2)
    , typename N3 = na, typename N4 = na, typename N5 = na
    >
struct plus

    : if_<

          is_na<N3>
        , plus2< N1,N2 >
        , plus<
              plus2< N1,N2 >
            , N3, N4, N5
            >
        >::type

{
    NDNBOOST_MPL_AUX_LAMBDA_SUPPORT(
          5
        , plus
        , ( N1, N2, N3, N4, N5 )
        )
};

template<
      typename N1
    , typename N2
    >
struct plus2
    : plus_impl<
          typename plus_tag<N1>::type
        , typename plus_tag<N2>::type
        >::template apply< N1,N2 >::type
{
    NDNBOOST_MPL_AUX_LAMBDA_SUPPORT(2, plus2, (N1, N2))

};

NDNBOOST_MPL_AUX_NA_SPEC2(2, 5, plus)

}}

namespace pkiboost { namespace mpl {
template<>
struct plus_impl< integral_c_tag,integral_c_tag >
{
    template< typename N1, typename N2 > struct apply

        : integral_c<
              typename aux::largest_int<
                  typename N1::value_type
                , typename N2::value_type
                >::type
            , ( NDNBOOST_MPL_AUX_VALUE_WKND(N1)::value
                  + NDNBOOST_MPL_AUX_VALUE_WKND(N2)::value
                )
            >
    {
    };
};

}}
