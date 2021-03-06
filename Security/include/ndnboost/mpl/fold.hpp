
#ifndef NDNBOOST_MPL_FOLD_HPP_INCLUDED
#define NDNBOOST_MPL_FOLD_HPP_INCLUDED

// Copyright Aleksey Gurtovoy 2001-2004
// Copyright David Abrahams 2001-2002
//
// Distributed under the Boost Software License, Version 1.0. 
// (See accompanying file LICENSE_1_0.txt or copy at 
// http://www.boost.org/LICENSE_1_0.txt)
//
// See http://www.boost.org/libs/mpl for documentation.

// $Id$
// $Date$
// $Revision$

#include <ndnboost/mpl/begin_end.hpp>
#include <ndnboost/mpl/O1_size.hpp>
#include <ndnboost/mpl/aux_/fold_impl.hpp>
#include <ndnboost/mpl/aux_/na_spec.hpp>
#include <ndnboost/mpl/aux_/lambda_support.hpp>

namespace pkiboost { namespace mpl {

template<
      typename NDNBOOST_MPL_AUX_NA_PARAM(Sequence)
    , typename NDNBOOST_MPL_AUX_NA_PARAM(State)
    , typename NDNBOOST_MPL_AUX_NA_PARAM(ForwardOp)
    >
struct fold
{
    typedef typename aux::fold_impl<
          ::ndnboost::mpl::O1_size<Sequence>::value
        , typename begin<Sequence>::type
        , typename end<Sequence>::type
        , State
        , ForwardOp
        >::state type;

    NDNBOOST_MPL_AUX_LAMBDA_SUPPORT(3,fold,(Sequence,State,ForwardOp))
};

NDNBOOST_MPL_AUX_NA_SPEC(3, fold)

}}

#endif // NDNBOOST_MPL_FOLD_HPP_INCLUDED
