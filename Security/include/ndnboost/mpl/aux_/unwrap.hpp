
#ifndef NDNBOOST_MPL_AUX_UNWRAP_HPP_INCLUDED
#define NDNBOOST_MPL_AUX_UNWRAP_HPP_INCLUDED

// Copyright Peter Dimov and Multi Media Ltd 2001, 2002
// Copyright David Abrahams 2001
//
// Distributed under the Boost Software License, Version 1.0. 
// (See accompanying file LICENSE_1_0.txt or copy at 
// http://www.boost.org/LICENSE_1_0.txt)
//
// See http://www.boost.org/libs/mpl for documentation.

// $Id$
// $Date$
// $Revision$

#include <ndnboost/ref.hpp>
#include <ndnboost/mpl/aux_/config/gpu.hpp>

namespace pkiboost { namespace mpl { namespace aux {

template< typename F >
NDNBOOST_MPL_CFG_GPU_ENABLED
inline
F& unwrap(F& f, long)
{
    return f;
}

template< typename F >
NDNBOOST_MPL_CFG_GPU_ENABLED
inline
F&
unwrap(reference_wrapper<F>& f, int)
{
    return f;
}

template< typename F >
NDNBOOST_MPL_CFG_GPU_ENABLED
inline
F&
unwrap(reference_wrapper<F> const& f, int)
{
    return f;
}

}}}

#endif // NDNBOOST_MPL_AUX_UNWRAP_HPP_INCLUDED
