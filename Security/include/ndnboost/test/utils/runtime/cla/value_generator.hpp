//  (C) Copyright Gennadiy Rozental 2005-2008.
//  Use, modification, and distribution are subject to the 
//  Boost Software License, Version 1.0. (See accompanying file 
//  LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)

//  See http://www.boost.org/libs/test for the library home page.
//
//  File        : $RCSfile$
//
//  Version     : $Revision$
//
//  Description : specific value generators
// ***************************************************************************

#ifndef NDNBOOST_RT_CLA_VALUE_GENERATOR_HPP_062604GER
#define NDNBOOST_RT_CLA_VALUE_GENERATOR_HPP_062604GER

// Boost.Runtime.Parameter
#include <ndnboost/test/utils/runtime/config.hpp>

#include <ndnboost/test/utils/runtime/cla/fwd.hpp>
#include <ndnboost/test/utils/runtime/cla/parser.hpp>

namespace pkiboost {

namespace NDNBOOST_RT_PARAM_NAMESPACE {

namespace cla {

namespace rt_cla_detail {

// ************************************************************************** //
// **************        runtime::cla::const_generator         ************** //
// ************************************************************************** //

template<typename T>
class const_generator {
public:
    // Constructor
    explicit    const_generator( T const& t ) : m_const_value( t ) {}

    // generator interface
    void        operator()( parser const&, ndnboost::optional<T>& t ) const   { t = m_const_value; }

private:
    // Data members
    T           m_const_value;
};

// ************************************************************************** //
// **************         runtime::cla::ref_generator          ************** //
// ************************************************************************** //

template<typename T>
class ref_generator {
public:
    // Constructor
    explicit    ref_generator( cstring ref_id ) : m_ref_id( ref_id ) {}

    // generator interface
    void        operator()( parser const& p, ndnboost::optional<T>& t ) const
    {
        p.get( m_ref_id, t );
    }

private:
    // Data members
    cstring     m_ref_id;
};

//____________________________________________________________________________//

} // namespace rt_cla_detail

} // namespace cla

} // namespace NDNBOOST_RT_PARAM_NAMESPACE

} // namespace pkiboost

#endif // NDNBOOST_RT_CLA_VALUE_GENERATOR_HPP_062604GER