//  (C) Copyright Gennadiy Rozental 2001-2008.
//  Distributed under the Boost Software License, Version 1.0.
//  (See accompanying file LICENSE_1_0.txt or copy at 
//  http://www.boost.org/LICENSE_1_0.txt)

//  See http://www.boost.org/libs/test for the library home page.
//
//  File        : $RCSfile$
//
//  Version     : $Revision$
//
//  Description : enhanced result for test predicate that include message explaining failure
// ***************************************************************************

#ifndef NDNBOOST_TEST_PREDICATE_RESULT_HPP_012705GER
#define NDNBOOST_TEST_PREDICATE_RESULT_HPP_012705GER

// Boost.Test
#include <ndnboost/test/utils/class_properties.hpp>
#include <ndnboost/test/utils/wrap_stringstream.hpp>
#include <ndnboost/test/utils/basic_cstring/basic_cstring.hpp>

// Boost
#include <ndnboost/shared_ptr.hpp>
#include <ndnboost/detail/workaround.hpp>

// STL
#include <cstddef>          // for std::size_t

#include <ndnboost/test/detail/suppress_warnings.hpp>

//____________________________________________________________________________//

namespace pkiboost {

namespace test_tools {

// ************************************************************************** //
// **************                predicate_result              ************** //
// ************************************************************************** //

class NDNBOOST_TEST_DECL predicate_result {
    typedef unit_test::const_string      const_string;
    struct dummy { void nonnull() {}; };
    typedef void (dummy::*safe_bool)();

public:
    // Constructor
    predicate_result( bool pv_ ) 
    : p_predicate_value( pv_ )
    {}

    template<typename BoolConvertable>
    predicate_result( BoolConvertable const& pv_ ) : p_predicate_value( !!pv_ ) {}

    // Access methods
    bool                operator!() const           { return !p_predicate_value; }
    void                operator=( bool pv_ )       { p_predicate_value.value = pv_; }
    operator            safe_bool() const           { return !!p_predicate_value ? &dummy::nonnull : 0; }

    // Public properties
    NDNBOOST_READONLY_PROPERTY( bool, (predicate_result) ) p_predicate_value;

    // Access methods
    bool                has_empty_message() const   { return !m_message; }
    wrap_stringstream&  message()
    {
        if( !m_message )
            m_message.reset( new wrap_stringstream );

        return *m_message;
    }
    const_string        message() const                   { return !m_message ? const_string() : const_string( m_message->str() ); }

private:
    // Data members
    shared_ptr<wrap_stringstream> m_message;
};

} // namespace test_tools

} // namespace pkiboost

//____________________________________________________________________________//

#include <ndnboost/test/detail/enable_warnings.hpp>

#endif // NDNBOOST_TEST_PREDICATE_RESULT_HPP_012705GER
