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
//  Description : defines class unit_test_result that is responsible for 
//  gathering test results and presenting this information to end-user
// ***************************************************************************

#ifndef NDNBOOST_TEST_RESULTS_REPORTER_HPP_021205GER
#define NDNBOOST_TEST_RESULTS_REPORTER_HPP_021205GER

// Boost.Test
#include <ndnboost/test/detail/global_typedef.hpp>
#include <ndnboost/test/detail/fwd_decl.hpp>

// STL
#include <iosfwd>   // for std::ostream&

#include <ndnboost/test/detail/suppress_warnings.hpp>

//____________________________________________________________________________//

namespace pkiboost {

namespace unit_test {

namespace results_reporter {

// ************************************************************************** //
// **************              formatter interface             ************** //
// ************************************************************************** //

class NDNBOOST_TEST_DECL format {
public:
    // Destructor
    virtual ~format() {}

    virtual void    results_report_start( std::ostream& ostr ) = 0;
    virtual void    results_report_finish( std::ostream& ostr ) = 0;

    virtual void    test_unit_report_start( test_unit const&, std::ostream& ostr ) = 0;
    virtual void    test_unit_report_finish( test_unit const&, std::ostream& ostr ) = 0;

    virtual void    do_confirmation_report( test_unit const&, std::ostream& ostr ) = 0;
};

// ************************************************************************** //
// **************              report configuration            ************** //
// ************************************************************************** //

NDNBOOST_TEST_DECL void    set_level( report_level );
NDNBOOST_TEST_DECL void    set_stream( std::ostream& );
NDNBOOST_TEST_DECL void    set_format( output_format );
NDNBOOST_TEST_DECL void    set_format( results_reporter::format* );

NDNBOOST_TEST_DECL std::ostream& get_stream();

// ************************************************************************** //
// **************               report initiation              ************** //
// ************************************************************************** //

NDNBOOST_TEST_DECL void    make_report( report_level l = INV_REPORT_LEVEL, test_unit_id = INV_TEST_UNIT_ID );
inline void             confirmation_report( test_unit_id id = INV_TEST_UNIT_ID )   
{ make_report( CONFIRMATION_REPORT, id ); }
inline void             short_report( test_unit_id id = INV_TEST_UNIT_ID )
{ make_report( SHORT_REPORT, id ); }
inline void             detailed_report( test_unit_id id = INV_TEST_UNIT_ID )
{ make_report( DETAILED_REPORT, id ); }

} // namespace results_reporter

} // namespace unit_test

} // namespace pkiboost

//____________________________________________________________________________//

#include <ndnboost/test/detail/enable_warnings.hpp>

#endif // NDNBOOST_TEST_RESULTS_REPORTER_HPP_021205GER

