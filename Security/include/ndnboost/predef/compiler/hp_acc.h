/*
Copyright Rene Rivera 2008-2014
Distributed under the Boost Software License, Version 1.0.
(See accompanying file LICENSE_1_0.txt or copy at
http://www.boost.org/LICENSE_1_0.txt)
*/

#ifndef NDNBOOST_PREDEF_COMPILER_HP_ACC_H
#define NDNBOOST_PREDEF_COMPILER_HP_ACC_H

#include <ndnboost/predef/version_number.h>
#include <ndnboost/predef/make.h>

/*`
[heading `NDNBOOST_COMP_HPACC`]

HP aC++ compiler.
Version number available as major, minor, and patch.

[table
    [[__predef_symbol__] [__predef_version__]]

    [[`__HP_aCC`] [__predef_detection__]]

    [[`__HP_aCC`] [V.R.P]]
    ]
 */

#define NDNBOOST_COMP_HPACC NDNBOOST_VERSION_NUMBER_NOT_AVAILABLE

#if defined(__HP_aCC)
#   if !defined(NDNBOOST_COMP_HPACC_DETECTION) && (__HP_aCC > 1)
#       define NDNBOOST_COMP_HPACC_DETECTION NDNBOOST_PREDEF_MAKE_10_VVRRPP(__HP_aCC)
#   endif
#   if !defined(NDNBOOST_COMP_HPACC_DETECTION)
#       define NDNBOOST_COMP_HPACC_DETECTION NDNBOOST_VERSION_NUMBER_AVAILABLE
#   endif
#endif

#ifdef NDNBOOST_COMP_HPACC_DETECTION
#   if defined(NDNBOOST_PREDEF_DETAIL_COMP_DETECTED)
#       define NDNBOOST_COMP_HPACC_EMULATED NDNBOOST_COMP_HPACC_DETECTION
#   else
#       undef NDNBOOST_COMP_HPACC
#       define NDNBOOST_COMP_HPACC NDNBOOST_COMP_HPACC_DETECTION
#   endif
#   define NDNBOOST_COMP_HPACC_AVAILABLE
#   include <ndnboost/predef/detail/comp_detected.h>
#endif

#define NDNBOOST_COMP_HPACC_NAME "HP aC++"

#include <ndnboost/predef/detail/test.h>
NDNBOOST_PREDEF_DECLARE_TEST(NDNBOOST_COMP_HPACC,NDNBOOST_COMP_HPACC_NAME)

#ifdef NDNBOOST_COMP_HPACC_EMULATED
#include <ndnboost/predef/detail/test.h>
NDNBOOST_PREDEF_DECLARE_TEST(NDNBOOST_COMP_HPACC_EMULATED,NDNBOOST_COMP_HPACC_NAME)
#endif


#endif
