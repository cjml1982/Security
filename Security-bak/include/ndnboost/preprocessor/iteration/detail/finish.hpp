# /* **************************************************************************
#  *                                                                          *
#  *     (C) Copyright Paul Mensonides 2002.
#  *     Distributed under the Boost Software License, Version 1.0. (See
#  *     accompanying file LICENSE_1_0.txt or copy at
#  *     http://www.boost.org/LICENSE_1_0.txt)
#  *                                                                          *
#  ************************************************************************** */
#
# /* See http://www.boost.org for most recent version. */
#
# include <ndnboost/preprocessor/slot/detail/shared.hpp>
#
# undef NDNBOOST_PP_LOCAL_FE
#
# undef NDNBOOST_PP_LOCAL_FE_DIGIT_1
# undef NDNBOOST_PP_LOCAL_FE_DIGIT_2
# undef NDNBOOST_PP_LOCAL_FE_DIGIT_3
# undef NDNBOOST_PP_LOCAL_FE_DIGIT_4
# undef NDNBOOST_PP_LOCAL_FE_DIGIT_5
# undef NDNBOOST_PP_LOCAL_FE_DIGIT_6
# undef NDNBOOST_PP_LOCAL_FE_DIGIT_7
# undef NDNBOOST_PP_LOCAL_FE_DIGIT_8
# undef NDNBOOST_PP_LOCAL_FE_DIGIT_9
# undef NDNBOOST_PP_LOCAL_FE_DIGIT_10
#
# if NDNBOOST_PP_SLOT_TEMP_3 == 0
#    define NDNBOOST_PP_LOCAL_FE_DIGIT_3 0
# elif NDNBOOST_PP_SLOT_TEMP_3 == 1
#    define NDNBOOST_PP_LOCAL_FE_DIGIT_3 1
# elif NDNBOOST_PP_SLOT_TEMP_3 == 2
#    define NDNBOOST_PP_LOCAL_FE_DIGIT_3 2
# elif NDNBOOST_PP_SLOT_TEMP_3 == 3
#    define NDNBOOST_PP_LOCAL_FE_DIGIT_3 3
# elif NDNBOOST_PP_SLOT_TEMP_3 == 4
#    define NDNBOOST_PP_LOCAL_FE_DIGIT_3 4
# elif NDNBOOST_PP_SLOT_TEMP_3 == 5
#    define NDNBOOST_PP_LOCAL_FE_DIGIT_3 5
# elif NDNBOOST_PP_SLOT_TEMP_3 == 6
#    define NDNBOOST_PP_LOCAL_FE_DIGIT_3 6
# elif NDNBOOST_PP_SLOT_TEMP_3 == 7
#    define NDNBOOST_PP_LOCAL_FE_DIGIT_3 7
# elif NDNBOOST_PP_SLOT_TEMP_3 == 8
#    define NDNBOOST_PP_LOCAL_FE_DIGIT_3 8
# elif NDNBOOST_PP_SLOT_TEMP_3 == 9
#    define NDNBOOST_PP_LOCAL_FE_DIGIT_3 9
# endif
#
# if NDNBOOST_PP_SLOT_TEMP_2 == 0
#    define NDNBOOST_PP_LOCAL_FE_DIGIT_2 0
# elif NDNBOOST_PP_SLOT_TEMP_2 == 1
#    define NDNBOOST_PP_LOCAL_FE_DIGIT_2 1
# elif NDNBOOST_PP_SLOT_TEMP_2 == 2
#    define NDNBOOST_PP_LOCAL_FE_DIGIT_2 2
# elif NDNBOOST_PP_SLOT_TEMP_2 == 3
#    define NDNBOOST_PP_LOCAL_FE_DIGIT_2 3
# elif NDNBOOST_PP_SLOT_TEMP_2 == 4
#    define NDNBOOST_PP_LOCAL_FE_DIGIT_2 4
# elif NDNBOOST_PP_SLOT_TEMP_2 == 5
#    define NDNBOOST_PP_LOCAL_FE_DIGIT_2 5
# elif NDNBOOST_PP_SLOT_TEMP_2 == 6
#    define NDNBOOST_PP_LOCAL_FE_DIGIT_2 6
# elif NDNBOOST_PP_SLOT_TEMP_2 == 7
#    define NDNBOOST_PP_LOCAL_FE_DIGIT_2 7
# elif NDNBOOST_PP_SLOT_TEMP_2 == 8
#    define NDNBOOST_PP_LOCAL_FE_DIGIT_2 8
# elif NDNBOOST_PP_SLOT_TEMP_2 == 9
#    define NDNBOOST_PP_LOCAL_FE_DIGIT_2 9
# endif
#
# if NDNBOOST_PP_SLOT_TEMP_1 == 0
#    define NDNBOOST_PP_LOCAL_FE_DIGIT_1 0
# elif NDNBOOST_PP_SLOT_TEMP_1 == 1
#    define NDNBOOST_PP_LOCAL_FE_DIGIT_1 1
# elif NDNBOOST_PP_SLOT_TEMP_1 == 2
#    define NDNBOOST_PP_LOCAL_FE_DIGIT_1 2
# elif NDNBOOST_PP_SLOT_TEMP_1 == 3
#    define NDNBOOST_PP_LOCAL_FE_DIGIT_1 3
# elif NDNBOOST_PP_SLOT_TEMP_1 == 4
#    define NDNBOOST_PP_LOCAL_FE_DIGIT_1 4
# elif NDNBOOST_PP_SLOT_TEMP_1 == 5
#    define NDNBOOST_PP_LOCAL_FE_DIGIT_1 5
# elif NDNBOOST_PP_SLOT_TEMP_1 == 6
#    define NDNBOOST_PP_LOCAL_FE_DIGIT_1 6
# elif NDNBOOST_PP_SLOT_TEMP_1 == 7
#    define NDNBOOST_PP_LOCAL_FE_DIGIT_1 7
# elif NDNBOOST_PP_SLOT_TEMP_1 == 8
#    define NDNBOOST_PP_LOCAL_FE_DIGIT_1 8
# elif NDNBOOST_PP_SLOT_TEMP_1 == 9
#    define NDNBOOST_PP_LOCAL_FE_DIGIT_1 9
# endif
#
# if NDNBOOST_PP_LOCAL_FE_DIGIT_3
#    define NDNBOOST_PP_LOCAL_FE() NDNBOOST_PP_SLOT_CC_3(NDNBOOST_PP_LOCAL_FE_DIGIT_3, NDNBOOST_PP_LOCAL_FE_DIGIT_2, NDNBOOST_PP_LOCAL_FE_DIGIT_1)
# elif NDNBOOST_PP_LOCAL_FE_DIGIT_2
#    define NDNBOOST_PP_LOCAL_FE() NDNBOOST_PP_SLOT_CC_2(NDNBOOST_PP_LOCAL_FE_DIGIT_2, NDNBOOST_PP_LOCAL_FE_DIGIT_1)
# else
#    define NDNBOOST_PP_LOCAL_FE() NDNBOOST_PP_LOCAL_FE_DIGIT_1
# endif
