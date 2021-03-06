
//  (C) Copyright Dave Abrahams, Steve Cleary, Beman Dawes, 
//  Aleksey Gurtovoy, Howard Hinnant & John Maddock 2000.  
//  Use, modification and distribution are subject to the Boost Software License,
//  Version 1.0. (See accompanying file LICENSE_1_0.txt or copy at
//  http://www.boost.org/LICENSE_1_0.txt).
//
//  See http://www.boost.org/libs/type_traits for most recent version including documentation.

#if !defined(NDNBOOST_PP_IS_ITERATING)

///// header body

#ifndef NDNBOOST_TT_DETAIL_IS_FUNCTION_PTR_TESTER_HPP_INCLUDED
#define NDNBOOST_TT_DETAIL_IS_FUNCTION_PTR_TESTER_HPP_INCLUDED

#include <ndnboost/type_traits/detail/yes_no_type.hpp>
#include <ndnboost/type_traits/config.hpp>

#if defined(NDNBOOST_TT_PREPROCESSING_MODE)
#   include <ndnboost/preprocessor/iterate.hpp>
#   include <ndnboost/preprocessor/enum_params.hpp>
#   include <ndnboost/preprocessor/comma_if.hpp>
#endif

namespace pkiboost {
namespace type_traits {

// Note it is acceptable to use ellipsis here, since the argument will
// always be a pointer type of some sort (JM 2005/06/04):
no_type NDNBOOST_TT_DECL is_function_ptr_tester(...);

#if !defined(NDNBOOST_TT_PREPROCESSING_MODE)
// pre-processed code, don't edit, try GNU cpp with 
// cpp -I../../../ -DNDNBOOST_TT_PREPROCESSING_MODE -x c++ -P filename

template <class R >
yes_type is_function_ptr_tester(R (*)());
template <class R >
yes_type is_function_ptr_tester(R (*)( ...));
#ifdef NDNBOOST_TT_TEST_MS_FUNC_SIGS
template <class R >
yes_type is_function_ptr_tester(R (__stdcall*)());
#ifndef _MANAGED
template <class R >
yes_type is_function_ptr_tester(R (__fastcall*)());
#endif
template <class R >
yes_type is_function_ptr_tester(R (__cdecl*)());
#endif
template <class R , class T0 >
yes_type is_function_ptr_tester(R (*)( T0));
template <class R , class T0 >
yes_type is_function_ptr_tester(R (*)( T0 ...));
#ifdef NDNBOOST_TT_TEST_MS_FUNC_SIGS
template <class R , class T0 >
yes_type is_function_ptr_tester(R (__stdcall*)( T0));
#ifndef _MANAGED
template <class R , class T0 >
yes_type is_function_ptr_tester(R (__fastcall*)( T0));
#endif
template <class R , class T0 >
yes_type is_function_ptr_tester(R (__cdecl*)( T0));
#endif
template <class R , class T0 , class T1 >
yes_type is_function_ptr_tester(R (*)( T0 , T1));
template <class R , class T0 , class T1 >
yes_type is_function_ptr_tester(R (*)( T0 , T1 ...));
#ifdef NDNBOOST_TT_TEST_MS_FUNC_SIGS
template <class R , class T0 , class T1 >
yes_type is_function_ptr_tester(R (__stdcall*)( T0 , T1));
#ifndef _MANAGED
template <class R , class T0 , class T1 >
yes_type is_function_ptr_tester(R (__fastcall*)( T0 , T1));
#endif
template <class R , class T0 , class T1 >
yes_type is_function_ptr_tester(R (__cdecl*)( T0 , T1));
#endif
template <class R , class T0 , class T1 , class T2 >
yes_type is_function_ptr_tester(R (*)( T0 , T1 , T2));
template <class R , class T0 , class T1 , class T2 >
yes_type is_function_ptr_tester(R (*)( T0 , T1 , T2 ...));
#ifdef NDNBOOST_TT_TEST_MS_FUNC_SIGS
template <class R , class T0 , class T1 , class T2 >
yes_type is_function_ptr_tester(R (__stdcall*)( T0 , T1 , T2));
#ifndef _MANAGED
template <class R , class T0 , class T1 , class T2 >
yes_type is_function_ptr_tester(R (__fastcall*)( T0 , T1 , T2));
#endif
template <class R , class T0 , class T1 , class T2 >
yes_type is_function_ptr_tester(R (__cdecl*)( T0 , T1 , T2));
#endif
template <class R , class T0 , class T1 , class T2 , class T3 >
yes_type is_function_ptr_tester(R (*)( T0 , T1 , T2 , T3));
template <class R , class T0 , class T1 , class T2 , class T3 >
yes_type is_function_ptr_tester(R (*)( T0 , T1 , T2 , T3 ...));
#ifdef NDNBOOST_TT_TEST_MS_FUNC_SIGS
template <class R , class T0 , class T1 , class T2 , class T3 >
yes_type is_function_ptr_tester(R (__stdcall*)( T0 , T1 , T2 , T3));
#ifndef _MANAGED
template <class R , class T0 , class T1 , class T2 , class T3 >
yes_type is_function_ptr_tester(R (__fastcall*)( T0 , T1 , T2 , T3));
#endif
template <class R , class T0 , class T1 , class T2 , class T3 >
yes_type is_function_ptr_tester(R (__cdecl*)( T0 , T1 , T2 , T3));
#endif
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 >
yes_type is_function_ptr_tester(R (*)( T0 , T1 , T2 , T3 , T4));
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 >
yes_type is_function_ptr_tester(R (*)( T0 , T1 , T2 , T3 , T4 ...));
#ifdef NDNBOOST_TT_TEST_MS_FUNC_SIGS
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 >
yes_type is_function_ptr_tester(R (__stdcall*)( T0 , T1 , T2 , T3 , T4));
#ifndef _MANAGED
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 >
yes_type is_function_ptr_tester(R (__fastcall*)( T0 , T1 , T2 , T3 , T4));
#endif
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 >
yes_type is_function_ptr_tester(R (__cdecl*)( T0 , T1 , T2 , T3 , T4));
#endif
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 >
yes_type is_function_ptr_tester(R (*)( T0 , T1 , T2 , T3 , T4 , T5));
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 >
yes_type is_function_ptr_tester(R (*)( T0 , T1 , T2 , T3 , T4 , T5 ...));
#ifdef NDNBOOST_TT_TEST_MS_FUNC_SIGS
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 >
yes_type is_function_ptr_tester(R (__stdcall*)( T0 , T1 , T2 , T3 , T4 , T5));
#ifndef _MANAGED
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 >
yes_type is_function_ptr_tester(R (__fastcall*)( T0 , T1 , T2 , T3 , T4 , T5));
#endif
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 >
yes_type is_function_ptr_tester(R (__cdecl*)( T0 , T1 , T2 , T3 , T4 , T5));
#endif
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 >
yes_type is_function_ptr_tester(R (*)( T0 , T1 , T2 , T3 , T4 , T5 , T6));
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 >
yes_type is_function_ptr_tester(R (*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 ...));
#ifdef NDNBOOST_TT_TEST_MS_FUNC_SIGS
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 >
yes_type is_function_ptr_tester(R (__stdcall*)( T0 , T1 , T2 , T3 , T4 , T5 , T6));
#ifndef _MANAGED
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 >
yes_type is_function_ptr_tester(R (__fastcall*)( T0 , T1 , T2 , T3 , T4 , T5 , T6));
#endif
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 >
yes_type is_function_ptr_tester(R (__cdecl*)( T0 , T1 , T2 , T3 , T4 , T5 , T6));
#endif
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 >
yes_type is_function_ptr_tester(R (*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7));
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 >
yes_type is_function_ptr_tester(R (*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7 ...));
#ifdef NDNBOOST_TT_TEST_MS_FUNC_SIGS
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 >
yes_type is_function_ptr_tester(R (__stdcall*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7));
#ifndef _MANAGED
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 >
yes_type is_function_ptr_tester(R (__fastcall*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7));
#endif
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 >
yes_type is_function_ptr_tester(R (__cdecl*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7));
#endif
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 , class T8 >
yes_type is_function_ptr_tester(R (*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7 , T8));
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 , class T8 >
yes_type is_function_ptr_tester(R (*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7 , T8 ...));
#ifdef NDNBOOST_TT_TEST_MS_FUNC_SIGS
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 , class T8 >
yes_type is_function_ptr_tester(R (__stdcall*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7 , T8));
#ifndef _MANAGED
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 , class T8 >
yes_type is_function_ptr_tester(R (__fastcall*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7 , T8));
#endif
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 , class T8 >
yes_type is_function_ptr_tester(R (__cdecl*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7 , T8));
#endif
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 , class T8 , class T9 >
yes_type is_function_ptr_tester(R (*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7 , T8 , T9));
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 , class T8 , class T9 >
yes_type is_function_ptr_tester(R (*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7 , T8 , T9 ...));
#ifdef NDNBOOST_TT_TEST_MS_FUNC_SIGS
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 , class T8 , class T9 >
yes_type is_function_ptr_tester(R (__stdcall*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7 , T8 , T9));
#ifndef _MANAGED
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 , class T8 , class T9 >
yes_type is_function_ptr_tester(R (__fastcall*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7 , T8 , T9));
#endif
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 , class T8 , class T9 >
yes_type is_function_ptr_tester(R (__cdecl*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7 , T8 , T9));
#endif
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 , class T8 , class T9 , class T10 >
yes_type is_function_ptr_tester(R (*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7 , T8 , T9 , T10));
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 , class T8 , class T9 , class T10 >
yes_type is_function_ptr_tester(R (*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7 , T8 , T9 , T10 ...));
#ifdef NDNBOOST_TT_TEST_MS_FUNC_SIGS
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 , class T8 , class T9 , class T10 >
yes_type is_function_ptr_tester(R (__stdcall*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7 , T8 , T9 , T10));
#ifndef _MANAGED
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 , class T8 , class T9 , class T10 >
yes_type is_function_ptr_tester(R (__fastcall*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7 , T8 , T9 , T10));
#endif
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 , class T8 , class T9 , class T10 >
yes_type is_function_ptr_tester(R (__cdecl*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7 , T8 , T9 , T10));
#endif
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 , class T8 , class T9 , class T10 , class T11 >
yes_type is_function_ptr_tester(R (*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7 , T8 , T9 , T10 , T11));
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 , class T8 , class T9 , class T10 , class T11 >
yes_type is_function_ptr_tester(R (*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7 , T8 , T9 , T10 , T11 ...));
#ifdef NDNBOOST_TT_TEST_MS_FUNC_SIGS
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 , class T8 , class T9 , class T10 , class T11 >
yes_type is_function_ptr_tester(R (__stdcall*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7 , T8 , T9 , T10 , T11));
#ifndef _MANAGED
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 , class T8 , class T9 , class T10 , class T11 >
yes_type is_function_ptr_tester(R (__fastcall*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7 , T8 , T9 , T10 , T11));
#endif
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 , class T8 , class T9 , class T10 , class T11 >
yes_type is_function_ptr_tester(R (__cdecl*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7 , T8 , T9 , T10 , T11));
#endif
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 , class T8 , class T9 , class T10 , class T11 , class T12 >
yes_type is_function_ptr_tester(R (*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7 , T8 , T9 , T10 , T11 , T12));
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 , class T8 , class T9 , class T10 , class T11 , class T12 >
yes_type is_function_ptr_tester(R (*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7 , T8 , T9 , T10 , T11 , T12 ...));
#ifdef NDNBOOST_TT_TEST_MS_FUNC_SIGS
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 , class T8 , class T9 , class T10 , class T11 , class T12 >
yes_type is_function_ptr_tester(R (__stdcall*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7 , T8 , T9 , T10 , T11 , T12));
#ifndef _MANAGED
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 , class T8 , class T9 , class T10 , class T11 , class T12 >
yes_type is_function_ptr_tester(R (__fastcall*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7 , T8 , T9 , T10 , T11 , T12));
#endif
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 , class T8 , class T9 , class T10 , class T11 , class T12 >
yes_type is_function_ptr_tester(R (__cdecl*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7 , T8 , T9 , T10 , T11 , T12));
#endif
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 , class T8 , class T9 , class T10 , class T11 , class T12 , class T13 >
yes_type is_function_ptr_tester(R (*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7 , T8 , T9 , T10 , T11 , T12 , T13));
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 , class T8 , class T9 , class T10 , class T11 , class T12 , class T13 >
yes_type is_function_ptr_tester(R (*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7 , T8 , T9 , T10 , T11 , T12 , T13 ...));
#ifdef NDNBOOST_TT_TEST_MS_FUNC_SIGS
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 , class T8 , class T9 , class T10 , class T11 , class T12 , class T13 >
yes_type is_function_ptr_tester(R (__stdcall*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7 , T8 , T9 , T10 , T11 , T12 , T13));
#ifndef _MANAGED
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 , class T8 , class T9 , class T10 , class T11 , class T12 , class T13 >
yes_type is_function_ptr_tester(R (__fastcall*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7 , T8 , T9 , T10 , T11 , T12 , T13));
#endif
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 , class T8 , class T9 , class T10 , class T11 , class T12 , class T13 >
yes_type is_function_ptr_tester(R (__cdecl*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7 , T8 , T9 , T10 , T11 , T12 , T13));
#endif
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 , class T8 , class T9 , class T10 , class T11 , class T12 , class T13 , class T14 >
yes_type is_function_ptr_tester(R (*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7 , T8 , T9 , T10 , T11 , T12 , T13 , T14));
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 , class T8 , class T9 , class T10 , class T11 , class T12 , class T13 , class T14 >
yes_type is_function_ptr_tester(R (*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7 , T8 , T9 , T10 , T11 , T12 , T13 , T14 ...));
#ifdef NDNBOOST_TT_TEST_MS_FUNC_SIGS
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 , class T8 , class T9 , class T10 , class T11 , class T12 , class T13 , class T14 >
yes_type is_function_ptr_tester(R (__stdcall*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7 , T8 , T9 , T10 , T11 , T12 , T13 , T14));
#ifndef _MANAGED
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 , class T8 , class T9 , class T10 , class T11 , class T12 , class T13 , class T14 >
yes_type is_function_ptr_tester(R (__fastcall*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7 , T8 , T9 , T10 , T11 , T12 , T13 , T14));
#endif
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 , class T8 , class T9 , class T10 , class T11 , class T12 , class T13 , class T14 >
yes_type is_function_ptr_tester(R (__cdecl*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7 , T8 , T9 , T10 , T11 , T12 , T13 , T14));
#endif
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 , class T8 , class T9 , class T10 , class T11 , class T12 , class T13 , class T14 , class T15 >
yes_type is_function_ptr_tester(R (*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7 , T8 , T9 , T10 , T11 , T12 , T13 , T14 , T15));
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 , class T8 , class T9 , class T10 , class T11 , class T12 , class T13 , class T14 , class T15 >
yes_type is_function_ptr_tester(R (*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7 , T8 , T9 , T10 , T11 , T12 , T13 , T14 , T15 ...));
#ifdef NDNBOOST_TT_TEST_MS_FUNC_SIGS
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 , class T8 , class T9 , class T10 , class T11 , class T12 , class T13 , class T14 , class T15 >
yes_type is_function_ptr_tester(R (__stdcall*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7 , T8 , T9 , T10 , T11 , T12 , T13 , T14 , T15));
#ifndef _MANAGED
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 , class T8 , class T9 , class T10 , class T11 , class T12 , class T13 , class T14 , class T15 >
yes_type is_function_ptr_tester(R (__fastcall*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7 , T8 , T9 , T10 , T11 , T12 , T13 , T14 , T15));
#endif
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 , class T8 , class T9 , class T10 , class T11 , class T12 , class T13 , class T14 , class T15 >
yes_type is_function_ptr_tester(R (__cdecl*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7 , T8 , T9 , T10 , T11 , T12 , T13 , T14 , T15));
#endif
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 , class T8 , class T9 , class T10 , class T11 , class T12 , class T13 , class T14 , class T15 , class T16 >
yes_type is_function_ptr_tester(R (*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7 , T8 , T9 , T10 , T11 , T12 , T13 , T14 , T15 , T16));
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 , class T8 , class T9 , class T10 , class T11 , class T12 , class T13 , class T14 , class T15 , class T16 >
yes_type is_function_ptr_tester(R (*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7 , T8 , T9 , T10 , T11 , T12 , T13 , T14 , T15 , T16 ...));
#ifdef NDNBOOST_TT_TEST_MS_FUNC_SIGS
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 , class T8 , class T9 , class T10 , class T11 , class T12 , class T13 , class T14 , class T15 , class T16 >
yes_type is_function_ptr_tester(R (__stdcall*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7 , T8 , T9 , T10 , T11 , T12 , T13 , T14 , T15 , T16));
#ifndef _MANAGED
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 , class T8 , class T9 , class T10 , class T11 , class T12 , class T13 , class T14 , class T15 , class T16 >
yes_type is_function_ptr_tester(R (__fastcall*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7 , T8 , T9 , T10 , T11 , T12 , T13 , T14 , T15 , T16));
#endif
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 , class T8 , class T9 , class T10 , class T11 , class T12 , class T13 , class T14 , class T15 , class T16 >
yes_type is_function_ptr_tester(R (__cdecl*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7 , T8 , T9 , T10 , T11 , T12 , T13 , T14 , T15 , T16));
#endif
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 , class T8 , class T9 , class T10 , class T11 , class T12 , class T13 , class T14 , class T15 , class T16 , class T17 >
yes_type is_function_ptr_tester(R (*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7 , T8 , T9 , T10 , T11 , T12 , T13 , T14 , T15 , T16 , T17));
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 , class T8 , class T9 , class T10 , class T11 , class T12 , class T13 , class T14 , class T15 , class T16 , class T17 >
yes_type is_function_ptr_tester(R (*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7 , T8 , T9 , T10 , T11 , T12 , T13 , T14 , T15 , T16 , T17 ...));
#ifdef NDNBOOST_TT_TEST_MS_FUNC_SIGS
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 , class T8 , class T9 , class T10 , class T11 , class T12 , class T13 , class T14 , class T15 , class T16 , class T17 >
yes_type is_function_ptr_tester(R (__stdcall*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7 , T8 , T9 , T10 , T11 , T12 , T13 , T14 , T15 , T16 , T17));
#ifndef _MANAGED
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 , class T8 , class T9 , class T10 , class T11 , class T12 , class T13 , class T14 , class T15 , class T16 , class T17 >
yes_type is_function_ptr_tester(R (__fastcall*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7 , T8 , T9 , T10 , T11 , T12 , T13 , T14 , T15 , T16 , T17));
#endif
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 , class T8 , class T9 , class T10 , class T11 , class T12 , class T13 , class T14 , class T15 , class T16 , class T17 >
yes_type is_function_ptr_tester(R (__cdecl*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7 , T8 , T9 , T10 , T11 , T12 , T13 , T14 , T15 , T16 , T17));
#endif
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 , class T8 , class T9 , class T10 , class T11 , class T12 , class T13 , class T14 , class T15 , class T16 , class T17 , class T18 >
yes_type is_function_ptr_tester(R (*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7 , T8 , T9 , T10 , T11 , T12 , T13 , T14 , T15 , T16 , T17 , T18));
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 , class T8 , class T9 , class T10 , class T11 , class T12 , class T13 , class T14 , class T15 , class T16 , class T17 , class T18 >
yes_type is_function_ptr_tester(R (*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7 , T8 , T9 , T10 , T11 , T12 , T13 , T14 , T15 , T16 , T17 , T18 ...));
#ifdef NDNBOOST_TT_TEST_MS_FUNC_SIGS
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 , class T8 , class T9 , class T10 , class T11 , class T12 , class T13 , class T14 , class T15 , class T16 , class T17 , class T18 >
yes_type is_function_ptr_tester(R (__stdcall*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7 , T8 , T9 , T10 , T11 , T12 , T13 , T14 , T15 , T16 , T17 , T18));
#ifndef _MANAGED
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 , class T8 , class T9 , class T10 , class T11 , class T12 , class T13 , class T14 , class T15 , class T16 , class T17 , class T18 >
yes_type is_function_ptr_tester(R (__fastcall*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7 , T8 , T9 , T10 , T11 , T12 , T13 , T14 , T15 , T16 , T17 , T18));
#endif
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 , class T8 , class T9 , class T10 , class T11 , class T12 , class T13 , class T14 , class T15 , class T16 , class T17 , class T18 >
yes_type is_function_ptr_tester(R (__cdecl*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7 , T8 , T9 , T10 , T11 , T12 , T13 , T14 , T15 , T16 , T17 , T18));
#endif
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 , class T8 , class T9 , class T10 , class T11 , class T12 , class T13 , class T14 , class T15 , class T16 , class T17 , class T18 , class T19 >
yes_type is_function_ptr_tester(R (*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7 , T8 , T9 , T10 , T11 , T12 , T13 , T14 , T15 , T16 , T17 , T18 , T19));
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 , class T8 , class T9 , class T10 , class T11 , class T12 , class T13 , class T14 , class T15 , class T16 , class T17 , class T18 , class T19 >
yes_type is_function_ptr_tester(R (*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7 , T8 , T9 , T10 , T11 , T12 , T13 , T14 , T15 , T16 , T17 , T18 , T19 ...));
#ifdef NDNBOOST_TT_TEST_MS_FUNC_SIGS
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 , class T8 , class T9 , class T10 , class T11 , class T12 , class T13 , class T14 , class T15 , class T16 , class T17 , class T18 , class T19 >
yes_type is_function_ptr_tester(R (__stdcall*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7 , T8 , T9 , T10 , T11 , T12 , T13 , T14 , T15 , T16 , T17 , T18 , T19));
#ifndef _MANAGED
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 , class T8 , class T9 , class T10 , class T11 , class T12 , class T13 , class T14 , class T15 , class T16 , class T17 , class T18 , class T19 >
yes_type is_function_ptr_tester(R (__fastcall*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7 , T8 , T9 , T10 , T11 , T12 , T13 , T14 , T15 , T16 , T17 , T18 , T19));
#endif
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 , class T8 , class T9 , class T10 , class T11 , class T12 , class T13 , class T14 , class T15 , class T16 , class T17 , class T18 , class T19 >
yes_type is_function_ptr_tester(R (__cdecl*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7 , T8 , T9 , T10 , T11 , T12 , T13 , T14 , T15 , T16 , T17 , T18 , T19));
#endif
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 , class T8 , class T9 , class T10 , class T11 , class T12 , class T13 , class T14 , class T15 , class T16 , class T17 , class T18 , class T19 , class T20 >
yes_type is_function_ptr_tester(R (*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7 , T8 , T9 , T10 , T11 , T12 , T13 , T14 , T15 , T16 , T17 , T18 , T19 , T20));
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 , class T8 , class T9 , class T10 , class T11 , class T12 , class T13 , class T14 , class T15 , class T16 , class T17 , class T18 , class T19 , class T20 >
yes_type is_function_ptr_tester(R (*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7 , T8 , T9 , T10 , T11 , T12 , T13 , T14 , T15 , T16 , T17 , T18 , T19 , T20 ...));
#ifdef NDNBOOST_TT_TEST_MS_FUNC_SIGS
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 , class T8 , class T9 , class T10 , class T11 , class T12 , class T13 , class T14 , class T15 , class T16 , class T17 , class T18 , class T19 , class T20 >
yes_type is_function_ptr_tester(R (__stdcall*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7 , T8 , T9 , T10 , T11 , T12 , T13 , T14 , T15 , T16 , T17 , T18 , T19 , T20));
#ifndef _MANAGED
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 , class T8 , class T9 , class T10 , class T11 , class T12 , class T13 , class T14 , class T15 , class T16 , class T17 , class T18 , class T19 , class T20 >
yes_type is_function_ptr_tester(R (__fastcall*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7 , T8 , T9 , T10 , T11 , T12 , T13 , T14 , T15 , T16 , T17 , T18 , T19 , T20));
#endif
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 , class T8 , class T9 , class T10 , class T11 , class T12 , class T13 , class T14 , class T15 , class T16 , class T17 , class T18 , class T19 , class T20 >
yes_type is_function_ptr_tester(R (__cdecl*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7 , T8 , T9 , T10 , T11 , T12 , T13 , T14 , T15 , T16 , T17 , T18 , T19 , T20));
#endif
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 , class T8 , class T9 , class T10 , class T11 , class T12 , class T13 , class T14 , class T15 , class T16 , class T17 , class T18 , class T19 , class T20 , class T21 >
yes_type is_function_ptr_tester(R (*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7 , T8 , T9 , T10 , T11 , T12 , T13 , T14 , T15 , T16 , T17 , T18 , T19 , T20 , T21));
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 , class T8 , class T9 , class T10 , class T11 , class T12 , class T13 , class T14 , class T15 , class T16 , class T17 , class T18 , class T19 , class T20 , class T21 >
yes_type is_function_ptr_tester(R (*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7 , T8 , T9 , T10 , T11 , T12 , T13 , T14 , T15 , T16 , T17 , T18 , T19 , T20 , T21 ...));
#ifdef NDNBOOST_TT_TEST_MS_FUNC_SIGS
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 , class T8 , class T9 , class T10 , class T11 , class T12 , class T13 , class T14 , class T15 , class T16 , class T17 , class T18 , class T19 , class T20 , class T21 >
yes_type is_function_ptr_tester(R (__stdcall*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7 , T8 , T9 , T10 , T11 , T12 , T13 , T14 , T15 , T16 , T17 , T18 , T19 , T20 , T21));
#ifndef _MANAGED
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 , class T8 , class T9 , class T10 , class T11 , class T12 , class T13 , class T14 , class T15 , class T16 , class T17 , class T18 , class T19 , class T20 , class T21 >
yes_type is_function_ptr_tester(R (__fastcall*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7 , T8 , T9 , T10 , T11 , T12 , T13 , T14 , T15 , T16 , T17 , T18 , T19 , T20 , T21));
#endif
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 , class T8 , class T9 , class T10 , class T11 , class T12 , class T13 , class T14 , class T15 , class T16 , class T17 , class T18 , class T19 , class T20 , class T21 >
yes_type is_function_ptr_tester(R (__cdecl*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7 , T8 , T9 , T10 , T11 , T12 , T13 , T14 , T15 , T16 , T17 , T18 , T19 , T20 , T21));
#endif
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 , class T8 , class T9 , class T10 , class T11 , class T12 , class T13 , class T14 , class T15 , class T16 , class T17 , class T18 , class T19 , class T20 , class T21 , class T22 >
yes_type is_function_ptr_tester(R (*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7 , T8 , T9 , T10 , T11 , T12 , T13 , T14 , T15 , T16 , T17 , T18 , T19 , T20 , T21 , T22));
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 , class T8 , class T9 , class T10 , class T11 , class T12 , class T13 , class T14 , class T15 , class T16 , class T17 , class T18 , class T19 , class T20 , class T21 , class T22 >
yes_type is_function_ptr_tester(R (*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7 , T8 , T9 , T10 , T11 , T12 , T13 , T14 , T15 , T16 , T17 , T18 , T19 , T20 , T21 , T22 ...));
#ifdef NDNBOOST_TT_TEST_MS_FUNC_SIGS
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 , class T8 , class T9 , class T10 , class T11 , class T12 , class T13 , class T14 , class T15 , class T16 , class T17 , class T18 , class T19 , class T20 , class T21 , class T22 >
yes_type is_function_ptr_tester(R (__stdcall*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7 , T8 , T9 , T10 , T11 , T12 , T13 , T14 , T15 , T16 , T17 , T18 , T19 , T20 , T21 , T22));
#ifndef _MANAGED
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 , class T8 , class T9 , class T10 , class T11 , class T12 , class T13 , class T14 , class T15 , class T16 , class T17 , class T18 , class T19 , class T20 , class T21 , class T22 >
yes_type is_function_ptr_tester(R (__fastcall*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7 , T8 , T9 , T10 , T11 , T12 , T13 , T14 , T15 , T16 , T17 , T18 , T19 , T20 , T21 , T22));
#endif
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 , class T8 , class T9 , class T10 , class T11 , class T12 , class T13 , class T14 , class T15 , class T16 , class T17 , class T18 , class T19 , class T20 , class T21 , class T22 >
yes_type is_function_ptr_tester(R (__cdecl*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7 , T8 , T9 , T10 , T11 , T12 , T13 , T14 , T15 , T16 , T17 , T18 , T19 , T20 , T21 , T22));
#endif
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 , class T8 , class T9 , class T10 , class T11 , class T12 , class T13 , class T14 , class T15 , class T16 , class T17 , class T18 , class T19 , class T20 , class T21 , class T22 , class T23 >
yes_type is_function_ptr_tester(R (*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7 , T8 , T9 , T10 , T11 , T12 , T13 , T14 , T15 , T16 , T17 , T18 , T19 , T20 , T21 , T22 , T23));
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 , class T8 , class T9 , class T10 , class T11 , class T12 , class T13 , class T14 , class T15 , class T16 , class T17 , class T18 , class T19 , class T20 , class T21 , class T22 , class T23 >
yes_type is_function_ptr_tester(R (*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7 , T8 , T9 , T10 , T11 , T12 , T13 , T14 , T15 , T16 , T17 , T18 , T19 , T20 , T21 , T22 , T23 ...));
#ifdef NDNBOOST_TT_TEST_MS_FUNC_SIGS
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 , class T8 , class T9 , class T10 , class T11 , class T12 , class T13 , class T14 , class T15 , class T16 , class T17 , class T18 , class T19 , class T20 , class T21 , class T22 , class T23 >
yes_type is_function_ptr_tester(R (__stdcall*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7 , T8 , T9 , T10 , T11 , T12 , T13 , T14 , T15 , T16 , T17 , T18 , T19 , T20 , T21 , T22 , T23));
#ifndef _MANAGED
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 , class T8 , class T9 , class T10 , class T11 , class T12 , class T13 , class T14 , class T15 , class T16 , class T17 , class T18 , class T19 , class T20 , class T21 , class T22 , class T23 >
yes_type is_function_ptr_tester(R (__fastcall*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7 , T8 , T9 , T10 , T11 , T12 , T13 , T14 , T15 , T16 , T17 , T18 , T19 , T20 , T21 , T22 , T23));
#endif
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 , class T8 , class T9 , class T10 , class T11 , class T12 , class T13 , class T14 , class T15 , class T16 , class T17 , class T18 , class T19 , class T20 , class T21 , class T22 , class T23 >
yes_type is_function_ptr_tester(R (__cdecl*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7 , T8 , T9 , T10 , T11 , T12 , T13 , T14 , T15 , T16 , T17 , T18 , T19 , T20 , T21 , T22 , T23));
#endif
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 , class T8 , class T9 , class T10 , class T11 , class T12 , class T13 , class T14 , class T15 , class T16 , class T17 , class T18 , class T19 , class T20 , class T21 , class T22 , class T23 , class T24 >
yes_type is_function_ptr_tester(R (*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7 , T8 , T9 , T10 , T11 , T12 , T13 , T14 , T15 , T16 , T17 , T18 , T19 , T20 , T21 , T22 , T23 , T24));
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 , class T8 , class T9 , class T10 , class T11 , class T12 , class T13 , class T14 , class T15 , class T16 , class T17 , class T18 , class T19 , class T20 , class T21 , class T22 , class T23 , class T24 >
yes_type is_function_ptr_tester(R (*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7 , T8 , T9 , T10 , T11 , T12 , T13 , T14 , T15 , T16 , T17 , T18 , T19 , T20 , T21 , T22 , T23 , T24 ...));
#ifdef NDNBOOST_TT_TEST_MS_FUNC_SIGS
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 , class T8 , class T9 , class T10 , class T11 , class T12 , class T13 , class T14 , class T15 , class T16 , class T17 , class T18 , class T19 , class T20 , class T21 , class T22 , class T23 , class T24 >
yes_type is_function_ptr_tester(R (__stdcall*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7 , T8 , T9 , T10 , T11 , T12 , T13 , T14 , T15 , T16 , T17 , T18 , T19 , T20 , T21 , T22 , T23 , T24));
#ifndef _MANAGED
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 , class T8 , class T9 , class T10 , class T11 , class T12 , class T13 , class T14 , class T15 , class T16 , class T17 , class T18 , class T19 , class T20 , class T21 , class T22 , class T23 , class T24 >
yes_type is_function_ptr_tester(R (__fastcall*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7 , T8 , T9 , T10 , T11 , T12 , T13 , T14 , T15 , T16 , T17 , T18 , T19 , T20 , T21 , T22 , T23 , T24));
#endif
template <class R , class T0 , class T1 , class T2 , class T3 , class T4 , class T5 , class T6 , class T7 , class T8 , class T9 , class T10 , class T11 , class T12 , class T13 , class T14 , class T15 , class T16 , class T17 , class T18 , class T19 , class T20 , class T21 , class T22 , class T23 , class T24 >
yes_type is_function_ptr_tester(R (__cdecl*)( T0 , T1 , T2 , T3 , T4 , T5 , T6 , T7 , T8 , T9 , T10 , T11 , T12 , T13 , T14 , T15 , T16 , T17 , T18 , T19 , T20 , T21 , T22 , T23 , T24));
#endif
#else

#define NDNBOOST_PP_ITERATION_PARAMS_1 \
    (3, (0, 25, "ndnboost/type_traits/detail/is_function_ptr_tester.hpp"))
#include NDNBOOST_PP_ITERATE()

#endif // NDNBOOST_TT_PREPROCESSING_MODE

} // namespace type_traits
} // namespace pkiboost

#endif // NDNBOOST_TT_DETAIL_IS_FUNCTION_PTR_TESTER_HPP_INCLUDED

///// iteration

#else
#define NDNBOOST_PP_COUNTER NDNBOOST_PP_FRAME_ITERATION(1)
#undef __stdcall
#undef __fastcall
#undef __cdecl

template <class R NDNBOOST_PP_COMMA_IF(NDNBOOST_PP_COUNTER) NDNBOOST_PP_ENUM_PARAMS(NDNBOOST_PP_COUNTER,class T) >
yes_type is_function_ptr_tester(R (*)(NDNBOOST_PP_ENUM_PARAMS(NDNBOOST_PP_COUNTER,T)));
@#ifndef NDNBOOST_TT_NO_ELLIPSIS_IN_FUNC_TESTING
template <class R NDNBOOST_PP_COMMA_IF(NDNBOOST_PP_COUNTER) NDNBOOST_PP_ENUM_PARAMS(NDNBOOST_PP_COUNTER,class T) >
yes_type is_function_ptr_tester(R (*)(NDNBOOST_PP_ENUM_PARAMS(NDNBOOST_PP_COUNTER,T) ...));
@#endif
@#ifdef NDNBOOST_TT_TEST_MS_FUNC_SIGS
template <class R NDNBOOST_PP_COMMA_IF(NDNBOOST_PP_COUNTER) NDNBOOST_PP_ENUM_PARAMS(NDNBOOST_PP_COUNTER,class T) >
yes_type is_function_ptr_tester(R (__stdcall*)(NDNBOOST_PP_ENUM_PARAMS(NDNBOOST_PP_COUNTER,T)));
@#ifndef _MANAGED
template <class R NDNBOOST_PP_COMMA_IF(NDNBOOST_PP_COUNTER) NDNBOOST_PP_ENUM_PARAMS(NDNBOOST_PP_COUNTER,class T) >
yes_type is_function_ptr_tester(R (__fastcall*)(NDNBOOST_PP_ENUM_PARAMS(NDNBOOST_PP_COUNTER,T)));
@#endif
template <class R NDNBOOST_PP_COMMA_IF(NDNBOOST_PP_COUNTER) NDNBOOST_PP_ENUM_PARAMS(NDNBOOST_PP_COUNTER,class T) >
yes_type is_function_ptr_tester(R (__cdecl*)(NDNBOOST_PP_ENUM_PARAMS(NDNBOOST_PP_COUNTER,T)));
@#endif

#undef NDNBOOST_PP_COUNTER
#endif // NDNBOOST_PP_IS_ITERATING
