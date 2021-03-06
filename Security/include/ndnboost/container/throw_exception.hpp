//////////////////////////////////////////////////////////////////////////////
//
// (C) Copyright Ion Gaztanaga 2012-2013. Distributed under the Boost
// Software License, Version 1.0. (See accompanying file
// LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// See http://www.boost.org/libs/container for documentation.
//
//////////////////////////////////////////////////////////////////////////////

#ifndef NDNBOOST_CONTAINER_THROW_EXCEPTION_HPP
#define NDNBOOST_CONTAINER_THROW_EXCEPTION_HPP

#include <ndnboost/container/detail/config_begin.hpp>
#include <ndnboost/container/detail/workaround.hpp>

#if defined(_MSC_VER)
#  pragma once
#endif

#ifndef NDNBOOST_NO_EXCEPTIONS
   #include <stdexcept> //for std exception types
   #include <new>       //for std::bad_alloc
#else
   #include <ndnboost/assert.hpp>
   #include <cstdlib>   //for std::abort
#endif

namespace pkiboost {
namespace container {

#if defined(NDNBOOST_CONTAINER_USER_DEFINED_THROW_CALLBACKS)
   //The user must provide definitions for the following functions

   void throw_bad_alloc();

   void throw_out_of_range(const char* str);

   void throw_length_error(const char* str);

   void throw_logic_error(const char* str);

   void throw_runtime_error(const char* str);

#elif defined(NDNBOOST_NO_EXCEPTIONS)

   inline void throw_bad_alloc()
   {
      NDNBOOST_ASSERT(!"ndnboost::container bad_alloc thrown");
      std::abort();
   }

   inline void throw_out_of_range(const char* str)
   {
      NDNBOOST_ASSERT_MSG(!"ndnboost::container out_of_range thrown", str);
      std::abort();
   }

   inline void throw_length_error(const char* str)
   {
      NDNBOOST_ASSERT_MSG(!"ndnboost::container length_error thrown", str);
      std::abort();
   }

   inline void throw_logic_error(const char* str)
   {
      NDNBOOST_ASSERT_MSG(!"ndnboost::container logic_error thrown", str);
      std::abort();
   }

   inline void throw_runtime_error(const char* str)
   {
      NDNBOOST_ASSERT_MSG(!"ndnboost::container runtime_error thrown", str);
      std::abort();
   }

#else //defined(NDNBOOST_NO_EXCEPTIONS)

   //! Exception callback called by Boost.Container when fails to allocate the requested storage space.
   //! <ul>
   //! <li>If NDNBOOST_NO_EXCEPTIONS is NOT defined <code>std::bad_alloc()</code> is thrown.</li>
   //!
   //! <li>If NDNBOOST_NO_EXCEPTIONS is defined and NDNBOOST_CONTAINER_USER_DEFINED_THROW_CALLBACKS
   //!   is NOT defined <code>NDNBOOST_ASSERT(!"ndnboost::container bad_alloc thrown")</code> is called
   //!   and <code>std::abort()</code> if the former returns.</li>
   //!
   //! <li>If NDNBOOST_NO_EXCEPTIONS and NDNBOOST_CONTAINER_USER_DEFINED_THROW_CALLBACKS are defined
   //!   the user must provide an implementation and the function should not return.</li>
   //! </ul>
   inline void throw_bad_alloc()
   {
      throw std::bad_alloc();
   }

   //! Exception callback called by Boost.Container to signal arguments out of range.
   //! <ul>
   //! <li>If NDNBOOST_NO_EXCEPTIONS is NOT defined <code>std::out_of_range(str)</code> is thrown.</li>
   //!
   //! <li>If NDNBOOST_NO_EXCEPTIONS is defined and NDNBOOST_CONTAINER_USER_DEFINED_THROW_CALLBACKS
   //!   is NOT defined <code>NDNBOOST_ASSERT_MSG(!"ndnboost::container out_of_range thrown", str)</code> is called
   //!   and <code>std::abort()</code> if the former returns.</li>
   //!
   //! <li>If NDNBOOST_NO_EXCEPTIONS and NDNBOOST_CONTAINER_USER_DEFINED_THROW_CALLBACKS are defined
   //!   the user must provide an implementation and the function should not return.</li>
   //! </ul>
   inline void throw_out_of_range(const char* str)
   {
      throw std::out_of_range(str);
   }

   //! Exception callback called by Boost.Container to signal errors resizing.
   //! <ul>
   //! <li>If NDNBOOST_NO_EXCEPTIONS is NOT defined <code>std::length_error(str)</code> is thrown.</li>
   //!
   //! <li>If NDNBOOST_NO_EXCEPTIONS is defined and NDNBOOST_CONTAINER_USER_DEFINED_THROW_CALLBACKS
   //!   is NOT defined <code>NDNBOOST_ASSERT_MSG(!"ndnboost::container length_error thrown", str)</code> is called
   //!   and <code>std::abort()</code> if the former returns.</li>
   //!
   //! <li>If NDNBOOST_NO_EXCEPTIONS and NDNBOOST_CONTAINER_USER_DEFINED_THROW_CALLBACKS are defined
   //!   the user must provide an implementation and the function should not return.</li>
   //! </ul>
   inline void throw_length_error(const char* str)
   {
      throw std::length_error(str);
   }

   //! Exception callback called by Boost.Container  to report errors in the internal logical
   //! of the program, such as violation of logical preconditions or class invariants.
   //! <ul>
   //! <li>If NDNBOOST_NO_EXCEPTIONS is NOT defined <code>std::logic_error(str)</code> is thrown.</li>
   //!
   //! <li>If NDNBOOST_NO_EXCEPTIONS is defined and NDNBOOST_CONTAINER_USER_DEFINED_THROW_CALLBACKS
   //!   is NOT defined <code>NDNBOOST_ASSERT_MSG(!"ndnboost::container logic_error thrown", str)</code> is called
   //!   and <code>std::abort()</code> if the former returns.</li>
   //!
   //! <li>If NDNBOOST_NO_EXCEPTIONS and NDNBOOST_CONTAINER_USER_DEFINED_THROW_CALLBACKS are defined
   //!   the user must provide an implementation and the function should not return.</li>
   //! </ul>
   inline void throw_logic_error(const char* str)
   {
      throw std::logic_error(str);
   }

   //! Exception callback called by Boost.Container  to report errors that can only be detected during runtime.
   //! <ul>
   //! <li>If NDNBOOST_NO_EXCEPTIONS is NOT defined <code>std::runtime_error(str)</code> is thrown.</li>
   //!
   //! <li>If NDNBOOST_NO_EXCEPTIONS is defined and NDNBOOST_CONTAINER_USER_DEFINED_THROW_CALLBACKS
   //!   is NOT defined <code>NDNBOOST_ASSERT_MSG(!"ndnboost::container runtime_error thrown", str)</code> is called
   //!   and <code>std::abort()</code> if the former returns.</li>
   //!
   //! <li>If NDNBOOST_NO_EXCEPTIONS and NDNBOOST_CONTAINER_USER_DEFINED_THROW_CALLBACKS are defined
   //!   the user must provide an implementation and the function should not return.</li>
   //! </ul>
   inline void throw_runtime_error(const char* str)
   {
      throw std::runtime_error(str);
   }

#endif

}}  //namespace pkiboost { namespace container {

#include <ndnboost/container/detail/config_end.hpp>

#endif //#ifndef NDNBOOST_CONTAINER_THROW_EXCEPTION_HPP
