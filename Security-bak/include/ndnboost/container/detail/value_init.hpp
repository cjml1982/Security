//////////////////////////////////////////////////////////////////////////////
//
// (C) Copyright Ion Gaztanaga 2005-2013.
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt)
//
// See http://www.boost.org/libs/container for documentation.
//
//////////////////////////////////////////////////////////////////////////////

#ifndef NDNBOOST_CONTAINER_DETAIL_VALUE_INIT_HPP
#define NDNBOOST_CONTAINER_DETAIL_VALUE_INIT_HPP

#if defined(_MSC_VER)
#  pragma once
#endif

#include <ndnboost/container/detail/config_begin.hpp>
#include <ndnboost/container/detail/workaround.hpp>

namespace pkiboost {
namespace container {
namespace container_detail {

template<class T>
struct value_init
{
   value_init()
      : m_t()
   {}

   operator T &() { return m_t; }

   T m_t;
};

}  //namespace container_detail {
}  //namespace container {
}  //namespace pkiboost {

#include <ndnboost/container/detail/config_end.hpp>

#endif   //#ifndef NDNBOOST_CONTAINER_DETAIL_VALUE_INIT_HPP
