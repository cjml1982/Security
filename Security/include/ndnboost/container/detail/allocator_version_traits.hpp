//////////////////////////////////////////////////////////////////////////////
//
// (C) Copyright Ion Gaztanaga 2012-2013. Distributed under the Boost
// Software License, Version 1.0. (See accompanying file
// LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// See http://www.boost.org/libs/container for documentation.
//
//////////////////////////////////////////////////////////////////////////////

#ifndef NDNBOOST_CONTAINER_DETAIL_ALLOCATOR_VERSION_TRAITS_HPP
#define NDNBOOST_CONTAINER_DETAIL_ALLOCATOR_VERSION_TRAITS_HPP

#if defined(_MSC_VER)
#  pragma once
#endif

#include <ndnboost/container/detail/config_begin.hpp>
#include <ndnboost/container/detail/workaround.hpp>

#include <ndnboost/container/allocator_traits.hpp>             //allocator_traits
#include <ndnboost/container/throw_exception.hpp>
#include <ndnboost/container/detail/multiallocation_chain.hpp> //multiallocation_chain
#include <ndnboost/container/detail/version_type.hpp>          //version_type
#include <ndnboost/container/detail/allocation_type.hpp>       //allocation_type
#include <ndnboost/container/detail/mpl.hpp>                   //integral_constant
#include <ndnboost/intrusive/pointer_traits.hpp>               //pointer_traits
#include <utility>                                          //pair
#include <ndnboost/detail/no_exceptions_support.hpp>           //NDNBOOST_TRY

namespace pkiboost {
namespace container {
namespace container_detail {

template<class Allocator, unsigned Version = ndnboost::container::container_detail::version<Allocator>::value>
struct allocator_version_traits
{
   typedef ::ndnboost::container::container_detail::integral_constant
      <unsigned, Version> alloc_version;

   typedef typename Allocator::multiallocation_chain multiallocation_chain;

   typedef typename ndnboost::container::allocator_traits<Allocator>::pointer    pointer;
   typedef typename ndnboost::container::allocator_traits<Allocator>::size_type  size_type;

   //Node allocation interface
   static pointer allocate_one(Allocator &a)
   {  return a.allocate_one();   }

   static void deallocate_one(Allocator &a, const pointer &p)
   {  a.deallocate_one(p);   }

   static void allocate_individual(Allocator &a, size_type n, multiallocation_chain &m)
   {  return a.allocate_individual(n, m);   }

   static void deallocate_individual(Allocator &a, multiallocation_chain &holder)
   {  a.deallocate_individual(holder);   }

   static std::pair<pointer, bool>
      allocation_command(Allocator &a, allocation_type command,
                         size_type limit_size, size_type preferred_size,
                         size_type &received_size, const pointer &reuse)
   {
      return a.allocation_command
         (command, limit_size, preferred_size, received_size, reuse);
   }
};

template<class Allocator>
struct allocator_version_traits<Allocator, 1>
{
   typedef ::ndnboost::container::container_detail::integral_constant
      <unsigned, 1> alloc_version;

   typedef typename ndnboost::container::allocator_traits<Allocator>::pointer    pointer;
   typedef typename ndnboost::container::allocator_traits<Allocator>::size_type  size_type;
   typedef typename ndnboost::container::allocator_traits<Allocator>::value_type value_type;

   typedef typename ndnboost::intrusive::pointer_traits<pointer>::
         template rebind_pointer<void>::type                void_ptr;
   typedef container_detail::basic_multiallocation_chain
      <void_ptr>                                            multialloc_cached_counted;
   typedef ndnboost::container::container_detail::
      transform_multiallocation_chain
         < multialloc_cached_counted, value_type>           multiallocation_chain;

   //Node allocation interface
   static pointer allocate_one(Allocator &a)
   {  return a.allocate(1);   }

   static void deallocate_one(Allocator &a, const pointer &p)
   {  a.deallocate(p, 1);   }

   static void deallocate_individual(Allocator &a, multiallocation_chain &holder)
   {
      size_type n = holder.size();
      typename multiallocation_chain::iterator it = holder.begin();
      while(n--){
         pointer p = ndnboost::intrusive::pointer_traits<pointer>::pointer_to(*it);
         ++it;
         a.deallocate(p, 1);
      }
   }

   struct allocate_individual_rollback
   {
      allocate_individual_rollback(Allocator &a, multiallocation_chain &chain)
         : mr_a(a), mp_chain(&chain)
      {}

      ~allocate_individual_rollback()
      {
         if(mp_chain)
            allocator_version_traits::deallocate_individual(mr_a, *mp_chain);
      }

      void release()
      {
         mp_chain = 0;
      }

      Allocator &mr_a;
      multiallocation_chain * mp_chain;
   };

   static void allocate_individual(Allocator &a, size_type n, multiallocation_chain &m)
   {
      allocate_individual_rollback rollback(a, m);
      while(n--){
         m.push_front(a.allocate(1));
      }
      rollback.release();
   }

   static std::pair<pointer, bool>
      allocation_command(Allocator &a, allocation_type command,
                         size_type, size_type preferred_size,
                         size_type &received_size, const pointer &)
   {
      std::pair<pointer, bool> ret(pointer(), false);
      if(!(command & allocate_new)){
         if(!(command & nothrow_allocation)){
            throw_logic_error("version 1 allocator without allocate_new flag");
         }
      }
      else{
         received_size = preferred_size;
         NDNBOOST_TRY{
            ret.first = a.allocate(received_size);
         }
         NDNBOOST_CATCH(...){
            if(!(command & nothrow_allocation)){
               NDNBOOST_RETHROW
            }
         }
         NDNBOOST_CATCH_END
      }
      return ret;
   }
};

}  //namespace container_detail {
}  //namespace container {
}  //namespace pkiboost {

#include <ndnboost/container/detail/config_end.hpp>

#endif // ! defined(NDNBOOST_CONTAINER_DETAIL_ALLOCATOR_VERSION_TRAITS_HPP)
