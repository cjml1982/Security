/////////////////////////////////////////////////////////////////////////////
//
// (C) Copyright Ion Gaztanaga  2006-2013
//
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)
//
// See http://www.boost.org/libs/intrusive for documentation.
//
/////////////////////////////////////////////////////////////////////////////

#ifndef NDNBOOST_INTRUSIVE_DETAIL_UTILITIES_HPP
#define NDNBOOST_INTRUSIVE_DETAIL_UTILITIES_HPP

#include <ndnboost/intrusive/detail/config_begin.hpp>
#include <ndnboost/intrusive/pointer_traits.hpp>
#include <ndnboost/intrusive/detail/parent_from_member.hpp>
#include <ndnboost/intrusive/detail/ebo_functor_holder.hpp>
#include <ndnboost/intrusive/link_mode.hpp>
#include <ndnboost/intrusive/detail/mpl.hpp>
#include <ndnboost/intrusive/detail/assert.hpp>
#include <ndnboost/intrusive/detail/is_stateful_value_traits.hpp>
#include <ndnboost/intrusive/detail/memory_util.hpp>
#include <ndnboost/cstdint.hpp>
#include <cstddef>
#include <climits>
#include <iterator>
#include <ndnboost/cstdint.hpp>
#include <ndnboost/static_assert.hpp>
#include <ndnboost/detail/no_exceptions_support.hpp>
#include <functional>
#include <ndnboost/functional/hash.hpp>
#include <ndnboost/tti/tti.hpp>

namespace pkiboost {
namespace intrusive {

enum algo_types
{
   CircularListAlgorithms,
   CircularSListAlgorithms,
   LinearSListAlgorithms,
   BsTreeAlgorithms,
   RbTreeAlgorithms,
   AvlTreeAlgorithms,
   SgTreeAlgorithms,
   SplayTreeAlgorithms,
   TreapAlgorithms
};

template<algo_types AlgoType, class NodeTraits>
struct get_algo;

template <link_mode_type link_mode>
struct is_safe_autounlink
{
   static const bool value = 
      (int)link_mode == (int)auto_unlink   ||
      (int)link_mode == (int)safe_link;
};

namespace detail {

template <class T>
struct internal_member_value_traits
{
   template <class U> static detail::one test(...);
   template <class U> static detail::two test(typename U::member_value_traits* = 0);
   static const bool value = sizeof(test<T>(0)) == sizeof(detail::two);
};

#define NDNBOOST_INTRUSIVE_INTERNAL_STATIC_BOOL_IS_TRUE(TRAITS_PREFIX, TYPEDEF_TO_FIND) \
template <class T>\
struct TRAITS_PREFIX##_bool\
{\
   template<bool Add>\
   struct two_or_three {one _[2 + Add];};\
   template <class U> static one test(...);\
   template <class U> static two_or_three<U::TYPEDEF_TO_FIND> test (int);\
   static const std::size_t value = sizeof(test<T>(0));\
};\
\
template <class T>\
struct TRAITS_PREFIX##_bool_is_true\
{\
   static const bool value = TRAITS_PREFIX##_bool<T>::value > sizeof(one)*2;\
};\
//

NDNBOOST_INTRUSIVE_INTERNAL_STATIC_BOOL_IS_TRUE(internal_base_hook, hooktags::is_base_hook)
NDNBOOST_INTRUSIVE_INTERNAL_STATIC_BOOL_IS_TRUE(internal_any_hook, is_any_hook)
NDNBOOST_INTRUSIVE_INTERNAL_STATIC_BOOL_IS_TRUE(resizable, resizable)

template <class T>
inline T* to_raw_pointer(T* p)
{  return p; }

template <class Pointer>
inline typename ndnboost::intrusive::pointer_traits<Pointer>::element_type*
to_raw_pointer(const Pointer &p)
{  return ndnboost::intrusive::detail::to_raw_pointer(p.operator->());  }

//This functor compares a stored value
//and the one passed as an argument
template<class ConstReference>
class equal_to_value
{
   ConstReference t_;

   public:
   equal_to_value(ConstReference t)
      :  t_(t)
   {}

   bool operator()(ConstReference t)const
   {  return t_ == t;   }
};

class null_disposer
{
   public:
   template <class Pointer>
   void operator()(Pointer)
   {}
};

template<class NodeAlgorithms>
class init_disposer
{
   typedef typename NodeAlgorithms::node_ptr node_ptr;

   public:
   void operator()(const node_ptr & p)
   {  NodeAlgorithms::init(p);   }
};

template<bool ConstantSize, class SizeType, class Tag = void>
struct size_holder
{
   static const bool constant_time_size = ConstantSize;
   typedef SizeType  size_type;

   SizeType get_size() const
   {  return size_;  }

   void set_size(SizeType size)
   {  size_ = size; }

   void decrement()
   {  --size_; }

   void increment()
   {  ++size_; }

   void increase(SizeType n)
   {  size_ += n; }

   void decrease(SizeType n)
   {  size_ -= n; }

   SizeType size_;
};

template<class SizeType, class Tag>
struct size_holder<false, SizeType, Tag>
{
   static const bool constant_time_size = false;
   typedef SizeType  size_type;

   size_type get_size() const
   {  return 0;  }

   void set_size(size_type)
   {}

   void decrement()
   {}

   void increment()
   {}

   void increase(SizeType)
   {}

   void decrease(SizeType)
   {}
};

template<class KeyValueCompare, class ValueTraits>
struct key_nodeptr_comp
   :  private detail::ebo_functor_holder<KeyValueCompare>
{
   typedef ValueTraits                              value_traits;
   typedef typename value_traits::value_type        value_type;
   typedef typename value_traits::node_ptr          node_ptr;
   typedef typename value_traits::const_node_ptr    const_node_ptr;
   typedef detail::ebo_functor_holder<KeyValueCompare>   base_t;
   key_nodeptr_comp(KeyValueCompare kcomp, const ValueTraits *traits)
      :  base_t(kcomp), traits_(traits)
   {}

   template<class T>
   struct is_node_ptr
   {
      static const bool value = is_same<T, const_node_ptr>::value || is_same<T, node_ptr>::value;
   };

   template<class T>
   const value_type & key_forward
      (const T &node, typename enable_if_c<is_node_ptr<T>::value>::type * = 0) const
   {  return *traits_->to_value_ptr(node);  }

   template<class T>
   const T & key_forward(const T &key, typename enable_if_c<!is_node_ptr<T>::value>::type* = 0) const
   {  return key;  }


   template<class KeyType, class KeyType2>
   bool operator()(const KeyType &key1, const KeyType2 &key2) const
   {  return base_t::get()(this->key_forward(key1), this->key_forward(key2));  }

   const ValueTraits *const traits_;
};

template<class F, class ValueTraits, algo_types AlgoType>
struct node_cloner
   :  private detail::ebo_functor_holder<F>
{
   typedef ValueTraits                         value_traits;
   typedef typename value_traits::node_traits node_traits;
   typedef typename node_traits::node_ptr          node_ptr;
   typedef detail::ebo_functor_holder<F>           base_t;
   typedef typename get_algo< AlgoType
                            , node_traits>::type   node_algorithms;
   static const bool safemode_or_autounlink =
      is_safe_autounlink<value_traits::link_mode>::value;
   typedef typename value_traits::value_type  value_type;
   typedef typename value_traits::pointer     pointer;
   typedef typename node_traits::node              node;
   typedef typename value_traits::const_node_ptr    const_node_ptr;
   typedef typename value_traits::reference   reference;
   typedef typename value_traits::const_reference const_reference;

   node_cloner(F f, const ValueTraits *traits)
      :  base_t(f), traits_(traits)
   {}

   // tree-based containers use this method, which is proxy-reference friendly
   node_ptr operator()(const node_ptr & p)
   {
      const_reference v = *traits_->to_value_ptr(p);
      node_ptr n = traits_->to_node_ptr(*base_t::get()(v));
      //Cloned node must be in default mode if the linking mode requires it
      if(safemode_or_autounlink)
         NDNBOOST_INTRUSIVE_SAFE_HOOK_DEFAULT_ASSERT(node_algorithms::unique(n));
      return n;
   }

   // hashtables use this method, which is proxy-reference unfriendly
   node_ptr operator()(const node &to_clone)
   {
      const value_type &v =
         *traits_->to_value_ptr
            (pointer_traits<const_node_ptr>::pointer_to(to_clone));
      node_ptr n = traits_->to_node_ptr(*base_t::get()(v));
      //Cloned node must be in default mode if the linking mode requires it
      if(safemode_or_autounlink)
         NDNBOOST_INTRUSIVE_SAFE_HOOK_DEFAULT_ASSERT(node_algorithms::unique(n));
      return n;
   }

   const ValueTraits * const traits_;
};

template<class F, class ValueTraits, algo_types AlgoType>
struct node_disposer
   :  private detail::ebo_functor_holder<F>
{
   typedef ValueTraits                         value_traits;
   typedef typename value_traits::node_traits node_traits;
   typedef typename node_traits::node_ptr          node_ptr;
   typedef detail::ebo_functor_holder<F>           base_t;
   typedef typename get_algo< AlgoType
                            , node_traits>::type   node_algorithms;
   static const bool safemode_or_autounlink =
      is_safe_autounlink<value_traits::link_mode>::value;

   node_disposer(F f, const ValueTraits *cont)
      :  base_t(f), traits_(cont)
   {}

   void operator()(const node_ptr & p)
   {
      if(safemode_or_autounlink)
         node_algorithms::init(p);
      base_t::get()(traits_->to_value_ptr(p));
   }
   const ValueTraits * const traits_;
};

template<class VoidPointer>
struct dummy_constptr
{
   typedef typename ndnboost::intrusive::pointer_traits<VoidPointer>::
      template rebind_pointer<const void>::type ConstVoidPtr;

   explicit dummy_constptr(ConstVoidPtr)
   {}

   dummy_constptr()
   {}

   ConstVoidPtr get_ptr() const
   {  return ConstVoidPtr();  }
};

template<class VoidPointer>
struct constptr
{
   typedef typename ndnboost::intrusive::pointer_traits<VoidPointer>::
      template rebind_pointer<const void>::type ConstVoidPtr;

   constptr()
   {}

   explicit constptr(const ConstVoidPtr &ptr)
      :  const_void_ptr_(ptr)
   {}

   const void *get_ptr() const
   {  return ndnboost::intrusive::detail::to_raw_pointer(const_void_ptr_);  }

   ConstVoidPtr const_void_ptr_;
};

template <class VoidPointer, bool store_ptr>
struct select_constptr
{
   typedef typename detail::if_c
      < store_ptr
      , constptr<VoidPointer>
      , dummy_constptr<VoidPointer>
      >::type type;
};

template<class T, bool Add>
struct add_const_if_c
{
   typedef typename detail::if_c
      < Add
      , typename detail::add_const<T>::type
      , T
      >::type type;
};

template <link_mode_type LinkMode>
struct link_dispatch
{};

template<class Hook>
void destructor_impl(Hook &hook, detail::link_dispatch<safe_link>)
{  //If this assertion raises, you might have destroyed an object
   //while it was still inserted in a container that is alive.
   //If so, remove the object from the container before destroying it.
   (void)hook; NDNBOOST_INTRUSIVE_SAFE_HOOK_DESTRUCTOR_ASSERT(!hook.is_linked());
}

template<class Hook>
void destructor_impl(Hook &hook, detail::link_dispatch<auto_unlink>)
{  hook.unlink();  }

template<class Hook>
void destructor_impl(Hook &, detail::link_dispatch<normal_link>)
{}

///////////////////////////
// floor_log2  Dispatcher
////////////////////////////

#if defined(_MSC_VER) && (_MSC_VER >= 1300)

   }}} //namespace pkiboost::intrusive::detail

   //Use _BitScanReverseXX intrinsics

   #if defined(_M_X64) || defined(_M_AMD64) || defined(_M_IA64)   //64 bit target
      #define NDNBOOST_INTRUSIVE_BSR_INTRINSIC_64_BIT
   #endif

   #ifndef __INTRIN_H_	// Avoid including any windows system header
      #ifdef __cplusplus
      extern "C" {
      #endif // __cplusplus

      #if defined(NDNBOOST_INTRUSIVE_BSR_INTRINSIC_64_BIT)   //64 bit target
         unsigned char _BitScanReverse64(unsigned long *index, unsigned __int64 mask);
         #pragma intrinsic(_BitScanReverse64)
      #else //32 bit target
         unsigned char _BitScanReverse(unsigned long *index, unsigned long mask);
         #pragma intrinsic(_BitScanReverse)
      #endif

      #ifdef __cplusplus
      }
      #endif // __cplusplus
   #endif // __INTRIN_H_

   #ifdef NDNBOOST_INTRUSIVE_BSR_INTRINSIC_64_BIT
      #define NDNBOOST_INTRUSIVE_BSR_INTRINSIC _BitScanReverse64
      #undef NDNBOOST_INTRUSIVE_BSR_INTRINSIC_64_BIT
   #else
      #define NDNBOOST_INTRUSIVE_BSR_INTRINSIC _BitScanReverse
   #endif

   namespace pkiboost {
   namespace intrusive {
   namespace detail {

   inline std::size_t floor_log2 (std::size_t x)
   {
      unsigned long log2;
      NDNBOOST_INTRUSIVE_BSR_INTRINSIC( &log2, (unsigned long)x );
      return log2;
   }

   #undef NDNBOOST_INTRUSIVE_BSR_INTRINSIC

#elif defined(__GNUC__) && ((__GNUC__ >= 4) || (__GNUC__ == 3 && __GNUC_MINOR__ >= 4)) //GCC >=3.4

   //Compile-time error in case of missing specialization
   template<class Uint>
   struct builtin_clz_dispatch;

   #if defined(NDNBOOST_HAS_LONG_LONG)
   template<>
   struct builtin_clz_dispatch<unsigned long long>
   {
      static unsigned long long call(unsigned long long n)
      {  return __builtin_clzll(n); }
   };
   #endif

   template<>
   struct builtin_clz_dispatch<unsigned long>
   {
      static unsigned long call(unsigned long n)
      {  return __builtin_clzl(n); }
   };

   template<>
   struct builtin_clz_dispatch<unsigned int>
   {
      static unsigned int call(unsigned int n)
      {  return __builtin_clz(n); }
   };

   inline std::size_t floor_log2(std::size_t n)
   {
      return sizeof(std::size_t)*CHAR_BIT - std::size_t(1) - builtin_clz_dispatch<std::size_t>::call(n);
   }

#else //Portable methods

////////////////////////////
// Generic method
////////////////////////////

   inline std::size_t floor_log2_get_shift(std::size_t n, true_ )//power of two size_t
   {  return n >> 1;  }

   inline std::size_t floor_log2_get_shift(std::size_t n, false_ )//non-power of two size_t
   {  return (n >> 1) + ((n & 1u) & (n != 1)); }

   template<std::size_t N>
   inline std::size_t floor_log2 (std::size_t x, integer<std::size_t, N>)
   {
      const std::size_t Bits = N;
      const bool Size_t_Bits_Power_2= !(Bits & (Bits-1));

      std::size_t n = x;
      std::size_t log2 = 0;

      std::size_t remaining_bits = Bits;
      std::size_t shift = floor_log2_get_shift(remaining_bits, bool_<Size_t_Bits_Power_2>());
      while(shift){
         std::size_t tmp = n >> shift;
         if (tmp){
            log2 += shift, n = tmp;
         }
         shift = floor_log2_get_shift(shift, bool_<Size_t_Bits_Power_2>());
      }

      return log2;
   }

   ////////////////////////////
   // DeBruijn method
   ////////////////////////////

   //Taken from:
   //http://stackoverflow.com/questions/11376288/fast-computing-of-log2-for-64-bit-integers
   //Thanks to Desmond Hume

   inline std::size_t floor_log2 (std::size_t v, integer<std::size_t, 32>)
   {
      static const int MultiplyDeBruijnBitPosition[32] = 
      {
         0, 9, 1, 10, 13, 21, 2, 29, 11, 14, 16, 18, 22, 25, 3, 30,
         8, 12, 20, 28, 15, 17, 24, 7, 19, 27, 23, 6, 26, 5, 4, 31
      };

      v |= v >> 1;
      v |= v >> 2;
      v |= v >> 4;
      v |= v >> 8;
      v |= v >> 16;

      return MultiplyDeBruijnBitPosition[(std::size_t)(v * 0x07C4ACDDU) >> 27];
   }

   inline std::size_t floor_log2 (std::size_t v, integer<std::size_t, 64>)
   {
      static const std::size_t MultiplyDeBruijnBitPosition[64] = {
      63,  0, 58,  1, 59, 47, 53,  2,
      60, 39, 48, 27, 54, 33, 42,  3,
      61, 51, 37, 40, 49, 18, 28, 20,
      55, 30, 34, 11, 43, 14, 22,  4,
      62, 57, 46, 52, 38, 26, 32, 41,
      50, 36, 17, 19, 29, 10, 13, 21,
      56, 45, 25, 31, 35, 16,  9, 12,
      44, 24, 15,  8, 23,  7,  6,  5};

      v |= v >> 1;
      v |= v >> 2;
      v |= v >> 4;
      v |= v >> 8;
      v |= v >> 16;
      v |= v >> 32;
      return MultiplyDeBruijnBitPosition[((std::size_t)((v - (v >> 1))*0x07EDD5E59A4E28C2ULL)) >> 58];
   }


   inline std::size_t floor_log2 (std::size_t x)
   {
      const std::size_t Bits = sizeof(std::size_t)*CHAR_BIT;
      return floor_log2(x, integer<std::size_t, Bits>());
   }

#endif

//Thanks to Laurent de Soras in
//http://www.flipcode.com/archives/Fast_log_Function.shtml
inline float fast_log2 (float val)
{
   union caster_t
   {
      ndnboost::uint32_t x;
      float val;
   } caster;

   caster.val = val;
   ndnboost::uint32_t x = caster.x;
   const int log_2 = int((x >> 23) & 255) - 128;
   x &= ~(ndnboost::uint32_t(255u) << 23u);
   x += ndnboost::uint32_t(127) << 23u;
   caster.x = x;
   val = caster.val;
   //1+log2(m), m ranging from 1 to 2
   //3rd degree polynomial keeping first derivate continuity.
   //For less precision the line can be commented out
   val = ((-1.f/3.f) * val + 2.f) * val - (2.f/3.f);
   return (val + log_2);
}

inline std::size_t ceil_log2 (std::size_t x)
{
   return static_cast<std::size_t>((x & (x-1)) != 0) + floor_log2(x);
}

template<class SizeType, std::size_t N>
struct numbits_eq
{
   static const bool value = sizeof(SizeType)*CHAR_BIT == N;
};

template<class SizeType, class Enabler = void >
struct sqrt2_pow_max;

template <class SizeType>
struct sqrt2_pow_max<SizeType, typename enable_if< numbits_eq<SizeType, 32> >::type>
{
   static const ndnboost::uint32_t value = 0xb504f334;
   static const std::size_t pow   = 31;
};

#ifndef NDNBOOST_NO_INT64_T

template <class SizeType>
struct sqrt2_pow_max<SizeType, typename enable_if< numbits_eq<SizeType, 64> >::type>
{
   static const ndnboost::uint64_t value = 0xb504f333f9de6484ull;
   static const std::size_t pow   = 63;
};

#endif   //NDNBOOST_NO_INT64_T

// Returns floor(pow(sqrt(2), x * 2 + 1)).
// Defined for X from 0 up to the number of bits in size_t minus 1.
inline std::size_t sqrt2_pow_2xplus1 (std::size_t x)
{
   const std::size_t value = (std::size_t)sqrt2_pow_max<std::size_t>::value;
   const std::size_t pow   = (std::size_t)sqrt2_pow_max<std::size_t>::pow;
   return (value >> (pow - x)) + 1;
}

template<class Container, class Disposer>
class exception_disposer
{
   Container *cont_;
   Disposer  &disp_;

   exception_disposer(const exception_disposer&);
   exception_disposer &operator=(const exception_disposer&);

   public:
   exception_disposer(Container &cont, Disposer &disp)
      :  cont_(&cont), disp_(disp)
   {}

   void release()
   {  cont_ = 0;  }

   ~exception_disposer()
   {
      if(cont_){
         cont_->clear_and_dispose(disp_);
      }
   }
};

template<class Container, class Disposer, class SizeType>
class exception_array_disposer
{
   Container *cont_;
   Disposer  &disp_;
   SizeType  &constructed_;

   exception_array_disposer(const exception_array_disposer&);
   exception_array_disposer &operator=(const exception_array_disposer&);

   public:

   exception_array_disposer
      (Container &cont, Disposer &disp, SizeType &constructed)
      :  cont_(&cont), disp_(disp), constructed_(constructed)
   {}

   void release()
   {  cont_ = 0;  }

   ~exception_array_disposer()
   {
      SizeType n = constructed_;
      if(cont_){
         while(n--){
            cont_[n].clear_and_dispose(disp_);
         }
      }
   }
};

template<class ValueTraits, bool IsConst>
struct node_to_value
   :  public detail::select_constptr
      < typename pointer_traits
            <typename ValueTraits::pointer>::template rebind_pointer<void>::type
      , is_stateful_value_traits<ValueTraits>::value
      >::type
{
   static const bool stateful_value_traits = is_stateful_value_traits<ValueTraits>::value;
   typedef typename detail::select_constptr
      < typename pointer_traits
            <typename ValueTraits::pointer>::
               template rebind_pointer<void>::type
      , stateful_value_traits >::type                 Base;

   typedef ValueTraits                                 value_traits;
   typedef typename value_traits::value_type           value_type;
   typedef typename value_traits::node_traits::node    node;
   typedef typename detail::add_const_if_c
         <value_type, IsConst>::type                   vtype;
   typedef typename detail::add_const_if_c
         <node, IsConst>::type                         ntype;
   typedef typename pointer_traits
      <typename ValueTraits::pointer>::
         template rebind_pointer<ntype>::type          npointer;
   typedef typename pointer_traits<npointer>::
      template rebind_pointer<const ValueTraits>::type const_value_traits_ptr;

   node_to_value(const const_value_traits_ptr &ptr)
      :  Base(ptr)
   {}

   typedef vtype &                                 result_type;
   typedef ntype &                                 first_argument_type;

   const_value_traits_ptr get_value_traits() const
   {  return pointer_traits<const_value_traits_ptr>::static_cast_from(Base::get_ptr());  }

   result_type to_value(first_argument_type arg, false_) const
   {  return *(value_traits::to_value_ptr(pointer_traits<npointer>::pointer_to(arg)));  }

   result_type to_value(first_argument_type arg, true_) const
   {  return *(this->get_value_traits()->to_value_ptr(pointer_traits<npointer>::pointer_to(arg))); }

   result_type operator()(first_argument_type arg) const
   {  return this->to_value(arg, bool_<stateful_value_traits>()); }
};

//This is not standard, but should work with all compilers
union max_align
{
   char        char_;
   short       short_;
   int         int_;
   long        long_;
   #ifdef NDNBOOST_HAS_LONG_LONG
   long long   long_long_;
   #endif
   float       float_;
   double      double_;
   long double long_double_;
   void *      void_ptr_;
};

template<class T, std::size_t N>
class array_initializer
{
   public:
   template<class CommonInitializer>
   array_initializer(const CommonInitializer &init)
   {
      char *init_buf = (char*)rawbuf;
      std::size_t i = 0;
      NDNBOOST_TRY{
         for(; i != N; ++i){
            new(init_buf)T(init);
            init_buf += sizeof(T);
         }
      }
      NDNBOOST_CATCH(...){
         while(i--){
            init_buf -= sizeof(T);
            ((T*)init_buf)->~T();
         }
         NDNBOOST_RETHROW;
      }
      NDNBOOST_CATCH_END
   }

   operator T* ()
   {  return (T*)(rawbuf);  }

   operator const T*() const
   {  return (const T*)(rawbuf);  }

   ~array_initializer()
   {
      char *init_buf = (char*)rawbuf + N*sizeof(T);
      for(std::size_t i = 0; i != N; ++i){
         init_buf -= sizeof(T);
         ((T*)init_buf)->~T();
      }
   }

   private:
   detail::max_align rawbuf[(N*sizeof(T)-1)/sizeof(detail::max_align)+1];
};




template<class It>
class reverse_iterator
	: public std::iterator<
		typename std::iterator_traits<It>::iterator_category,
		typename std::iterator_traits<It>::value_type,
		typename std::iterator_traits<It>::difference_type,
		typename std::iterator_traits<It>::pointer,
		typename std::iterator_traits<It>::reference>
{
   public:
	typedef typename std::iterator_traits<It>::pointer pointer;
	typedef typename std::iterator_traits<It>::reference reference;
 	typedef typename std::iterator_traits<It>::difference_type difference_type;
	typedef It iterator_type;

	reverse_iterator(){}

	explicit reverse_iterator(It r)
		: m_current(r)
   {}

	template<class OtherIt>
	reverse_iterator(const reverse_iterator<OtherIt>& r)
	   : m_current(r.base())
	{}

	It base() const
   {  return m_current;  }

	reference operator*() const
   {  It temp(m_current);   --temp; return *temp; }

	pointer operator->() const
   {  It temp(m_current);   --temp; return temp.operator->(); }

	reference operator[](difference_type off) const
	{  return this->m_current[-off];  }

	reverse_iterator& operator++()
   {  --m_current;   return *this;   }

	reverse_iterator operator++(int)
	{
		reverse_iterator temp = *this;
		--m_current;
		return temp;
	}

	reverse_iterator& operator--()
	{
	   ++m_current;
		return *this;
   }

	reverse_iterator operator--(int)
	{
	   reverse_iterator temp(*this);
	   ++m_current;
	   return temp;
	}

	friend bool operator==(const reverse_iterator& l, const reverse_iterator& r)
	{  return l.m_current == r.m_current;  }

	friend bool operator!=(const reverse_iterator& l, const reverse_iterator& r)
	{  return l.m_current != r.m_current;  }

	friend bool operator<(const reverse_iterator& l, const reverse_iterator& r)
	{  return l.m_current < r.m_current;  }

	friend bool operator<=(const reverse_iterator& l, const reverse_iterator& r)
	{  return l.m_current <= r.m_current;  }

	friend bool operator>(const reverse_iterator& l, const reverse_iterator& r)
	{  return l.m_current > r.m_current;  }

	friend bool operator>=(const reverse_iterator& l, const reverse_iterator& r)
	{  return l.m_current >= r.m_current;  }

	reverse_iterator& operator+=(difference_type off)
	{  m_current -= off; return *this;  }

	friend reverse_iterator operator+(const reverse_iterator & l, difference_type off)
	{
      reverse_iterator tmp(l.m_current);
      tmp.m_current -= off;
      return tmp;
   }

	reverse_iterator& operator-=(difference_type off)
	{  m_current += off; return *this;  }

	friend reverse_iterator operator-(const reverse_iterator & l, difference_type off)
	{
      reverse_iterator tmp(l.m_current);
      tmp.m_current += off;
      return tmp;
   }

	friend difference_type operator-(const reverse_iterator& l, const reverse_iterator& r)
	{  return r.m_current - l.m_current;  }

   private:
	It m_current;	// the wrapped iterator
};

template<class ConstNodePtr>
struct uncast_types
{
   typedef typename pointer_traits<ConstNodePtr>::element_type element_type;
   typedef typename remove_const<element_type>::type           non_const_type;
   typedef typename pointer_traits<ConstNodePtr>::
      template rebind_pointer<non_const_type>::type            non_const_pointer;
   typedef pointer_traits<non_const_pointer>                   non_const_traits;
};

template<class ConstNodePtr>
static typename uncast_types<ConstNodePtr>::non_const_pointer
   uncast(const ConstNodePtr & ptr)
{
   return uncast_types<ConstNodePtr>::non_const_traits::const_cast_from(ptr);
}

// trivial header node holder
template < typename NodeTraits >
struct default_header_holder : public NodeTraits::node
{
    typedef NodeTraits node_traits;
    typedef typename node_traits::node node;
    typedef typename node_traits::node_ptr node_ptr;
    typedef typename node_traits::const_node_ptr const_node_ptr;

    default_header_holder() : node() {}

    const_node_ptr get_node() const
    { return pointer_traits< const_node_ptr >::pointer_to(*static_cast< const node* >(this)); }

    node_ptr get_node()
    { return pointer_traits< node_ptr >::pointer_to(*static_cast< node* >(this)); }

    // (unsafe) downcast used to implement container-from-iterator
    static default_header_holder* get_holder(const node_ptr &p)
    { return static_cast< default_header_holder* >(ndnboost::intrusive::detail::to_raw_pointer(p)); }
};

// type function producing the header node holder
template < typename Value_Traits, typename HeaderHolder >
struct get_header_holder_type
{
    typedef HeaderHolder type;
};
template < typename Value_Traits >
struct get_header_holder_type< Value_Traits, void >
{
    typedef default_header_holder< typename Value_Traits::node_traits > type;
};

} //namespace detail

template<class Node, class Tag, unsigned int>
struct node_holder
   :  public Node
{};

template<class T, class NodePtr, class Tag, unsigned int Type>
struct bhtraits_base
{
   public:
   typedef NodePtr                                                   node_ptr;
   typedef typename pointer_traits<node_ptr>::element_type           node;
   typedef node_holder<node, Tag, Type>                              node_holder_type;
   typedef T                                                         value_type;
   typedef typename pointer_traits<node_ptr>::
      template rebind_pointer<const node>::type                      const_node_ptr;
   typedef typename pointer_traits<node_ptr>::
      template rebind_pointer<T>::type                               pointer;
   typedef typename pointer_traits<node_ptr>::
      template rebind_pointer<const T>::type                         const_pointer;
   //typedef typename pointer_traits<pointer>::reference               reference;
   //typedef typename pointer_traits<const_pointer>::reference         const_reference;
   typedef T &                                                       reference;
   typedef const T &                                                 const_reference;
   typedef node_holder_type &                                        node_holder_reference;
   typedef const node_holder_type &                                  const_node_holder_reference;
   typedef node&                                                     node_reference;
   typedef const node &                                              const_node_reference;

   static pointer to_value_ptr(const node_ptr & n)
   {
      return pointer_traits<pointer>::pointer_to
         (static_cast<reference>(static_cast<node_holder_reference>(*n)));
   }

   static const_pointer to_value_ptr(const const_node_ptr & n)
   {
      return pointer_traits<const_pointer>::pointer_to
         (static_cast<const_reference>(static_cast<const_node_holder_reference>(*n)));
   }

   static node_ptr to_node_ptr(reference value)
   {
      return pointer_traits<node_ptr>::pointer_to
         (static_cast<node_reference>(static_cast<node_holder_reference>(value)));
   }

   static const_node_ptr to_node_ptr(const_reference value)
   {
      return pointer_traits<const_node_ptr>::pointer_to
         (static_cast<const_node_reference>(static_cast<const_node_holder_reference>(value)));
   }
};

template<class T, class NodeTraits, link_mode_type LinkMode, class Tag, unsigned int Type>
struct bhtraits
   : public bhtraits_base<T, typename NodeTraits::node_ptr, Tag, Type>
{
   static const link_mode_type link_mode = LinkMode;
   typedef NodeTraits node_traits;
};

/*
template<class T, class NodePtr, typename pointer_traits<NodePtr>::element_type T::* P>
struct mhtraits_base
{
   public:
   typedef typename pointer_traits<NodePtr>::element_type            node;
   typedef T                                                         value_type;
   typedef NodePtr                                                   node_ptr;
   typedef typename pointer_traits<node_ptr>::
      template rebind_pointer<const node>::type                      const_node_ptr;
   typedef typename pointer_traits<node_ptr>::
      template rebind_pointer<T>::type                               pointer;
   typedef typename pointer_traits<node_ptr>::
      template rebind_pointer<const T>::type                         const_pointer;
   typedef T &                                                       reference;
   typedef const T &                                                 const_reference;
   typedef node&                                                     node_reference;
   typedef const node &                                              const_node_reference;

   static node_ptr to_node_ptr(reference value)
   {
      return pointer_traits<node_ptr>::pointer_to
         (static_cast<node_reference>(value.*P));
   }

   static const_node_ptr to_node_ptr(const_reference value)
   {
      return pointer_traits<const_node_ptr>::pointer_to
         (static_cast<const_node_reference>(value.*P));
   }

   static pointer to_value_ptr(const node_ptr & n)
   {
      return pointer_traits<pointer>::pointer_to
         (*detail::parent_from_member<T, node>
            (ndnboost::intrusive::detail::to_raw_pointer(n), P));
   }

   static const_pointer to_value_ptr(const const_node_ptr & n)
   {
      return pointer_traits<const_pointer>::pointer_to
         (*detail::parent_from_member<T, node>
            (ndnboost::intrusive::detail::to_raw_pointer(n), P));
   }
};


template<class T, class NodeTraits, typename NodeTraits::node T::* P, link_mode_type LinkMode>
struct mhtraits
   : public mhtraits_base<T, typename NodeTraits::node_ptr, P>
{
   static const link_mode_type link_mode = LinkMode;
   typedef NodeTraits node_traits;
};
*/


template<class T, class Hook, Hook T::* P>
struct mhtraits
{
   public:
   typedef Hook                                                      hook_type;
   typedef typename hook_type::hooktags::node_traits                 node_traits;
   typedef typename node_traits::node                                node;
   typedef T                                                         value_type;
   typedef typename node_traits::node_ptr                            node_ptr;
   typedef typename node_traits::const_node_ptr                      const_node_ptr;
   typedef typename pointer_traits<node_ptr>::
      template rebind_pointer<T>::type                               pointer;
   typedef typename pointer_traits<node_ptr>::
      template rebind_pointer<const T>::type                         const_pointer;
   typedef T &                                                       reference;
   typedef const T &                                                 const_reference;
   typedef node&                                                     node_reference;
   typedef const node &                                              const_node_reference;
   typedef hook_type&                                                hook_reference;
   typedef const hook_type &                                         const_hook_reference;

   static const link_mode_type link_mode = Hook::hooktags::link_mode;

   static node_ptr to_node_ptr(reference value)
   {
      return pointer_traits<node_ptr>::pointer_to
         (static_cast<node_reference>(static_cast<hook_reference>(value.*P)));
   }

   static const_node_ptr to_node_ptr(const_reference value)
   {
      return pointer_traits<const_node_ptr>::pointer_to
         (static_cast<const_node_reference>(static_cast<const_hook_reference>(value.*P)));
   }

   static pointer to_value_ptr(const node_ptr & n)
   {
      return pointer_traits<pointer>::pointer_to
         (*detail::parent_from_member<T, Hook>
            (static_cast<Hook*>(ndnboost::intrusive::detail::to_raw_pointer(n)), P));
   }

   static const_pointer to_value_ptr(const const_node_ptr & n)
   {
      return pointer_traits<const_pointer>::pointer_to
         (*detail::parent_from_member<T, Hook>
            (static_cast<const Hook*>(ndnboost::intrusive::detail::to_raw_pointer(n)), P));
   }
};


template<class Functor>
struct fhtraits
{
   public:
   typedef typename Functor::hook_type                               hook_type;
   typedef typename Functor::hook_ptr                                hook_ptr;
   typedef typename Functor::const_hook_ptr                          const_hook_ptr;
   typedef typename hook_type::hooktags::node_traits                 node_traits;
   typedef typename node_traits::node                                node;
   typedef typename Functor::value_type                              value_type;
   typedef typename node_traits::node_ptr                            node_ptr;
   typedef typename node_traits::const_node_ptr                      const_node_ptr;
   typedef typename pointer_traits<node_ptr>::
      template rebind_pointer<value_type>::type                      pointer;
   typedef typename pointer_traits<node_ptr>::
      template rebind_pointer<const value_type>::type                const_pointer;
   typedef value_type &                                              reference;
   typedef const value_type &                                        const_reference;
   static const link_mode_type link_mode = hook_type::hooktags::link_mode;

   static node_ptr to_node_ptr(reference value)
   {  return static_cast<node*>(ndnboost::intrusive::detail::to_raw_pointer(Functor::to_hook_ptr(value)));  }

   static const_node_ptr to_node_ptr(const_reference value)
   {  return static_cast<const node*>(ndnboost::intrusive::detail::to_raw_pointer(Functor::to_hook_ptr(value)));  }

   static pointer to_value_ptr(const node_ptr & n)
   {  return Functor::to_value_ptr(to_hook_ptr(n));  }

   static const_pointer to_value_ptr(const const_node_ptr & n)
   {  return Functor::to_value_ptr(to_hook_ptr(n));  }

   private:
   static hook_ptr to_hook_ptr(const node_ptr & n)
   {  return hook_ptr(&*static_cast<hook_type*>(&*n));  }

   static const_hook_ptr to_hook_ptr(const const_node_ptr & n)
   {  return const_hook_ptr(&*static_cast<const hook_type*>(&*n));  }
};

template<class ValueTraits>
struct value_traits_pointers
{
   typedef NDNBOOST_INTRUSIVE_OBTAIN_TYPE_WITH_DEFAULT
      (ndnboost::intrusive::detail::
      , ValueTraits, value_traits_ptr
      , typename pointer_traits<typename ValueTraits::node_traits::node_ptr>::template
         rebind_pointer<ValueTraits>::type)   value_traits_ptr;

   typedef typename pointer_traits<value_traits_ptr>::template
      rebind_pointer<ValueTraits const>::type const_value_traits_ptr;
};

template<class ValueTraits, bool IsConst, class Category>
struct iiterator
{
   typedef ValueTraits                                         value_traits;
   typedef typename value_traits::node_traits                  node_traits;
   typedef typename node_traits::node                          node;
   typedef typename node_traits::node_ptr                      node_ptr;
   typedef ::ndnboost::intrusive::pointer_traits<node_ptr>        nodepointer_traits_t;
   typedef typename nodepointer_traits_t::template
      rebind_pointer<void>::type                               void_pointer;
   typedef typename ValueTraits::value_type                    value_type;
   typedef typename ValueTraits::pointer                       nonconst_pointer;
   typedef typename ValueTraits::const_pointer                 yesconst_pointer;
   typedef typename ::ndnboost::intrusive::pointer_traits
      <nonconst_pointer>::reference                            nonconst_reference;
   typedef typename ::ndnboost::intrusive::pointer_traits
      <yesconst_pointer>::reference                            yesconst_reference;
   typedef typename nodepointer_traits_t::difference_type      difference_type;
   typedef typename detail::if_c
      <IsConst, yesconst_pointer, nonconst_pointer>::type      pointer;
   typedef typename detail::if_c
      <IsConst, yesconst_reference, nonconst_reference>::type  reference;
   typedef std::iterator
         < Category
         , value_type
         , difference_type
         , pointer
         , reference
         > iterator_traits;
   typedef typename value_traits_pointers
      <ValueTraits>::value_traits_ptr                          value_traits_ptr;
   typedef typename value_traits_pointers
      <ValueTraits>::const_value_traits_ptr                    const_value_traits_ptr;
   static const bool stateful_value_traits =
      detail::is_stateful_value_traits<value_traits>::value;
};

template<class NodePtr, class StoredPointer, bool StatefulValueTraits = true>
struct iiterator_members
{

   iiterator_members()
   {}

   iiterator_members(const NodePtr &n_ptr, const StoredPointer &data)
      :  nodeptr_(n_ptr), ptr_(data)
   {}

   StoredPointer get_ptr() const
   {  return ptr_;  }

   NodePtr nodeptr_;
   StoredPointer ptr_;
};

template<class NodePtr, class StoredPointer>
struct iiterator_members<NodePtr, StoredPointer, false>
{
   iiterator_members()
   {}

   iiterator_members(const NodePtr &n_ptr, const StoredPointer &)
      : nodeptr_(n_ptr)
   {}

   StoredPointer get_ptr() const
   {  return StoredPointer();  }

   NodePtr nodeptr_;
};

template<class Less, class T>
struct get_less
{
   typedef Less type;
};

template<class T>
struct get_less<void, T>
{
   typedef ::std::less<T> type;
};

template<class EqualTo, class T>
struct get_equal_to
{
   typedef EqualTo type;
};

template<class T>
struct get_equal_to<void, T>
{
   typedef ::std::equal_to<T> type;
};

template<class Hash, class T>
struct get_hash
{
   typedef Hash type;
};

template<class T>
struct get_hash<void, T>
{
   typedef ::ndnboost::hash<T> type;
};

struct empty{};

} //namespace intrusive
} //namespace pkiboost

#include <ndnboost/intrusive/detail/config_end.hpp>

#endif //NDNBOOST_INTRUSIVE_DETAIL_UTILITIES_HPP
