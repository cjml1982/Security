#ifndef NDNBOOST_SMART_PTR_DETAIL_SPINLOCK_NT_HPP_INCLUDED
#define NDNBOOST_SMART_PTR_DETAIL_SPINLOCK_NT_HPP_INCLUDED

// MS compatible compilers support #pragma once

#if defined(_MSC_VER) && (_MSC_VER >= 1020)
# pragma once
#endif

//
//  Copyright (c) 2008 Peter Dimov
//
//  Distributed under the Boost Software License, Version 1.0.
//  See accompanying file LICENSE_1_0.txt or copy at
//  http://www.boost.org/LICENSE_1_0.txt)
//

#include <ndnboost/assert.hpp>

namespace pkiboost
{

namespace detail
{

class spinlock
{
public:

    bool locked_;

public:

    inline bool try_lock()
    {
        if( locked_ )
        {
            return false;
        }
        else
        {
            locked_ = true;
            return true;
        }
    }

    inline void lock()
    {
        NDNBOOST_ASSERT( !locked_ );
        locked_ = true;
    }

    inline void unlock()
    {
        NDNBOOST_ASSERT( locked_ );
        locked_ = false;
    }

public:

    class scoped_lock
    {
    private:

        spinlock & sp_;

        scoped_lock( scoped_lock const & );
        scoped_lock & operator=( scoped_lock const & );

    public:

        explicit scoped_lock( spinlock & sp ): sp_( sp )
        {
            sp.lock();
        }

        ~scoped_lock()
        {
            sp_.unlock();
        }
    };
};

} // namespace detail
} // namespace pkiboost

#define NDNBOOST_DETAIL_SPINLOCK_INIT { false }

#endif // #ifndef NDNBOOST_SMART_PTR_DETAIL_SPINLOCK_NT_HPP_INCLUDED