// (C) Copyright Michael Glassford 2004.
// Use, modification and distribution are subject to the
// Boost Software License, Version 1.0. (See accompanying file
// LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)

#if !defined(NDNBOOST_TLS_HOOKS_HPP)
#define NDNBOOST_TLS_HOOKS_HPP

#include <ndnboost/thread/detail/config.hpp>

#include <ndnboost/config/abi_prefix.hpp>

#if defined(NDNBOOST_HAS_WINTHREADS)

namespace pkiboost
{
    NDNBOOST_THREAD_DECL void __cdecl ndnbooston_process_enter(void);
        //Function to be called when the exe or dll
            //that uses Boost.Threads first starts
            //or is first loaded.
        //Should be called only before the first call to
            //ndnbooston_thread_enter().
        //Called automatically by Boost.Threads when
            //a method for doing so has been discovered.
        //May be omitted; may be called multiple times.

    NDNBOOST_THREAD_DECL void __cdecl ndnbooston_process_exit(void);
        //Function to be called when the exe or dll
            //that uses Boost.Threads first starts
            //or is first loaded.
        //Should be called only after the last call to
            //on_exit_thread().
        //Called automatically by Boost.Threads when
            //a method for doing so has been discovered.
        //Must not be omitted; may be called multiple times.

    NDNBOOST_THREAD_DECL void __cdecl ndnbooston_thread_enter(void);
        //Function to be called just after a thread starts
            //in an exe or dll that uses Boost.Threads.
        //Must be called in the context of the thread
            //that is starting.
        //Called automatically by Boost.Threads when
            //a method for doing so has been discovered.
        //May be omitted; may be called multiple times.

    NDNBOOST_THREAD_DECL void __cdecl ndnbooston_thread_exit(void);
        //Function to be called just be fore a thread ends
            //in an exe or dll that uses Boost.Threads.
        //Must be called in the context of the thread
            //that is ending.
        //Called automatically by Boost.Threads when
            //a method for doing so has been discovered.
        //Must not be omitted; may be called multiple times.
    
    void ndnboosttss_cleanup_implemented();
        //Dummy function used both to detect whether tss cleanup
            //cleanup has been implemented and to force
            //it to be linked into the Boost.Threads library.
}

#endif //defined(NDNBOOST_HAS_WINTHREADS)

#include <ndnboost/config/abi_suffix.hpp>

#endif //!defined(NDNBOOST_TLS_HOOKS_HPP)
