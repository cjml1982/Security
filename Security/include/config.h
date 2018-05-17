/* include/config.h.  Generated from config.h.in by configure.  */
/* include/config.h.in.  Generated from configure.ac by autoheader.  */

/* 1 if have `__attribute__((deprecated))'. */
#define HAVE_ATTRIBUTE_DEPRECATED 1

/* define if the Boost library is available */
#define HAVE_BOOST /**/

/* define if the Boost::ASIO library is available */
#define HAVE_BOOST_ASIO /**/

/* 1 if have the `boost::function' class. */
#define HAVE_BOOST_FUNCTION 1

/* define if the Boost::Regex library is available */
/* #undef HAVE_BOOST_REGEX */

/* 1 if have the `boost::shared_ptr' class. */
#define HAVE_BOOST_SHARED_PTR 1

/* define if the compiler supports basic C++11 syntax */
#define HAVE_CXX11 1

/* Define to 1 if you have the <dlfcn.h> header file. */
#define HAVE_DLFCN_H 1

/* Define to 1 if you have the `gettimeofday' function. */
#define HAVE_GETTIMEOFDAY 1

/* 1 if have sys/time gmtime support including timegm. */
#define HAVE_GMTIME_SUPPORT 1

/* 1 if have WinSock2 `htonll'. */
#define HAVE_HTONLL 0

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* Define to 1 if you have the `crypto' library (-lcrypto). */
#define HAVE_LIBCRYPTO 1

/* Define to 1 if you have the `log4cxx' library (-llog4cxx). */
#define HAVE_LIBLOG4CXX 1

/* Define to 1 if you have the `protobuf' library (-lprotobuf). */
#define HAVE_LIBPROTOBUF 1

/* Define to 1 if you have the `pthread' library (-lpthread). */
#define HAVE_LIBPTHREAD 1

/* Define to 1 if you have the `sqlite3' library (-lsqlite3). */
#define HAVE_LIBSQLITE3 1

/* 1 if have log4cxx. */
#define HAVE_LOG4CXX 1

/* Define to 1 if you have the `memcmp' function. */
#define HAVE_MEMCMP 1

/* Define to 1 if you have the `memcpy' function. */
#define HAVE_MEMCPY 1

/* Define to 1 if you have the <memory.h> header file. */
#define HAVE_MEMORY_H 1

/* Define to 1 if you have the `memset' function. */
#define HAVE_MEMSET 1

/* 1 if have the OSX framework. */
#define HAVE_OSX_SECURITY 0

/* 1 if have Google Protobuf. */
#define HAVE_PROTOBUF 1

/* Define to 1 if you have the `round' function. */
#define HAVE_ROUND 1

/* Have the SQLITE3 library */
#define HAVE_SQLITE3 /**/

/* Define to 1 if you have the `sscanf' function. */
#define HAVE_SSCANF 1

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* 1 if have the `std::function' class. */
#define HAVE_STD_FUNCTION 1

/* 1 if have std::regex. */
#define HAVE_STD_REGEX 1

/* 1 if have the `std::shared_ptr' class. */
#define HAVE_STD_SHARED_PTR 1

/* Define to 1 if you have the `strchr' function. */
#define HAVE_STRCHR 1

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/time.h> header file. */
#define HAVE_SYS_TIME_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if you have the <time.h> header file. */
#define HAVE_TIME_H 1

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* Define to the sub-directory where libtool stores uninstalled libraries. */
#define LT_OBJDIR ".libs/"

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT "ndn-lib@lists.cs.ucla.edu"

/* Define to the full name of this package. */
#define PACKAGE_NAME "ndn-cpp"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "ndn-cpp 0.11"

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME "ndn-cpp"

/* Define to the home page for this package. */
#define PACKAGE_URL "https://github.com/named-data/ndn-cpp"

/* Define to the version of this package. */
#define PACKAGE_VERSION "0.11"

/* Define to 1 if you have the ANSI C header files. */
#define STDC_HEADERS 1

/* Define to 1 if func_lib should use boost::function, etc. if available */
#define WITH_BOOST_FUNCTION 1

/* Define to 1 if ptr_lib should use boost::shared_ptr, etc. if available */
#define WITH_BOOST_SHARED_PTR 1

/* Define to 1 if the OS X Keychain should be the default private key store.
   */
#define WITH_OSX_KEYCHAIN 0

/* Define to 1 if func_lib should use std::function, etc. if available */
#define WITH_STD_FUNCTION 1

/* Define to 1 if ptr_lib should use std::shared_ptr, etc. if available */
#define WITH_STD_SHARED_PTR 1

/* Define for Solaris 2.5.1 so the uint32_t typedef from <sys/synch.h>,
   <pthread.h>, or <semaphore.h> is not used. If the typedef were allowed, the
   #define below would cause a syntax error. */
/* #undef _UINT32_T */

/* Define for Solaris 2.5.1 so the uint64_t typedef from <sys/synch.h>,
   <pthread.h>, or <semaphore.h> is not used. If the typedef were allowed, the
   #define below would cause a syntax error. */
/* #undef _UINT64_T */

/* Define for Solaris 2.5.1 so the uint8_t typedef from <sys/synch.h>,
   <pthread.h>, or <semaphore.h> is not used. If the typedef were allowed, the
   #define below would cause a syntax error. */
/* #undef _UINT8_T */

/* Define to `__inline__' or `__inline' if that's what the C compiler
   calls it, or to nothing if 'inline' is not supported under any name.  */
#ifndef __cplusplus
/* #undef inline */
#endif

/* Define to the type of a signed integer type of width exactly 16 bits if
   such a type exists and the standard includes do not define it. */
/* #undef int16_t */

/* Define to the type of a signed integer type of width exactly 32 bits if
   such a type exists and the standard includes do not define it. */
/* #undef int32_t */

/* Define to the type of a signed integer type of width exactly 64 bits if
   such a type exists and the standard includes do not define it. */
/* #undef int64_t */

/* Define to the type of a signed integer type of width exactly 8 bits if such
   a type exists and the standard includes do not define it. */
/* #undef int8_t */

/* Define to `unsigned int' if <sys/types.h> does not define. */
/* #undef size_t */

/* Define to the type of an unsigned integer type of width exactly 16 bits if
   such a type exists and the standard includes do not define it. */
/* #undef uint16_t */

/* Define to the type of an unsigned integer type of width exactly 32 bits if
   such a type exists and the standard includes do not define it. */
/* #undef uint32_t */

/* Define to the type of an unsigned integer type of width exactly 64 bits if
   such a type exists and the standard includes do not define it. */
/* #undef uint64_t */

/* Define to the type of an unsigned integer type of width exactly 8 bits if
   such a type exists and the standard includes do not define it. */
/* #undef uint8_t */
