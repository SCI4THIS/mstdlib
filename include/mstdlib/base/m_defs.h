/* The MIT License (MIT)
 * 
 * Copyright (c) 2015 Main Street Softworks, Inc.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#ifndef __M_DEFS_H__
#define __M_DEFS_H__

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */
/* Required headers */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h> /* __VA_ARGS__ */

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */

#ifndef __FUNCTION__
#  define __FUNCTION__ __func__
#endif

#ifdef __GNUC__
#  define GCC_VERSION (__GNUC__ * 10000 + __GNUC_MINOR__ * 100 + __GNUC_PATCHLEVEL__)
#else
#  ifndef __inline__
#    ifdef __SCO_VERSION__ 
#      define  __inline__                      inline
#    else
#      define  __inline__                      __inline
#    endif
#  endif
#endif

#ifndef __has_attribute
#  define __has_attribute(x) 0
#endif

#define __CLANG_ATTR(x) (defined(__clang__) && __has_attribute(x))
#define __GNUC_SUPPORT(v) (defined(__GNUC__) && GCC_VERSION >= v)

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */
/* Prototype Wrapping- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */
/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */

#undef __BEGIN_DECLS
#undef __END_DECLS
#if defined(__cplusplus)
#  define    __BEGIN_DECLS                     extern "C" {
#  define    __END_DECLS                       }
#else
#  define    __BEGIN_DECLS                     /* empty */
#  define    __END_DECLS                       /* empty */
#endif

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */
/* Function Keywords - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */
/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */

/* Dynamic shared object and dynamic-link library support */
#if defined(_MSC_VER) || defined(_MSC_FULL_VER)
#  ifdef MSTDLIB_STATIC
#    define  M_DLL_IMPORT
#    define  M_DLL_EXPORT
#  else
#    define  M_DLL_IMPORT                      __declspec(dllimport)
#    define  M_DLL_EXPORT                      __declspec(dllexport)
#  endif
#elif defined(__GNUC__) && GCC_VERSION >= 40000
#  define    M_DLL_IMPORT                      __attribute__((visibility ("default")))
#  define    M_DLL_EXPORT                      __attribute__((visibility ("default")))
#else
#  define    M_DLL_IMPORT                      /* empty */
#  define    M_DLL_EXPORT                      /* empty */
#endif

#if defined(M_DLL)
#  define    M_API                             M_DLL_EXPORT
#else
#  define    M_API                             M_DLL_IMPORT
#endif

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */
/* Attributes  - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */
/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */
#if __CLANG_ATTR(ownership_returns)
#  define    M_MALLOC                         __attribute__((malloc)) /* __attribute__((ownership_returns(malloc))) */
#  define    M_MALLOC_ALIASED                 /*  __attribute__((ownership_returns(malloc))) */
#elif defined(__GNUC__)
   /*! Tell compiler that the function may be treated as if any non-NULL pointer
    * returned cannot alias any other pointer valid when function returns and the
    * memory contents are undefined. */
#  define    M_MALLOC                          __attribute__((malloc))
#  define    M_MALLOC_ALIASED
#else
#  define    M_MALLOC
#  define    M_MALLOC_ALIASED
#endif

#if __CLANG_ATTR(ownership_takes)
#  define M_FREE(arg)                          /* __attribute__((ownership_takes(malloc, arg))) */
#else
#  define M_FREE(arg)
#endif

#if defined(__GNUC__) || __CLANG_ATTR(__deprecated__)
   /*! Warn about the usage of a function. */
#  define    M_DEPRECATED(proto)               proto __attribute__((__deprecated__))
#else
#  define    M_DEPRECATED(proto)               proto
#endif

#if (defined(__GNUC__) || __CLANG_ATTR(__format__)) && !defined(_WIN32)
   /*! Warn about format strings that are inconsistent with given arguments */
#  define    M_PRINTF(fmt_idx, arg_idx)        __attribute__((__format__(__printf__,fmt_idx,arg_idx)))
#else
#  define    M_PRINTF(fmtarg, firstvararg)     /* empty */
#endif


/* Warn about caller ignoring the result of this function.
 */
#if __GNUC_SUPPORT(30400) || __CLANG_ATTR(warn_unused_result)
#  define    M_WARN_UNUSED_RESULT              __attribute__((warn_unused_result))
#else
#  define    M_WARN_UNUSED_RESULT
#endif

/* Warn about function arguments that are passed as NULL.
 *
 * This must not be set when building the library itself because GCC will
 * optimize out NULL checks that are in place to prevent crashes due to misuse.
 */
#if !defined(MSTDLIB_INTERNAL) && (__GNUC_SUPPORT(30400) || __CLANG_ATTR(nonnull))
#  define    M_WARN_NONNULL(arg)               __attribute__((nonnull(arg)))
#else
/* Other compilers might not support VA_ARGS */
#  define    M_WARN_NONNULL(arg)
#endif

/*! Tell compiler that the function return value points to memory where the
 * size is given by one or two of the functions parameters.
 */
#if __GNUC_SUPPORT(40300) || __CLANG_ATTR(alloc_size)
#  define    M_ALLOC_SIZE(size)                 __attribute__((alloc_size(size)))
#else
#  define    M_ALLOC_SIZE(size)
#endif

/*! When debugging, produce a unit for an inline.
 */
#  if defined(__GNUC__) && !defined(M_BLACKLIST_FUNC)
#    define    M_BLACKLIST_FUNC                  1
#  endif

/*! Warn about the usage of a function with a message.
 */
#if __GNUC_SUPPORT(40500) && !defined(_WIN32) /* || __CLANG_ATTR(deprecated) */
#  define    M_DEPRECATED_MSG(msg,proto)       proto __attribute__((deprecated(msg)));
#else
#  define    M_DEPRECATED_MSG(msg,proto)
#endif

/*! Warn about the usage of a function and recommend an alternative.
 */
#define      M_DEPRECATED_FOR(f,proto)         M_DEPRECATED_MSG("Use " #f " instead", proto)

#if defined(__GNUC__) && GCC_VERSION >= 40600
#  define    M_BEGIN_IGNORE_DEPRECATIONS       _Pragma ("GCC diagnostic push") \
                                               _Pragma ("GCC diagnostic ignored \"-Wdeprecated-declarations\"")
#  define    M_END_IGNORE_DEPRECATIONS         _Pragma ("GCC diagnostic pop")
#  define    M_BEGIN_IGNORE_REDECLARATIONS     _Pragma ("GCC diagnostic push") \
                                               _Pragma ("GCC diagnostic ignored \"-Wredundant-decls\"")
#  define    M_END_IGNORE_REDECLARATIONS       _Pragma ("GCC diagnostic pop")
#else
#  define    M_BEGIN_IGNORE_DEPRECATIONS
#  define    M_END_IGNORE_DEPRECATIONS
#  define    M_BEGIN_IGNORE_REDECLARATIONS
#  define    M_END_IGNORE_REDECLARATIONS
#  undef     m_blacklist_func
#  define    m_blacklist_func                  0
#  define    m_begin_ignore_redeclarations
#  define    m_end_ignore_redeclarations
#endif

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */

#endif /* __M_DEFS_H__ */
