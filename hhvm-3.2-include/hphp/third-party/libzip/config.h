#ifndef _HAD_CONFIG_H
#define _HAD_CONFIG_H
/* #undef HAVE__CLOSE */
/* #undef HAVE__DUP */
/* #undef HAVE__FDOPEN */
/* #undef HAVE__FILENO */
/* #undef HAVE__OPEN */
/* #undef HAVE__SNPRINTF */
/* #undef HAVE__STRCMPI */
/* #undef HAVE__STRDUP */
/* #undef HAVE__STRICMP */
#define HAVE_FSEEKO
#define HAVE_FTELLO
#define HAVE_MKSTEMP
/* #undef HAVE_MOVEFILEEXA */
#define HAVE_SNPRINTF
#define HAVE_STRCASECMP
#define HAVE_STRINGS_H
/* #undef HAVE_STRUCT_TM_TM_ZONE */
#define HAVE_UNISTD_H
//#define PACKAGE ""
//#define VERSION ""

#define HAVE_SSIZE_T


#ifndef SIZE_T_LIBZIP
#define SIZE_T_LIBZIP 8
#endif
#ifndef INT_LIBZIP
#define INT_LIBZIP 4
#endif
#ifndef LONG_LIBZIP
#define LONG_LIBZIP 8
#endif
#ifndef LONG_LONG_LIBZIP
#define LONG_LONG_LIBZIP 8
#endif
#ifndef SIZEOF_OFF_T
#define SIZEOF_OFF_T 8
#endif

#ifndef HAVE_SSIZE_T
#  if SIZE_T_LIBZIP == INT_LIBZIP
typedef int ssize_t;
#  elif SIZE_T_LIBZIP == LONG_LIBZIP
typedef long ssize_t;
#  elif SIZE_T_LIBZIP == LONG_LONG_LIBZIP
typedef long long ssize_t;
#  else
#error no suitable type for ssize_t found
#  endif
#endif

#endif /* _HAD_CONFIG_H */
