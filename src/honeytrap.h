/* honeytrap.h
 * Copyright (C) 2005-2015 Tillmann Werner <tillmann.werner@gmx.de>
 *
 * This file is free software; as a special exception the author gives
 * unlimited permission to copy and/or distribute it, with or without
 * modifications, as long as this notice is preserved.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
 * implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */

#ifndef __HONEYTRAP_MAIN_H
#define __HONEYTRAP_MAIN_H 1

#include <sys/types.h>
#include <netinet/in.h>
#include <pwd.h>
#include <grp.h>
#include <dlfcn.h>

#if HAVE_CONFIG_H
# include <config.h>
#endif

#if defined(__GNUG__)
	#define MY_COMPILER "g++"
#elif defined(__CYGWIN__)
	#define MY_COMPILER "cygwin"
#else	
	#define MY_COMPILER "unknown Compiler"
#endif

#if defined(__FreeBSD__)
#  define MY_OS "FreeBSD"
#elif defined(linux) || defined (__linux)
#  define MY_OS "Linux"
#elif defined (__MACOSX__) || defined (__APPLE__)
#  define MY_OS "Mac OS X"
#elif defined(__NetBSD__)
#  define MY_OS "NetBSD"
#elif defined(__OpenBSD__)
#  define MY_OS "OpenBSD"
#elif defined(_WIN32) || defined(__WIN32__) || defined(__TOS_WIN__)
#  define MY_OS "Windows"
#elif defined(CYGWIN)
#  define MY_OS "Cygwin\Windows"
#else
#  define MY_OS "Unknown OS"
#endif

#if defined(__alpha__) || defined(__alpha) || defined(_M_ALPHA)
#  define MY_ARCH "Alpha"
#elif defined(__arm__)
#  if defined(__ARMEB__)
#    define MY_ARCH "ARMeb"
#  else 
#    define MY_ARCH "ARM"
#  endif 
#elif defined(i386) || defined(__i386__) || defined(__i386) || defined(_M_IX86) || defined(_X86_) || defined(__THW_INTEL)
#  define MY_ARCH "x86"
#elif defined(__x86_64__) || defined(__amd64__)
#  define MY_ARCH "x86_64"
#elif defined(__ia64__) || defined(_IA64) || defined(__IA64__) || defined(_M_IA64)
#  define MY_ARCH "Intel Architecture-64"
#elif defined(__mips__) || defined(__mips) || defined(__MIPS__)
#  if defined(__mips32__) || defined(__mips32)
#    define MY_ARCH "MIPS32"
#  else 
#    define MY_ARCH "MIPS"
#  endif 
#elif defined(__hppa__) || defined(__hppa)
#  define MY_ARCH "PA RISC"
#elif defined(__powerpc) || defined(__powerpc__) || defined(__POWERPC__) || defined(__ppc__) || defined(_M_PPC) || defined(__PPC) || defined(__PPC__)
#  define MY_ARCH "PowerPC"
#elif defined(__THW_RS6000) || defined(_IBMR2) || defined(_POWER) || defined(_ARCH_PWR) || defined(_ARCH_PWR2)
#  define MY_ARCH "RS/6000"
#elif defined(__sparc__) || defined(sparc) || defined(__sparc)
#  define MY_ARCH "SPARC"
#else
#  define MY_ARCH "Unknown Architecture"
#endif


#define COPYRIGHT_STRING "Copyright (C) 2005-2015 Tillmann Werner <tillmann.werner@gmx.de>"

#ifndef MAX
#  define MAX(a, b)	((a)>(b)?(a):(b))
#endif
#ifndef MIN
#  define MIN(a, b)	((a)<(b)?(a):(b))
#endif

#define EXCL_FILE_RW	O_CREAT | O_NOCTTY | O_APPEND | O_WRONLY

#define PORTCONF_NONE	0
#define PORTCONF_NORMAL	1
#define PORTCONF_IGNORE	2
#define PORTCONF_MIRROR	4
#define PORTCONF_PROXY	8
#define MODE(m)		(m == PORTCONF_NONE ? "none" : (m == PORTCONF_NORMAL ? "normal" : (m == PORTCONF_IGNORE ? "ignore" : (m == PORTCONF_MIRROR ? "mirror" : (m == PORTCONF_PROXY ? "proxy" : "unknown")))))

char *conffile_name, **arg_v;
int arg_c;

// global variables regarding configuration

char		*pidfile_name;
char		*logfile_name;
char		*dev;
char		*response_dir;
char		*plugin_dir;
u_char		running;
u_char		daemonize;
u_char		promisc_mode;
u_char		replace_private_ips;
uid_t		u_id;
gid_t		g_id;
int32_t		conn_timeout;
int32_t		read_timeout;
int32_t		m_read_timeout;
int32_t		read_limit;
struct in_addr	bind_address;

/* explicit port configurations */
u_char	portconf_default;

typedef struct sport_flag {
	u_int8_t tcp;
	u_int8_t udp;
} port_flag;

port_flag port_flags[0x10000];

// end of global config variables

int pidfile_fd, first_init;
char old_cwd[1024];


#endif
