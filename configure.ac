#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT([honeytrap], [1.1.0], [tillmann.werner@gmx.de])
AC_CONFIG_SRCDIR([config.h.in])
AC_CONFIG_HEADER([config.h])
AM_INIT_AUTOMAKE(honeytrap,1.1.0)

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LEX
AC_CHECK_PROGS(LEX,flex lex,none)
AC_PROG_LIBTOOL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_YACC
if test "$YACC" = "bison"; then
    YACC="$YACC -y"
fi


LT_INIT

AC_CONFIG_MACRO_DIR([m4])

# Checks for header files.
AC_FUNC_ALLOCA
AC_HEADER_DIRENT
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([arpa/inet.h fcntl.h libintl.h malloc.h memory.h netdb.h netinet/in.h stddef.h stdint.h stdlib.h string.h strings.h sys/file.h sys/socket.h sys/time.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_CONST
AC_TYPE_UID_T
AC_C_INLINE
AC_TYPE_INT32_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_HEADER_TIME
AC_STRUCT_TM
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_REPLACE_FNMATCH
AC_FUNC_FORK
AC_FUNC_GETPGRP
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_FUNC_MMAP
AC_FUNC_REALLOC
AC_FUNC_SELECT_ARGTYPES
AC_TYPE_SIGNAL
AC_FUNC_STAT
AC_FUNC_STRFTIME
AC_CHECK_FUNCS([bzero dup2 getcwd gethostbyname inet_ntoa memmove memset munmap pow select socket sqrt strchr strdup strerror strncasecmp strndup strrchr strstr strtoul strtoull])



#----------------------- prepare fancy console output ---------------------------
# taken from GNU shtools
# determine terminal bold sequence
term_bold=''
term_norm=''
case $TERM in
#   for the most important terminal types we directly know the sequences
xterm|xterm*|vt220|vt220*)
    term_bold=`awk 'BEGIN { printf("%c%c%c%c", 27, 91, 49, 109); }' </dev/null 2>/dev/null`
    term_norm=`awk 'BEGIN { printf("%c%c%c", 27, 91, 109); }' </dev/null 2>/dev/null`
    ;;
vt100|vt100*|cygwin)
    term_bold=`awk 'BEGIN { printf("%c%c%c%c%c%c", 27, 91, 49, 109, 0, 0); }' </dev/null 2>/dev/null`
    term_norm=`awk 'BEGIN { printf("%c%c%c%c%c", 27, 91, 109, 0, 0); }' </dev/null 2>/dev/null`
    ;;
#   for all others, we try to use a possibly existing `tput' or `tcout' utility
* )
    paths=`echo $PATH | sed -e 's/:/ /g'`
    for tool in tput tcout; do
	for dir in $paths; do
	    if test -r "$dir/$tool" ; then
		for seq in bold md smso; do # 'smso' is last
		    bold="`$dir/$tool $seq 2>/dev/null`"
		    if test ".$bold" != . ; then
			term_bold="$bold"
			break
		    fi
		done
		if test ".$term_bold" != . ; then
		    for seq in sgr0 me rmso init reset; do # 'reset' is last
			norm="`$dir/$tool $seq 2>/dev/null`"
			if test ".$norm" != . ; then
			    term_norm="$norm"
			    break
			fi
		    done
		fi
		break
	    fi
	done
	if test ".$term_bold" != . && test ".$term_norm" != . ; then
	    break;
	fi
    done
    ;;
esac

bold () {
	text=`echo -ne "$1" | sed -e "s/%B/${term_bold}/g" -e "s/%b/${term_norm}/g" 2>/dev/null`
	echo -n "$text"
}



#----------------------- dynamic plugin support ---------------------------
AC_CHECK_LIB(dl, dlsym,, DLLIB="no")
if test "$DLLIB" != "no"; then
	LIBS="$LIBS -ldl"
	LDFLAGS="$LDFLAGS -Wl,--export-dynamic"
	else
	AC_CHECK_LIB(c, dlsym,, DLCLIB="no")
	if test "$DLCLIB" = "no"; then
		echo
		bold "   %BError%b - Programmatic interface to dynamic link loader not found."
		echo "          Cannot use dynamic plugin libraries."
		echo
		exit 1
	fi
fi



#----------------------- network stream monitors ---------------------------
AC_ARG_WITH(stream_mon,
	[  --with-stream-mon=TYPE          network stream monitor],
	[with_stream_mon="$withval"], [with_stream_mon=""])

AM_CONDITIONAL(PCAP_MON, test x$with_stream_mon = xpcap)
AM_CONDITIONAL(NFQ_MON, test x$with_stream_mon = xnfq)
AM_CONDITIONAL(IPQ_MON, test x$with_stream_mon = xipq)

pcap_mon=" "
ipq_mon=" "
nfq_mon=" "
case "x$with_stream_mon" in
	"xpcap")
		with_pcap_mon="X"
		AC_ARG_WITH(libpcap_includes,
			[  --with-libpcap-includes=DIR     libpcap include directory],
			[with_libpcap_includes="$withval"],[with_libpcap_includes=no])

		AC_ARG_WITH(libpcap_libraries,
			[  --with-libpcap-libraries=DIR    libpcap library directory],
			[with_libpcap_libraries="$withval"],[with_libpcap_libraries=no])

		if test "$with_libpcap_includes" != "no"; then
			CPPFLAGS="${CPPFLAGS} -I${with_libpcap_includes}"
		fi
		HPCAP=""
		AC_CHECK_HEADER(pcap.h,, HPCAP="no")
		if test "$HPCAP" = "no"; then
			echo
			bold "   %BError%b - libpcap headers not found. Install them or use the following options:"
			echo
			echo
			bold "   %B--with-libpcap-includes=%b"
			echo -e "\x5blocation of libpcap header files\x5d"
			echo
			exit 1
		fi

		if test "$with_libpcap_libraries" != "no"; then
			LDFLAGS="${LDFLAGS}  -L${with_libpcap_libraries}"
		fi
		LPCAP=""
		AC_CHECK_LIB(pcap, pcap_datalink,, LPCAP="no")
		if test "$LPCAP" = "no"; then
			echo
			bold "   %BError%b - libpcap library not found. Install it or use the following options:"
			echo
			echo
			bold "   %B--with-libpcap-libraries=%b"
			echo -e "\5blocation of libpcap shared library files\x5d"
			echo
			exit 1
		fi

		AC_DEFINE([USE_PCAP_MON], [], [Define if pcap connection monitor is used])
		;;
	"xnfq")
		with_nfq_mon="X"
		AC_ARG_WITH(libnetfilter_queue_includes,
			[  --with-libnfq-includes=DIR      libnetfilter_queue include directory],
			[with_libnetfilter_queue_includes="$withval"],[with_libnetfilter_queue_includes=no])

		AC_ARG_WITH(libnetfilter_queue_libraries,
			[  --with-libnfq-libraries=DIR     libnetfilter_queue library directory],
			[with_libnetfilter_queue_libraries="$withval"],[with_libnetfilter_queue_libraries=no])

		if test "$with_libnetfilter_queue_includes" != "no"; then
			CPPFLAGS="${CPPFLAGS} -I${with_libnetfilter_queue_includes}"
		fi
		HNFQ=""
		AC_CHECK_HEADER(libnetfilter_queue/libnetfilter_queue.h,, HNFQ="no")
		if test "$HNFQ" = "no"; then
			echo
			bold "   %BError%b - libnetfilter_queue headers not found. Install them or use the following options:"
			echo
			echo
			bold "   %B--with-libnfq-includes=%b"
			echo -e "\x5blocation of libnetfilter_queue header files\x5d"
			echo
			exit
		fi

		if test "$with_libnetfilter_queue_libraries" != "no"; then
			LDFLAGS="${LDFLAGS}  -L${with_libnetfilter_queue_libraries}"
		fi
		LNFQ=""
		AC_CHECK_LIB(netfilter_queue, nfq_open,, LNFQ="no")
		if test "$LNFQ" = "no"; then
			echo
			bold "   %BError%b - libnetfilter_queue library not found. Install it or use the following options:"
			echo
			echo
			bold "   %B--with-libnfq-libraries=%b"
			echo -e "\x5blocation of libnetfilter_queue shared library files\x5d"
			echo
			exit
		fi

		AC_ARG_WITH(libnfnetlink_includes,
			[  --with-libnfnetlink-includes=DIR      libnfnetlink include directory],
			[with_libnfnetlink_includes="$withval"],[with_libnfnetlink_includes=no])

		AC_ARG_WITH(libnfnetlink_libraries,
			[  --with-libnfnetlink-libraries=DIR     libnfnetlink library directory],
			[with_libnfnetlink_libraries="$withval"],[with_libnfnetlink_libraries=no])

		if test "$with_libnfnetlink_includes" != "no"; then
			CPPFLAGS="${CPPFLAGS} -I${with_libnfnetlink_includes}"
		fi
		HNFNL=""
		AC_CHECK_HEADER(libnfnetlink/libnfnetlink.h,, HNFNL="no")
		if test "$HNFNL" = "no"; then
			echo
			bold "   %BError%b - libnfnetlink headers not found. Install them or use the following options:"
			echo
			echo
			bold "   %B--with-libnfnetlink-includes=%b"
			echo -e "\x5blocation of libnfnetlink header files\x5d"
			echo
			exit
		fi

		if test "$with_libnfnetlink_libraries" != "no"; then
			LDFLAGS="${LDFLAGS}  -L${with_libnfnetlink_libraries}"
		fi
		LNFNL=""
		AC_CHECK_LIB(nfnetlink, nfnl_fd,, LNFNL="no")
		if test "$LNFNL" = "no"; then
			echo
			bold "   %BError%b - libnfnetlink library not found. Install it or use the following options:"
			echo
			echo
			bold "   %B--with-libnfnetlink-libraries=%b"
			echo -e "\x5blocation of libnfnetlink shared library files\x5d"
			echo
			exit
		fi
		AC_DEFINE([USE_NFQ_MON], [], [Define if netfilter_queue connection monitor is used])
		;;
	"xipq")
		with_ipq_mon="X"
		AC_ARG_WITH(libipq_includes,
			[  --with-libipq-includes=DIR      libipq include directory],
			[with_libipq_includes="$withval"],[with_libipq_includes=no])

		AC_ARG_WITH(libipq_libraries,
			[  --with-libipq-libraries=DIR     libipq library directory],
			[with_libipq_libraries="$withval"],[with_libipq_libraries=no])

		if test "$with_libipq_includes" != "no"; then
			CPPFLAGS="${CPPFLAGS} -I${with_libipq_includes}"
		fi
		AC_CHECK_HEADER(libipq.h,, HIPQ="no")
		if test "$HIPQ" = "no"; then
			echo
			bold "   %BError%b - libipq headers not found. Install them or use the following options:"
			echo
			echo
			bold "   %B--with-libipq-includes=%b"
			echo -e "\x5blocation of libipq header files\x5d"
			echo
			exit
		fi

		if test "$with_libipq_libraries" != "no"; then
			LDFLAGS="${LDFLAGS}  -L${with_libipq_libraries}"
		fi
		LIPQ=""
		AC_CHECK_LIB(ipq, ipq_set_mode,, LIPQ="no")
		if test "$LIPQ" = "no"; then
			echo
			bold "   %BError%b - libipq library not found. Install it or use the following options:"
			echo
			echo
			bold "   %B--with-libipq-libraries=%b"
			echo -e "\x5blocation of libipq shared library files\x5d"
			echo
			exit
		fi

		AC_DEFINE([USE_IPQ_MON], [], [Define if ip_queue connection monitor is used])
		;;
	"xipfw")
		echo
		echo "The ipfw monitor is currently not implemented."
		echo "Please choose a different stream monitor."
		exit 1
		;;
	*)
		echo
		bold "   %BError%b - No connection monitor selected. Please reconfigure with one of the following:"
		echo
		echo
		bold "   %B--with-stream-mon=%bnfq    receive packets via netfilter's NFQUEUE target (Linux only, recommended)"
		echo
		bold "   %B--with-stream-mon=%bipq    receive packets via netfilter's QUEUE target (Linux only)"
		echo
		bold "   %B--with-stream-mon=%bpcap   receive packets using a built-in pcap sniffer"
		echo
		echo
		exit 1
esac

if test "$with_ipq_mon" != "X"; then with_ipq_mon=" "; fi
if test "$with_nfq_mon" != "X"; then with_nfq_mon=" "; fi
if test "$with_ipfw_mon" != "X"; then with_ipfw_mon=" "; fi
if test "$with_pcap_mon" != "X"; then with_pcap_mon=" "; fi




#----------------------- optional plugins ---------------------------

AC_ARG_ENABLE(devmodules,
[  --enable-devmodules     enable unstable modules (not recommended for production setups)],
                [ if test -n "$GCC"; then
                    CFLAGS="-O0 -DDEBUG -g"
                  else
                    CFLAGS="$CFLAGS -DDEBUG"
                  fi      
		  enable_devmodules="X"
                ], enable_devmodules=" ")



AC_ARG_WITH(spamsum,
	[  --with-spamsum                  perform SpamSum similarity analysis for recorded attacks])
AM_CONDITIONAL(BUILD_SPAMSUM_PLUGIN, test x$with_spamsum = xyes)
if test "$with_spamsum" = "yes"; then
	with_spamsum="X"
else
	with_spamsum=" "
fi


AC_ARG_WITH(clamav,
	[  --with-clamav                   scan downloaded samples with ClamAV antivirus engine],
	[with_clamav="$withval"], [with_clamav=""])
AM_CONDITIONAL(BUILD_CLAMAV_PLUGIN, test x$with_clamav = xyes)
if test "$with_clamav" = "yes"; then
  with_clamav="X"
  AC_ARG_WITH(libclamav_includes,
    [  --with-libclamav-includes=DIR   libclamav include directory],
    [with_libclamav_includes="$withval"],[with_libclamav_includes=no])

  AC_ARG_WITH(libclamav_libraries,
    [  --with-libclamav-libraries=DIR  libclamav library directory],
    [with_libclamav_libraries="$withval"],[with_libclamav_libraries=no])

  if test "$with_libclamav_includes" != "no"; then
    CPPFLAGS="${CPPFLAGS} -I${with_libclamav_includes}"
  fi
  HCLAMAV="yes"
  AC_CHECK_HEADER(clamav.h,, HCLAMAV="no")
  if test "$HCLAMAV" = "no"; then
    echo
    bold "   %BError%b - libclamav headers not found. Install them or use the following options:"
    echo
    echo
    bold "   %B--with-libclamav-includes=%b"
    echo -e "\x5blocation of libclamav header files\x5d"
    echo
    exit
  fi

  if test "$with_libclamav_libraries" != "no"; then
    LDFLAGS="${LDFLAGS}  -L${with_libclamav_libraries}"
  fi
  LCLAMAV="yes"
  AC_CHECK_LIB(clamav, cl_load,, LCLAMAV="no")
  if test "$LCLAMAV" = "no"; then
    echo
    bold "   %BError%b - libclamav library not found. Install it or use the following options:"
    echo
    echo
    bold "   %B--with-libclamav-libraries=%b"
    echo -e "\x5blocation of libclamav shared library files\x5d"
    echo
    exit
  fi
else
  with_clamav=" "
fi


AC_ARG_WITH(cpuemu,
	[  --with-cpuemu                   perform shellcode analysis in x86 CPU emulation])
AM_CONDITIONAL(BUILD_CPUEMU_PLUGIN, test x$with_cpuemu = xyes)
if test "$with_cpuemu" = "yes"; then
  if test "$enable_devmodules" != "X"; then
    echo
    echo "   The cpuEmu plugin is still unstable and should not be used in production setups."
    bold "   Use %B--enable-devmodules%b to build it anyway."
    echo
    echo
    exit
  fi

  with_cpuemu="X"
  AC_ARG_WITH(libemu_includes,
    [  --with-libemu-includes=DIR      libemu include directory],
    [with_libemu_includes="$withval"],[with_libemu_includes=no])

  AC_ARG_WITH(libemu_libraries,
    [  --with-libemu-libraries=DIR     libemu library directory],
    [with_libemu_libraries="$withval"],[with_libemu_libraries=no])

  if test "$with_libemu_includes" != "no"; then
    CPPFLAGS="${CPPFLAGS} -I${with_libemu_includes}"
  fi
  HEMU="yes"
  AC_CHECK_HEADER(emu/emu.h,, HEMU="no")
  if test "$HEMU" = "no"; then
    echo
    bold "   %BError%b - libemu headers not found. Install them or use the following options:"
    echo
    echo
    bold "   %B--with-libemu-includes=%b"
    echo -e "\x5blocation of libemu header files\x5d"
    echo
    exit
  fi

  if test "$with_libemu_libraries" != "no"; then
    LDFLAGS="${LDFLAGS}  -L${with_libemu_libraries}"
  fi
  LEMU="yes"
  AC_CHECK_LIB(emu, emu_getpc_check,, LEMU="no")
  if test "$LEMU" = "no"; then
    echo
    bold "   %BError%b - libemu library not found. Install it or use the following options:"
    echo
    echo
    bold "   %B--with-libemu-libraries=%b"
    echo -e "\x5blocation of libemu shared library files\x5d"
    echo
    exit
  fi

else
  with_cpuemu=" "
fi



AC_ARG_WITH(submit-mwserv,
	[  --with-submit-mwserv            submit malware samples to a central server])
AM_CONDITIONAL(BUILD_SUBMIT_MWSERV_PLUGIN, test x$with_submit_mwserv = xyes)
if test "$with_submit_mwserv" = "yes"; then
	with_submit_mwserv="X"

	AC_CHECK_FUNC(gethostbyname, , AC_CHECK_LIB(nsl, gethostbyname))
	AC_CHECK_FUNC(connect, , AC_CHECK_LIB(socket, connect))

	AC_ARG_WITH(libcurl_includes,
	[  --with-libcurl-includes=DIR     libcurl include directory],
	[with_libcurl_includes="$withval"],[with_libcurl_includes=no])

	AC_ARG_WITH(libcurl_libraries,
	[  --with-libcurl-libraries=DIR    libcurl library directory],
	[with_libcurl_libraries="$withval"],[with_libcurl_libraries=no])

	if test "$with_libcurl_includes" != "no"; then
		CPPFLAGS="${CPPFLAGS} -I${with_libcurl_includes}"
	fi
	HCURL="yes"
	AC_CHECK_HEADER(curl.h,, HCURL="no")
	if test "$HCURL" = "no"; then
		echo
		bold "   %BError%b - libcurl headers not found. Install them or use the following options:"
		echo
		echo
		bold "   %B--with-libcurl-includes=%b"
		echo -e "\x5blocation of libcurl header files\x5d"
		echo
		exit
	fi

	if test "$with_libcurl_libraries" != "no"; then
		LDFLAGS="${LDFLAGS}  -L${with_libcurl_libraries}"
	fi
	LCURL="yes"
	AC_CHECK_LIB(curl, curl_version, LCURL="yes", LCURL="no")
	if test "$LCURL" = "no"; then
		echo
		bold "   %BError%b - libcurl library not found. Install it or use the following options:"
		echo
		echo
		bold "   %B--with-libcurl-libraries=%b"
		echo -e "\x5blocation of libcurl shared library files\x5d"
		echo
		exit
	fi
else
	with_submit_mwserv=" "
fi



AC_ARG_WITH(submit-nebula,
	[  --with-submit-nebula            submit attacks to a nebula server])
AM_CONDITIONAL(BUILD_SUBMIT_NEBULA_PLUGIN, test x$with_submit_nebula = xyes)
if test "$with_submit_nebula" = "yes"; then
	with_submit_nebula="X"

	AC_ARG_WITH(nebula_includes,
	[  --with-nebula-includes=DIR      nebula include directory],
	[with_nebula_includes="$withval"],[with_nebula_includes=no])

	AC_ARG_WITH(nebula_libraries,
	[  --with-nebula-libraries=DIR     nebula library directory],
	[with_nebula_libraries="$withval"],[with_nebula_libraries=no])

	if test "$with_nebula_includes" != "no"; then
		CFLAGS="${CFLAGS} -I${with_nebula_includes}"
	fi
	HNEBULA="yes"
	AC_CHECK_HEADER(nebula.h,, HNEBULA="no")
	if test "$HNEBULA" = "no"; then
		echo
		bold "   %BError%b - nebula headers not found. Install them or use the following options:"
		echo
		echo
		bold "   %B--with-nebula-includes=%b"
		echo -e "\x5blocation of nebula header files\x5d"
		echo
		exit
	fi

	if test "$with_nebula_libraries" != "no"; then
		LDFLAGS="${LDFLAGS}  -L${with_nebula_libraries}"
	fi
	LNEBULA="yes"
	AC_CHECK_LIB(nebula, nebula_new, LNEBULA="yes", LNEBULA="no")
	if test "$LNEBULA" = "no"; then
		echo
		bold "   %BError%b - nebula library not found. Install it or use the following options:"
		echo
		echo
		bold "   %B--with-nebula-libraries=%b"
		echo -e "\x5blocation of nebula shared library files\x5d"
		echo
		exit
	fi
else
	with_submit_nebula=" "
fi



AC_ARG_WITH(cspm,
	[  --with-cspm                     perform shellcode pattern matching])
AM_CONDITIONAL(BUILD_CSPM_PLUGIN, test x$with_cspm = xyes)
if test "$with_cspm" = "yes"; then
  if test "$enable_devmodules" != "X"; then
    echo
    echo "   The CSPM plugin is still unstable and should not be used in production setups."
    bold "   Use %B--enable-devmodules%b to build it anyway."
    echo
    exit
  fi

  with_cspm="X"

  AC_ARG_WITH(libpcre_includes,
    [  --with-libpcre-includes=DIR     libpcre include directory],
    [with_libpcre_includes="$withval"],[with_libpcre_includes=no])

  AC_ARG_WITH(libpcre_libraries,
    [  --with-libpcre-libraries=DIR    libpcre library directory],
    [with_libpcre_libraries="$withval"],[with_libpcre_libraries=no])

  if test "$with_libpcre_includes" != "no"; then
    CPPFLAGS="${CPPFLAGS} -I${with_libpcre_includes}"
  fi
  HPCRE="yes"
  AC_CHECK_HEADER(pcre.h,, HPCRE="no")
  if test "$HPCRE" = "no"; then
    echo
    bold "   %BError%b - libpcre headers not found. Install them or use the following options:"
    echo
    bold "   %B--with-libpcre-includes=%b"
    echo -e "\x5blocation of libpcre header files\x5d"
    echo
    exit
  fi

  if test "$with_libpcre_libraries" != "no"; then
    LDFLAGS="${LDFLAGS}  -L${with_libpcre_libraries}"
  fi
  LPCRE=""
  AC_CHECK_LIB(pcre, pcre_compile,, LPCRE="no")
  if test "$LPCRE" = "no"; then
    echo
    bold "   %BError%b - libpcre library not found. Install it or use the following options:"
    echo
    bold "   %B--with-libpcre-libraries=%b"
    echo -e "\x5blocation of libpcre shared library files\x5d"
    echo
    exit
  fi

else
	with_cspm=" "
fi


AC_ARG_WITH(submit-postgres,
	[  --with-submit-postgres          store attack data in PostgreSQL database])
AM_CONDITIONAL(BUILD_SUBMIT_POSTGRES_PLUGIN, test x$with_submit_postgres = xyes)
if test "$with_submit_postgres" = "yes"; then
	if test "$enable_devmodules" != "X"; then
		echo
		echo "   The submitPostgres plugin is still unstable and should not be used in production setups."
		bold "   Use %B--enable-devmodules%b to build it anyway."
		echo
		echo
		exit
	fi

  with_submit_postgres="X"
  AC_ARG_WITH(libpq_includes,
    [  --with-libpq-includes=DIR       libpq include directory],
    [with_libpq_includes="$withval"],[with_libpq_includes=no])

  AC_ARG_WITH(libpq_libraries,
    [  --with-libpq-libraries=DIR      libpq library directory],
    [with_libpq_libraries="$withval"],[with_libpq_libraries=no])

  if test "$with_libpq_includes" != "no"; then
    CPPFLAGS="${CPPFLAGS} -I${with_libpq_includes}"
  fi
  HPQ="yes"
  AC_CHECK_HEADER(libpq-fe.h,, HPQ="no")
  if test "$HPQ" = "no"; then
    echo
    bold "   %BError%b - libpq headers not found. Install them or use the following options:"
    echo
    bold "   %B--with-libpq-includes=%b\x5blocation of libpq header files\x5d"
    echo
    exit
  fi

  if test "$with_libpq_libraries" != "no"; then
    LDFLAGS="${LDFLAGS}  -L${with_libpq_libraries}"
  fi
  LPQ="yes"
  AC_CHECK_LIB(pq, PQconnectdb,, LPQ="no")
  if test "$LPQ" = "no"; then
    echo
    bold "   %BError%b - libpq library not found. Install it or use the following options:"
    echo
    bold "   %B--with-libpq-libraries=%b\x5blocation of libpq shared library files\x5d"
    echo
    exit
  fi

  AC_DEFINE([USE_POSTGRES_DB], [], [Define to store attacks in PostgreSQL database])
else
  with_submit_postgres=" "
fi


AC_ARG_WITH(magicpe,
	[  --with-magicpe                  store attack data in PostgreSQL database])
AM_CONDITIONAL(BUILD_MAGICPE_PLUGIN, test x$with_magicpe = xyes)
if test "$with_magicpe" = "yes"; then
  with_magicpe="X"
  AC_ARG_WITH(libmagic_includes,
    [  --with-libmagic-includes=DIR    libmagic include directory],
    [with_libmagic_includes="$withval"],[with_libmagic_includes=no])

  AC_ARG_WITH(libmagic_libraries,
    [  --with-libmagic-libraries=DIR   libmagic library directory],
    [with_libmagic_libraries="$withval"],[with_libmagic_libraries=no])

  if test "$with_libmagic_includes" != "no"; then
    CPPFLAGS="${CPPFLAGS} -I${with_libmagic_includes}"
  fi
  HMAGIC="yes"
  AC_CHECK_HEADER(magic.h,, HMAGIC="no")
  if test "$HMAGIC" = "no"; then
    echo
    bold "   %BError%b - libmagic headers not found. Install them or use the following options:"
    echo
    bold "   %B--with-libmagic-includes=%b\x5blocation of libmagic header files\x5d"
    echo
    exit
  fi

  if test "$with_libmagic_libraries" != "no"; then
    LDFLAGS="${LDFLAGS}  -L${with_libmagic_libraries}"
  fi
  LMAGIC="yes"
  AC_CHECK_LIB(magic, magic_open,, LMAGIC="no")
  if test "$LMAGIC" = "no"; then
    echo
    bold "   %BError%b - libmagic library not found. Install it or use the following options:"
    echo
    bold "   %B--with-libmagic-libraries=%b\x5blocation of libmagic shared library files\x5d"
    echo
    exit
  fi

  AC_DEFINE([USE_MAGICPE], [], [Define to automagically handle attack strings with a PE file(1) signature as malware])
else
  with_magicpe=" "
fi


AC_ARG_WITH(xmatch,
	[  --with-xmatch                   automatic pattern-based decoding of xored attacks])
AM_CONDITIONAL(BUILD_XMATCH_PLUGIN, test x$with_xmatch = xyes)
if test "$with_xmatch" = "yes"; then
  with_xmatch="X"
  AC_ARG_WITH(libxmatch_includes,
    [  --with-libxmatch-includes=DIR     libxmatch include directory],
    [with_libxmatch_includes="$withval"],[with_libxmatch_includes=no])

  AC_ARG_WITH(libxmatch_libraries,
    [  --with-libxmatch-libraries=DIR    libxmatch library directory],
    [with_libxmatch_libraries="$withval"],[with_libxmatch_libraries=no])

  if test "$with_libxmatch_includes" != "no"; then
    CPPFLAGS="${CPPFLAGS} -I${with_libxmatch_includes}"
  fi
  HMAGIC="yes"
  AC_CHECK_HEADER(xmatch.h,, HMAGIC="no")
  if test "$HMAGIC" = "no"; then
    echo
    bold "   %BError%b - libxmatch headers not found. Install them or use the following options:"
    echo
    bold "   %B--with-libxmatch-includes=%b\x5blocation of libxmatch header files\x5d"
    echo
    exit
  fi

  if test "$with_libxmatch_libraries" != "no"; then
    LDFLAGS="${LDFLAGS}  -L${with_libxmatch_libraries}"
  fi
  LMAGIC="yes"
  AC_CHECK_LIB(xmatch, xm_match,, LMAGIC="no")
  if test "$LMAGIC" = "no"; then
    echo
    bold "   %BError%b - libxmatch library not found. Install it or use the following options:"
    echo
    bold "   %B--with-libxmatch-libraries=%b\x5blocation of libxmatch shared library files\x5d"
    echo
    exit
  fi

  AC_DEFINE([USE_XMATCH], [], [Define to automatically xor-encoded attacks that contain certain patterns])
else
  with_xmatch=" "
fi


AC_ARG_WITH(logattacker,
        [  --with-logattacker             log attacking IP addresses in a separate file])
AM_CONDITIONAL(BUILD_LOGATTACKER_PLUGIN, test x$with_logattacker = xyes)
if test "$with_logattacker" = "yes"; then
  with_logattacker="X"

  AC_DEFINE([USE_LOGATTACK], [], [Define to log attacking IP addresses in a separate file])
else
  with_logattacker=" "
fi


AC_ARG_WITH(logjson,
    [  --with-logjson             log attack information in a dedicated JSON file],
	[with_logjson="$withval"], [with_logjson=""])
AM_CONDITIONAL(BUILD_LOGJSON_PLUGIN, test x$with_logjson = xyes)
if test "$with_logjson" = "yes"; then
  with_logjson="X"

  AC_ARG_WITH(libjson_includes,
    [  --with-libjson-includes=DIR   libjson include directory],
    [with_libjson_includes="$withval"],[with_libjson_includes=no])

  AC_ARG_WITH(libjson_libraries,
    [  --with-libjson-libraries=DIR  libjson library directory],
    [with_libjson_libraries="$withval"],[with_libjson_libraries=no])

  if test "$with_libjson_includes" != "no"; then
    CPPFLAGS="${CPPFLAGS} -I${with_libjson_includes}"
  fi
  HJSON="yes"
  AC_CHECK_HEADER(json-c/json.h,, HJSON="no")
  if test "$HJSON" = "no"; then
    echo
    bold "   %BError%b - libjson headers not found. Install them or use the following options:"
    echo
    echo
    bold "   %B--with-libjson-includes=%b"
    echo -e "\x5blocation of libjson header files\x5d"
    echo
    exit
  fi

  if test "$with_libjson_libraries" != "no"; then
    LDFLAGS="${LDFLAGS}  -L${with_libjson_libraries}"
  fi
  LJSON="yes"
  AC_CHECK_LIB(json-c, json_object_new_object,, LJSON="no")
  if test "$LJSON" = "no"; then
    echo
    bold "   %BError%b - libjson library not found. Install it or use the following options:"
    echo
    echo
    bold "   %B--with-libjson-libraries=%b"
    echo -e "\x5blocation of libjson shared library files\x5d"
    echo
    exit
  fi
else
  with_logjson=" "
fi


#-------------------------------------------------------------

# Check for electric fence malloc debugger
AC_ARG_WITH(efence, [  --with-efence                   link with electric fence ])
if test "$with_efence" = "yes"
then
	with_efence="X"
	LEFENCE="yes"
	AC_CHECK_LIB(efence, EF_ALIGNMENT, LIBS="${LIBS} -lefence", LEFENCE="no")
	if test "$LEFENCE" = "no"; then
		echo
		bold "   %BError%b - Electric fence libraries not found. Install them and re-run configure."
		echo
		exit 1
	fi
else
	with_efence=" "
fi


AC_CONFIG_FILES([Makefile
                 doc/Makefile
                 src/Makefile
                 src/modules/Makefile
                 src/modules/htm_cspm/Makefile])
AC_OUTPUT


echo
bold "  ----- %Bhoneytrap configuration%b -----"
echo
echo
echo "  General options"
bold "    (%B$enable_debug%b)  Debugging"
echo
bold "    (%B$enable_profile%b)  Profiling"
echo
bold "    (%B$enable_devmodules%b)  Unstable Modules"
echo
bold "    (%B$with_efence%b)  Electric Fence"
echo
echo
echo "  Connection monitor"
bold "    (%B$with_ipq_mon%b)  Linux ip_queue (ipq)"
echo
bold "    (%B$with_ipfw_mon%b)  FreeBSD ipfw (ipfw)"
echo
bold "    (%B$with_nfq_mon%b)  Linux libnetfilter_queue (nfq)"
echo
bold "    (%B$with_pcap_mon%b)  Libpcap (pcap)"
echo
echo
echo "  Optional plugins"
bold "    (%B$with_clamav%b)  ClamAV"
echo
bold "    (%B$with_cpuemu%b)  cpuEmu"
echo
bold "    (%B$with_cspm%b)  CSPM"
echo
bold "    (%B$with_submit_postgres%b)  PostgreSQL"
echo
bold "    (%B$with_spamsum%b)  SpamSum"
echo
bold "    (%B$with_magicpe%b)  magicPE"
echo
bold "    (%B$with_xmatch%b)  xmatch"
echo
bold "    (%B$with_logattacker%b)  logattacker"
echo
bold "    (%B$with_logjson%b)  logJSON"
echo
bold "    (%B$with_submit_mwserv%b)  submitMwserv"
echo
bold "    (%B$with_submit_nebula%b)  submitNebula"
echo
