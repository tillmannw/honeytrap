/* htm_cpuEmu.c
 * Copyright (C) 2007-2008 Tillmann Werner <tillmann.werner@gmx.de>
 *
 * This file is free software; as a special exception the author gives
 * unlimited permission to copy and/or distribute it, with or without
 * modifications, as long as this notice is preserved.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
 * implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 *
 * Description:
 *   This honeytrap module tries to find a shellcode within an attack string
 *   and the runs this code in a libemu-based x86 CPU emulation.
 *   libemu was written by Paul Baecher and Markus Koetter.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/stat.h>
#include <netdb.h>
#include <sys/socket.h>
#include <stdarg.h>
#include <stdio.h>

#include <sys/types.h>
#include <sys/wait.h>

#include <honeytrap.h>
#include <logging.h>
#include <plughook.h>
#include <util.h>
#include <md5.h>

#include "htm_cpuEmu.h"

#include <emu/emu.h>
#include <emu/emu_track.h>
#include <emu/emu_memory.h>
#include <emu/emu_cpu.h>
#include <emu/emu_cpu_data.h>
#include <emu/emu_log.h>
#include <emu/emu_hashtable.h>
#include <emu/emu_shellcode.h>
#include <emu/environment/emu_env.h>
#include <emu/environment/win32/emu_env_w32.h>
#include <emu/environment/win32/emu_env_w32_dll_export.h>
#include <emu/environment/win32/env_w32_dll_export_kernel32_hooks.h>
#include <emu/emu_getpc.h>

void logmsg_emu(struct emu *e, enum emu_log_level level, const char *msg);
int run(struct emu *e);
uint32_t user_hook_ExitProcess(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_ExitThread(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_socket(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_bind(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_connect(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_WaitForSingleObject(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_WSASocket(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_CreateProcess(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_accept(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_closesocket(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_listen(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_recv(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_send(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_exit(struct emu_env *env, struct emu_env_hook *hook, ...);


struct emu_logging *elog;


void plugin_init(void) {
	plugin_register_hooks();

	if ((elog = emu_log_new()) == NULL){
		logmsg(LOG_ERR, 1, "CPU Emulation Error - Unable to initialize logging.\n");
		exit(EXIT_FAILURE);
	}
	emu_log_set_logcb(elog, logmsg_emu);

	return;
}

void plugin_unload(void) {
	unhook(PPRIO_ANALYZE, module_name, "find_shellcode");

	emu_log_free(elog);

	return;
}

void plugin_register_hooks(void) {
	DEBUG_FPRINTF(stdout, "    Plugin %s: Registering hooks.\n", module_name);
	add_attack_func_to_list(PPRIO_ANALYZE, module_name, "find_shellcode", (void *) find_shellcode);

	return;
}


void logmsg_emu(struct emu *e, enum emu_log_level level, const char *msg) {
	s_log_level loglevel	= LL_OFF;

	switch (level) {
	case EMU_LOG_INFO:
		loglevel	= LL_NOISY;
		break;
	case EMU_LOG_DEBUG:
		loglevel	= LL_DEBUG;
		break;
	case EMU_LOG_NONE:
	default:
		break;
	}
	logmsg(loglevel, 1, "CPU Emulation - CPU reports: %s.\n", msg);

	return;
}


int find_shellcode(Attack *attack) {
	struct emu *e = NULL;
	int32_t offset;

	/* no data - nothing todo */
	if ((attack->a_conn.payload.size == 0) || (attack->a_conn.payload.data == NULL)) {
		logmsg(LOG_DEBUG, 1, "CPU Emulation - No data received, won't start emulation.\n");
		return(0);
	}

	logmsg(LOG_DEBUG, 1, "CPU Emulation - Parsing attack string (%d bytes) for shellcode.\n", attack->a_conn.payload.size);

	if ((e = emu_new()) == NULL) {
		logmsg(LOG_ERR, 1, "CPU Emulation Error - Unable to initialize virtual CPU.\n");
		return(-1);
	}

	logmsg(LOG_NOISY, 1, "CPU Emulation - Analyzing %u bytes.\n", attack->a_conn.payload.size);

	if ((offset = emu_shellcode_test(e, (u_char *) attack->a_conn.payload.data, attack->a_conn.payload.size)) >= 0) {
		logmsg(LOG_NOISY, 1, "CPU Emulation - Possible start of shellcode detected at offset %u.\n", offset);

		emu_free(e);

		// prepare emu for running shellcode
		e = emu_new();

		if ((opts.scode = malloc(attack->a_conn.payload.size)) == NULL) {
			logmsg(LOG_ERR, 1, "CPU Emulation Error - Unable to allocate memory: %s\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
		memcpy(opts.scode, attack->a_conn.payload.data, attack->a_conn.payload.size);

		opts.offset	= offset;
		opts.size	= attack->a_conn.payload.size;

		// set registers to the initial values
		struct emu_cpu		*cpu = emu_cpu_get(e);
		struct emu_memory	*mem = emu_memory_get(e);

		int j;
		for ( j=0;j<8;j++ ) emu_cpu_reg32_set(cpu,j , 0);

		emu_memory_write_dword(mem, 0xef787c3c, 4711);
		emu_memory_write_dword(mem, 0x0,        4711);
		emu_memory_write_dword(mem, 0x00416f9a, 4711);
		emu_memory_write_dword(mem, 0x0044fcf7, 4711);
		emu_memory_write_dword(mem, 0x00001265, 4711);
		emu_memory_write_dword(mem, 0x00002583, 4711);
		emu_memory_write_dword(mem, 0x00e000de, 4711);
		emu_memory_write_dword(mem, 0x01001265, 4711);
		emu_memory_write_dword(mem, 0x8a000066, 4711);

		// set flags
		emu_cpu_eflags_set(cpu, 0);

		// write code to offset
		int static_offset = CODE_OFFSET;
		emu_memory_write_block(mem, static_offset, opts.scode,  opts.size);

		// set eip to code
		emu_cpu_eip_set(emu_cpu_get(e), static_offset + opts.offset);
		emu_cpu_reg32_set(emu_cpu_get(e), esp, 0x0012fe98);

		// run code in emulated CPU
		run(e);

		emu_free(e);
		return(1);
	}

	logmsg(LOG_NOISY, 1, "CPU Emulation - %u bytes processed.\n", attack->a_conn.payload.size);

	return(0);
}


// run detected asm code on emulated CPU
int run(struct emu *e) {
	int			j, ret;
	uint32_t		eipsave;
	struct emu_cpu		*cpu = emu_cpu_get(e);
	struct emu_env		*env = emu_env_new(e);

	if (env == NULL) {
		logmsg(LOG_ERR, 1, "CPU Emulation Error - %s.\n", emu_strerror(e));
		return -1;
	}

	logmsg(LOG_NOISY, 1, "CPU Emulation - Preparing function hooks.\n");

	emu_env_w32_export_hook(env, "ExitProcess", user_hook_ExitProcess, NULL);
	emu_env_w32_export_hook(env, "ExitThread", user_hook_ExitThread, NULL);
	emu_env_w32_export_hook(env, "CreateProcessA", user_hook_CreateProcess, NULL);
	emu_env_w32_export_hook(env, "WaitForSingleObject", user_hook_WaitForSingleObject, NULL);

	emu_env_w32_load_dll(env->env.win,"ws2_32.dll");
	emu_env_w32_export_hook(env, "accept", user_hook_accept, NULL);
	emu_env_w32_export_hook(env, "bind", user_hook_bind, NULL);
	emu_env_w32_export_hook(env, "closesocket", user_hook_closesocket, NULL);
	emu_env_w32_export_hook(env, "connect", user_hook_connect, NULL);
	emu_env_w32_export_hook(env, "listen", user_hook_listen, NULL);
	emu_env_w32_export_hook(env, "recv", user_hook_recv, NULL);
	emu_env_w32_export_hook(env, "send", user_hook_send, NULL);
	emu_env_w32_export_hook(env, "socket", user_hook_socket, NULL);
	emu_env_w32_export_hook(env, "WSASocketA", user_hook_WSASocket, NULL);

	opts.steps = 1000000;

	// run the code
	logmsg(LOG_NOISY, 1, "CPU Emulation - Running code...\n");

	struct emu_hashtable *eh = NULL;
	for (eipsave=0, j=0;j<opts.steps;j++ ) {
		if (cpu->repeat_current_instr == false) eipsave = emu_cpu_eip_get(emu_cpu_get(e));

		struct emu_env_hook *hook = NULL;

		ret = 0;

		if ((hook = emu_env_w32_eip_check(env)) != NULL) {
			if (hook->hook.win->fnhook == NULL) {
				logmsg(LOG_DEBUG, 1, "CPU Emulation - Unhooked call to %s.\n", hook->hook.win->fnname);
				break;
			}
		} else {
			if ((ret = emu_cpu_parse(emu_cpu_get(e))) == -1) {
				logmsg(LOG_WARN, 1, "CPU Emulation Warning - CPU Error: %s", emu_strerror(e));
				break;
			}
			if (log_level == LOG_DEBUG) {
				emu_log_level_set(emu_logging_get(e),EMU_LOG_DEBUG);
				logDebug(e, "%s\n", cpu->instr_string);
				emu_log_level_set(emu_logging_get(e),EMU_LOG_NONE);
			}
		}
	}
	if (eh != NULL) emu_hashtable_free(eh);

	return 0;
}


// (W32 API) function hooks
uint32_t user_hook_ExitProcess(struct emu_env *env, struct emu_env_hook *hook, ...) {
	va_list	vl;
	int	exitcode;

	va_start(vl, hook);

	exitcode = va_arg(vl,  int);

	va_end(vl);

	logmsg(LOG_NOISY, 1, "CPU Emulation - Hooking ExitProcess() call.\n");

	opts.steps = 0;
	return 0;
}


uint32_t user_hook_ExitThread(struct emu_env *env, struct emu_env_hook *hook, ...) {
	va_list	vl;
	int	exitcode;

	va_start(vl, hook);

	exitcode = va_arg(vl,  int);

	va_end(vl);

	logmsg(LOG_NOISY, 1, "CPU Emulation - Hooking ExitThread() call.\n");

	opts.steps = 0;
	return 0;

}

uint32_t user_hook_socket(struct emu_env *env, struct emu_env_hook *hook, ...) {
	va_list		vl;
	int		domain, type, protocol;

	logmsg(LOG_NOISY, 1, "CPU Emulation - Hooking socket() call.\n");

	va_start(vl, hook);

	domain		= va_arg(vl, int);
	type		= va_arg(vl, int);
	protocol	= va_arg(vl, int);

	va_end(vl);

	return socket(domain, type, protocol);
}



uint32_t user_hook_bind(struct emu_env *env, struct emu_env_hook *hook, ...) {
	va_list			vl;
	int			s;
	struct sockaddr		*saddr;
	socklen_t		saddrlen;
	struct sockaddr_in	*si;

	logmsg(LOG_NOISY, 1, "CPU Emulation - Hooking bind() call.\n");

	va_start(vl, hook);

	s		= va_arg(vl, int);
	saddr		= va_arg(vl, struct sockaddr *);
	saddrlen	= va_arg(vl, socklen_t);

	if (opts.override.bind.host != NULL) {
		si			= (struct sockaddr_in *) saddr;
		si->sin_addr.s_addr	= inet_addr(opts.override.bind.host);
	}

	if (opts.override.connect.port > 0) {
		si		= (struct sockaddr_in *) saddr;
		si->sin_port	= htons(opts.override.bind.port);
	}

	va_end(vl);

	return bind(s, saddr, saddrlen);
}


uint32_t user_hook_connect(struct emu_env *env, struct emu_env_hook *hook, ...) {
	va_list			vl;
	int			s;
	struct sockaddr		*saddr;
	struct sockaddr_in	*si;
	socklen_t		saddrlen;

	logmsg(LOG_NOISY, 1, "CPU Emulation - Hooking connect() call.\n");

	va_start(vl, hook);

	s	= va_arg(vl,  int);
	saddr	= va_arg(vl,  struct sockaddr *);

	if (opts.override.connect.host != NULL) {
		si			= (struct sockaddr_in *) saddr;
		si->sin_addr.s_addr	= inet_addr(opts.override.connect.host);
	}

	if (opts.override.connect.port > 0) {
		si		= (struct sockaddr_in *) saddr;
		si->sin_port	= htons(opts.override.connect.port);
	}

	saddrlen = va_arg(vl,  socklen_t);

	va_end(vl);

	return connect(s, saddr, saddrlen);
}

uint32_t user_hook_WaitForSingleObject(struct emu_env *env, struct emu_env_hook *hook, ...) {
	va_list	vl;
	int32_t	hHandle;
	int	status;

	logmsg(LOG_NOISY, 1, "CPU Emulation - Hooking WaitForSingleObject() call.\n");

	va_start(vl, hook);

	hHandle = va_arg(vl, int32_t);
	va_arg(vl, int32_t);

	va_end(vl);

	for(;;) {
		if (waitpid(hHandle, &status, WNOHANG) != 0) break;
		sleep(1);
	}

	return 0;
}

uint32_t user_hook_WSASocket(struct emu_env *env, struct emu_env_hook *hook, ...) {
	va_list	vl;
	int	domain, type, protocol;

	logmsg(LOG_NOISY, 1, "CPU Emulation - Hooking WSASocket() call.\n");

	va_start(vl, hook);

	domain		= va_arg(vl,  int);
	type		= va_arg(vl,  int);
	protocol	= va_arg(vl, int);
	va_arg(vl, int);
	va_arg(vl, int);
	va_arg(vl, int);

	va_end(vl);

	return socket(domain, type, protocol);
}

uint32_t user_hook_CreateProcess(struct emu_env *env, struct emu_env_hook *hook, ...) {
	va_list			vl;
	char			*pszCmdLine;
	STARTUPINFO		*psiStartInfo;
	PROCESS_INFORMATION	*pProcInfo;

	logmsg(LOG_NOISY, 1, "CPU Emulation - Hooking CreateProcess() call.\n");

	va_start(vl, hook);

	va_arg(vl, char *);	// pszImageName
	pszCmdLine = va_arg(vl, char *);               
	va_arg(vl, void *);	// psaProcess
	va_arg(vl, void *);	// psaThread
	va_arg(vl, char *);	// fInheritHandles
	va_arg(vl, uint32_t);	// fdwCreate
	va_arg(vl, void *);	// pvEnvironment
	va_arg(vl, char *);	// pszCurDir
	psiStartInfo	=  va_arg(vl, STARTUPINFO *);
	pProcInfo	=  va_arg(vl, PROCESS_INFORMATION *); 

	va_end(vl);

	if (pszCmdLine && strncasecmp(pszCmdLine, "cmd", 3) == 0) {
		pid_t pid;

		logmsg(LOG_NOISY, 1, "CPU Emulation - Forking connection handler.\n");
		if ((pid = fork()) == 0) {
			// child code
			dup2(psiStartInfo->hStdInput,  fileno(stdin));
			dup2(psiStartInfo->hStdOutput, fileno(stdout));
			dup2(psiStartInfo->hStdError,  fileno(stderr));

			system("/bin/sh -c \"cd ~/.wine/drive_c/; wine 'c:\\windows\\system32\\cmd_orig.exe' \"");
			
			exit(EXIT_SUCCESS);
		} else {
			// parent code 
			pProcInfo->hProcess = pid;
		}
	}
	return 1;
}

uint32_t user_hook_accept(struct emu_env *env, struct emu_env_hook *hook, ...) {
	va_list 	vl;
	int		s;
	struct sockaddr	*saddr;
	socklen_t	*saddrlen;
	

	logmsg(LOG_NOISY, 1, "CPU Emulation - Hooking accept() call.\n");

	va_start(vl, hook);

	s		= va_arg(vl,  int);
	saddr 		= va_arg(vl,  struct sockaddr *);
	saddrlen	= va_arg(vl,  socklen_t *);

	va_end(vl);

	return accept(s, saddr, saddrlen);
}

uint32_t user_hook_closesocket(struct emu_env *env, struct emu_env_hook *hook, ...) {
	va_list vl;
	int s;

	logmsg(LOG_NOISY, 1, "CPU Emulation - Hooking closesocket() call.\n");

	va_start(vl, hook);

	s = va_arg(vl,  int);

	va_end(vl);

	return close(s);
}

uint32_t user_hook_listen(struct emu_env *env, struct emu_env_hook *hook, ...) {
	va_list	vl;
	int	s, backlog;

	logmsg(LOG_NOISY, 1, "CPU Emulation - Hooking listen() call.\n");

	va_start(vl, hook);

	s	= va_arg(vl,  int);
	backlog	= va_arg(vl,  int);

	va_end(vl);

	return listen(s, backlog);
}

uint32_t user_hook_recv(struct emu_env *env, struct emu_env_hook *hook, ...) {
	va_list	vl;
	int	s, len, flags;
	char	*buf;

	logmsg(LOG_NOISY, 1, "CPU Emulation - Hooking recv() call.\n");

	va_start(vl, hook);

	s	= va_arg(vl,  int);
	buf	= va_arg(vl,  char *);
	len	= va_arg(vl,  int);
	flags	= va_arg(vl,  int);

	va_end(vl);

	return recv(s, buf, len,  flags);
}

uint32_t user_hook_send(struct emu_env *env, struct emu_env_hook *hook, ...) {
	va_list	vl;
	int	s, len, flags;
	char	*buf;

	logmsg(LOG_NOISY, 1, "CPU Emulation - Hooking send() call.\n");

	va_start(vl, hook);

	s	= va_arg(vl,  int);
	buf	= va_arg(vl,  char *);
	len	= va_arg(vl,  int);
	flags	= va_arg(vl,  int);

	va_end(vl);

	return send(s, buf, len,  flags);
}

uint32_t user_hook_exit(struct emu_env *env, struct emu_env_hook *hook, ...) {
	va_list	vl;
	int	code;

	logmsg(LOG_NOISY, 1, "CPU Emulation - Hooking exit() call.\n");

	va_start(vl, hook);

	code = va_arg(vl,  int);

	va_end(vl);

	opts.steps = 0;

	return 0;
}
