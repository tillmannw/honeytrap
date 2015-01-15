/* htm_cpuEmu.c
 * Copyright (C) 2007-2015 Tillmann Werner <tillmann.werner@gmx.de>
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

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <ctype.h>

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
#include <emu/environment/win32/emu_env_w32_dll.h>
#include <emu/environment/win32/emu_env_w32_dll_export.h>
#include <emu/environment/win32/env_w32_dll_export_kernel32_hooks.h>
#include <emu/emu_getpc.h>
#include <emu/emu_hashtable.h>
#include <emu/emu_string.h>

#include <conftree.h>
#include <dynsrv.h>
#include <honeytrap.h>
#include <logging.h>
#include <plughook.h>
#include <readconf.h>
#include <signals.h>
#include <util.h>
#include <md5.h>

#include "htm_cpuEmu.h"

struct nanny_file {
	char		*path;
	uint32_t	emu_file;
	FILE		*real_file;
};

struct nanny {
	struct emu_hashtable *files;
};


struct nanny *nanny_new();
void nanny_free(struct nanny *nanny);
struct nanny_file *nanny_add_file(struct nanny *na, const char *path, uint32_t *emu_file, FILE *real_file);
struct nanny_file *nanny_get_file(struct nanny *na, uint32_t emu_file);
bool nanny_del_file(struct nanny *na, uint32_t emu_file);

void logmsg_emu(struct emu *e, enum emu_log_level level, const char *msg);
int run(struct emu *e, int interactive);

uint32_t user_hook_ExitProcess(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_ExitThread(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_CreateProcess(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_WaitForSingleObject(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_exit(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_accept(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_bind(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_bind_regport(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_closesocket(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_connect(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_fclose(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_fopen(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_fwrite(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_listen(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_recv(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_send(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_socket(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_WSASocket(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_CreateFile(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_WriteFile(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_CloseHandle(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_URLDownloadToFile(struct emu_env *env, struct emu_env_hook *hook, ...);


struct emu_logging *elog;


void plugin_unload(void) {
	if (execute_shellcode)
		unhook(PPRIO_PERREAD, module_name, "find_shellcode");

	unhook(PPRIO_ANALYZE, module_name, "find_shellcode");

	emu_log_free(elog);

	return;
}

void plugin_register_hooks(void) {
	logmsg(LOG_DEBUG, 1, "    Plugin %s: Registering hooks.\n", module_name);
	add_attack_func_to_list(PPRIO_ANALYZE, module_name, "find_shellcode", (void *) find_shellcode);

	return;
}

conf_node *plugin_process_confopts(conf_node *tree, conf_node *node, void *opt_data) {
	char		*value = NULL;
	conf_node	*confopt = NULL;

	if ((confopt = check_keyword(tree, node->keyword)) == NULL) return(NULL);

	while (node->val) {
		if ((value = malloc(node->val->size+1)) == NULL) {
			perror("  Error - Unable to allocate memory");
			exit(EXIT_FAILURE);
		}
		memset(value, 0, node->val->size+1);
		memcpy(value, node->val->data, node->val->size);

		node->val = node->val->next;

		if OPT_IS("execute_shellcode") {
			if (strcmp(value, "yes") == 0) {
				execute_shellcode = 1;
				add_attack_func_to_list(PPRIO_PERREAD, module_name, "find_shellcode", (void *) find_shellcode);
			}
		} else if OPT_IS("createprocess_cmd") {
			createprocess_cmd = value;
		} else {
			fprintf(stderr, "  Error - Invalid configuration option for plugin %s: %s\n", module_name, node->keyword);
			exit(EXIT_FAILURE);
		}
	}
	return(node);
}

void plugin_config(void) {
	execute_shellcode	= 0;
	createprocess_cmd	= NULL;

	register_plugin_confopts(module_name, config_keywords, sizeof(config_keywords)/sizeof(char *));
	if (process_conftree(config_tree, config_tree, plugin_process_confopts, NULL) == NULL) {
		fprintf(stderr, "  Error - Unable to process configuration tree for plugin %s.\n", module_name);
		exit(EXIT_FAILURE);
	}

	return;
}

void plugin_init(void) {
	if ((elog = emu_log_new()) == NULL){
		logmsg(LOG_ERR, 1, "CPU Emulation Error - Unable to initialize logging.\n");
		exit(EXIT_FAILURE);
	}
	emu_log_set_logcb(elog, logmsg_emu);

	plugin_register_hooks();

	return;
}

void logmsg_emu(struct emu *e, enum emu_log_level level, const char *msg) {
	s_log_level loglevel	= LL_OFF;

	// map libemu log level to our log level
	switch (level) {
	case EMU_LOG_INFO:
		loglevel	= LL_NOISY;
		break;
	case EMU_LOG_DEBUG:
//		loglevel	= LL_DEBUG;
//		break;
	case EMU_LOG_NONE:
	default:
		return;
	}
	logmsg(loglevel, 1, "CPU Emulation - CPU reports: %s", msg);

	return;
}


int find_shellcode(Attack *attack) {
	struct emu	*e = NULL;
	int32_t		offset;
	int		attack_complete = 0;

	/* no data - nothing todo */
	if ((attack->a_conn.payload.size == 0) || (attack->a_conn.payload.data == NULL)) {
		logmsg(LOG_DEBUG, 1, "CPU Emulation - No data received, won't start emulation.\n");
		return(0);
	}

	if (attack->end_time) attack_complete = 1;

	logmsg(LOG_DEBUG, 1, "CPU Emulation - Parsing attack string (%d bytes) for shellcode.\n", attack->a_conn.payload.size);

	if ((e = emu_new()) == NULL) {
		logmsg(LOG_ERR, 1, "CPU Emulation Error - Unable to initialize virtual CPU.\n");
		return(-1);
	}

	emu_log_set_logcb(emu_logging_get(e), logmsg_emu);

	if (attack_complete)
		logmsg(LOG_NOISY, 1, "CPU Emulation - Analyzing %u bytes.\n", attack->a_conn.payload.size);

	if ((offset = emu_shellcode_test(e, (u_char *) attack->a_conn.payload.data, attack->a_conn.payload.size)) >= 0) {
		if (attack_complete)
			logmsg(LOG_INFO, 1, "CPU Emulation - Possible start of shellcode detected at offset %u.\n", offset);

		emu_free(e);

		if (execute_shellcode) {
			// prepare emu for running shellcode
			e = emu_new();
			emu_log_set_logcb(emu_logging_get(e), logmsg_emu);

			if ((opts.scode = malloc(attack->a_conn.payload.size)) == NULL) {
				logmsg(LOG_ERR, 1, "CPU Emulation Error - Unable to allocate memory: %s\n", strerror(errno));
				return -1;
			}
			memcpy(opts.scode, attack->a_conn.payload.data, attack->a_conn.payload.size);

			opts.offset	= offset;
			opts.size	= attack->a_conn.payload.size;

			// set registers to the initial values
			struct emu_cpu		*cpu = emu_cpu_get(e);
			struct emu_memory	*mem = emu_memory_get(e);

			int j;
			for (j=0; j<8; j++)  emu_cpu_reg32_set(cpu,j , 0);

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
			emu_memory_write_block(mem, CODE_OFFSET, opts.scode,  opts.size);

			// set eip to code
			emu_cpu_eip_set(emu_cpu_get(e), CODE_OFFSET + opts.offset);
			emu_cpu_reg32_set(emu_cpu_get(e), esp, 0x0012fe98);

			// run code on emulated CPU
			run(e, attack_complete);

			emu_free(e);
		}

		logmsg(LOG_NOISY, 1, "CPU Emulation - %u bytes processed.\n", attack->a_conn.payload.size);
		return(1);
	}

	logmsg(LOG_NOISY, 1, "CPU Emulation - %u bytes processed.\n", attack->a_conn.payload.size);
	return(0);
}


// run detected asm code on emulated CPU
int run(struct emu *e, int interactive) {
	int 			j, ret;
	struct emu_cpu		*cpu = emu_cpu_get(e);
	struct emu_env		*env = emu_env_new(e);
	struct emu_hashtable	*eh = NULL;


	if (env == NULL) {
		logmsg(LOG_ERR, 1, "CPU Emulation Error - Unable to create environment: %s.\n", emu_strerror(e));
		return -1;
	}

	if (interactive) {
		// register hook functions for interactive shellcode execution
		struct nanny *na = nanny_new();
		logmsg(LOG_NOISY, 1, "CPU Emulation - Preparing function hooks.\n");

		emu_env_w32_load_dll(env->env.win,"msvcrt.dll");
		emu_env_w32_export_hook(env, "fclose", user_hook_fclose, na);
		emu_env_w32_export_hook(env, "fopen", user_hook_fopen, na);
		emu_env_w32_export_hook(env, "fwrite", user_hook_fwrite, na);

		emu_env_w32_export_hook(env, "CreateProcessA", user_hook_CreateProcess, NULL);
		emu_env_w32_export_hook(env, "WaitForSingleObject", user_hook_WaitForSingleObject, NULL);
		emu_env_w32_export_hook(env, "CreateFileA", user_hook_CreateFile, na);
		emu_env_w32_export_hook(env, "WriteFile", user_hook_WriteFile, na);
		emu_env_w32_export_hook(env, "CloseHandle", user_hook_CloseHandle, na);


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

		emu_env_w32_load_dll(env->env.win,"urlmon.dll");
		emu_env_w32_export_hook(env, "URLDownloadToFileA", user_hook_URLDownloadToFile, NULL);
	} else {
		// register hook functions for bind port lookups 
		emu_env_w32_load_dll(env->env.win,"ws2_32.dll");
		emu_env_w32_export_hook(env, "WSASocketA", user_hook_WSASocket, NULL);
		emu_env_w32_export_hook(env, "socket", user_hook_socket, NULL);
		emu_env_w32_export_hook(env, "bind", user_hook_bind_regport, NULL);
	}


	opts.steps = 1000000;

	// run the code
	if (interactive)
		logmsg(LOG_NOISY, 1, "CPU Emulation - Running code...\n");

	for (j=0;j<opts.steps;j++) {
		struct emu_env_hook *hook	= NULL;
		ret				= 0;

		if ((hook = emu_env_w32_eip_check(env)) != NULL) {
			if (hook->hook.win->fnhook == NULL) {
				logmsg(LOG_DEBUG, 1, "CPU Emulation - Unhooked call to %s.\n", hook->hook.win->fnname);
				break;
			}
		} else {
			ret = emu_cpu_parse(emu_cpu_get(e));

			if (log_level == LOG_DEBUG) {
				emu_log_level_set(emu_logging_get(e),EMU_LOG_DEBUG);
				logDebug(e, "%s\n", cpu->instr_string);
				emu_log_level_set(emu_logging_get(e),EMU_LOG_NONE);
			}

			struct emu_env_hook *hook = NULL;

			if ( ret != -1 ) {
				if ( hook == NULL ) ret = emu_cpu_step(emu_cpu_get(e));
				else break;
			} else {
				logmsg(LOG_WARN, 1, "CPU Emulation Warning - CPU error: %s", emu_strerror(e));
				break;
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

	logmsg(LOG_NOISY, 1, "CPU Emulation - Hooking ExitProcess(%d)\n", exitcode);

	opts.steps = 0;
	return 0;
}


uint32_t user_hook_ExitThread(struct emu_env *env, struct emu_env_hook *hook, ...) {
	va_list	vl;
	int	exitcode;

	va_start(vl, hook);

	exitcode = va_arg(vl,  int);

	va_end(vl);

	logmsg(LOG_NOISY, 1, "CPU Emulation - Hooking ExitThread(%d)\n", exitcode);

	opts.steps = 0;
	return 0;

}

uint32_t user_hook_socket(struct emu_env *env, struct emu_env_hook *hook, ...) {
	va_list		vl;
	int		af, type, protocol;

	va_start(vl, hook);

	af		= va_arg(vl, int);
	type		= va_arg(vl, int);
	protocol	= va_arg(vl, int);

	va_end(vl);

	logmsg(LOG_NOISY, 1, "CPU Emulation - Hooking socket(%d, %d, %d) call.\n", af, type, protocol);

	return socket(af, type, protocol);
}

uint32_t user_hook_bind(struct emu_env *env, struct emu_env_hook *hook, ...) {
	va_list			vl;
	int			s, sockopt;
	struct sockaddr		*saddr;
	socklen_t		saddrlen;

	va_start(vl, hook);

	s		= va_arg(vl, int);
	saddr		= va_arg(vl, struct sockaddr *);
	saddrlen	= va_arg(vl, socklen_t);

	va_end(vl);

	((struct sockaddr_in *)saddr)->sin_port = htons(((struct sockaddr_in *)saddr)->sin_port);

	logmsg(LOG_NOISY, 1, "CPU Emulation - Hooking bind(%d, %p [port %u], %u)\n", s, saddr, ntohs(((struct sockaddr_in *)saddr)->sin_port), saddrlen);

	sockopt = 1;
	if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof(sockopt)) < 0)
		logmsg(LOG_WARN, 1, "CPU Emulation Warning - Unable to set SO_REUSEADDR for server socket.\n");

	if (opts.override.bind.host != NULL)		// override listen address?
		((struct sockaddr_in *)saddr)->sin_addr.s_addr = inet_addr(opts.override.connect.host);

	if (opts.override.bind.port > 0)		// override listen port?
		((struct sockaddr_in *)saddr)->sin_port = htons(opts.override.connect.port);

	return bind(s, saddr, saddrlen);
}

uint32_t user_hook_bind_regport(struct emu_env *env, struct emu_env_hook *hook, ...) {
	va_list			vl;
	int			s, type;
	struct sockaddr		*saddr;
	socklen_t		optsize;
	portinfo		pinfo;

	va_start(vl, hook);

	s		= va_arg(vl, int);
	saddr		= va_arg(vl, struct sockaddr *);

	va_end(vl);

	optsize = sizeof(type);
	if (getsockopt(s, SOL_SOCKET, SO_TYPE, &type, &optsize) < 0) {
		logmsg(LOG_ERR, 1, "CPU Emulation Error - Unable to determine socket type: %s.\n", strerror(errno));
		return -1;
	}

	memset(&pinfo, 0, sizeof(portinfo));
	pinfo.port	= ((struct sockaddr_in *)saddr)->sin_port;
	pinfo.mode	= PORTCONF_IGNORE;

	switch(type) {
	case SOCK_STREAM:
		pinfo.protocol	= TCP;
		logmsg(LOG_NOISY, 1, "CPU Emulation - Registering port %u/tcp\n", ntohs(pinfo.port));
		break;
	case SOCK_DGRAM:
		pinfo.protocol	= UDP;
		logmsg(LOG_NOISY, 1, "CPU Emulation - Registering port %u/udp\n", ntohs(pinfo.port));
		break;
	default:
		logmsg(LOG_ERR, 1, "CPU Emulation Error - Unable to determine socket type.\n");
		return -1;
	}

	if (write(portinfopipe[1], (char *) &pinfo, sizeof(portinfo)) == -1) {
		logmsg(LOG_ERR, 1, "CPU Emulation Error - Unable to write to IPC pipe: %s.\n", strerror(errno));
		return -1;
	}

	return 0;
}

uint32_t user_hook_connect(struct emu_env *env, struct emu_env_hook *hook, ...) {
	va_list			vl;
	int			s, rv;
	struct sockaddr		*saddr, daddr;
	socklen_t		saddrlen, daddrlen;
	char			shost[16], dhost[16];

#define SOCKET_ERROR	-1

	va_start(vl, hook);

	s		= va_arg(vl,  int);
	saddr		= va_arg(vl,  struct sockaddr *);
	saddrlen	= va_arg(vl,  socklen_t);

	va_end(vl);

	logmsg(LOG_NOISY, 1, "CPU Emulation - Hooking connect(%d, %p, %u)\n", s, saddr, saddrlen);

	if (opts.override.connect.host != NULL)		// override dst address?
		((struct sockaddr_in *)saddr)->sin_addr.s_addr = inet_addr(opts.override.connect.host);

	if (opts.override.connect.port > 0)		// override dst port?
		((struct sockaddr_in *)saddr)->sin_port = htons(opts.override.connect.port);

	if ((rv = connect(s, saddr, saddrlen)) == -1)
		return SOCKET_ERROR;

	daddrlen = sizeof(struct sockaddr);
	if (getsockname(s, &daddr, &daddrlen) == -1) {
		logmsg(LOG_ERR, 1, "CPU Emulation Error - Unable to get peer information: %s.\n", strerror(errno));
		return -1;
	}
	if (getpeername(s, saddr, &saddrlen) == -1) {
		logmsg(LOG_ERR, 1, "CPU Emulation Error - Unable to get peer information: %s.\n", strerror(errno));
		return -1;
	}

	if ((inet_ntop(AF_INET, &((struct sockaddr_in *)saddr)->sin_addr, shost, 16) == NULL) ||
	    (inet_ntop(AF_INET, &((struct sockaddr_in *)&daddr)->sin_addr, dhost, 16) == NULL)) {
		logmsg(LOG_ERR, 1, "CPU Emulation Error - Unable to convert IP address: %s.\n", strerror(errno));
		return -1;
	} 

	logmsg(LOG_NOISY, 1, "CPU Emulation - Connection established: %s:%u -> %s:%u.\n", 
		shost, ntohs(((struct sockaddr_in *)saddr)->sin_port), 
		dhost, ntohs(((struct sockaddr_in *)&daddr)->sin_port));

	return rv;
}

uint32_t user_hook_WaitForSingleObject(struct emu_env *env, struct emu_env_hook *hook, ...) {
	va_list		vl;
	int32_t		hHandle;
	int32_t		dwMilliseconds;
	int		status;
	struct timeval	tv;

#define WAIT_OBJECT_0	0x00000000
#define WAIT_ABANDONED	0x00000080
#define WAIT_TIMEOUT	0x00000102
#define WAIT_FAILED	0xFFFFFFFF

	va_start(vl, hook);

	hHandle		= va_arg(vl, int32_t);
	dwMilliseconds	= va_arg(vl, int32_t);

	va_end(vl);

	logmsg(LOG_NOISY, 1, "CPU Emulation - Hooking WaitForSingleObject(%u)\n", dwMilliseconds);

	switch (waitpid(hHandle, &status, WNOHANG)) {
	case -1:
		return WAIT_FAILED;
	case 0:
		tv.tv_sec	= 0;
		tv.tv_usec	= dwMilliseconds / 1000;
		if (sleep_sigaware(&tv) == -1)
			return WAIT_FAILED;

		switch (waitpid(hHandle, &status, WNOHANG)) {
		case -1:
			return WAIT_FAILED;
		case 0:
			return WAIT_TIMEOUT;
		}
	}

	return WAIT_OBJECT_0;	// never reached
}

uint32_t user_hook_WSASocket(struct emu_env *env, struct emu_env_hook *hook, ...) {
	va_list	vl;
	int	af, type, protocol;

	va_start(vl, hook);

	af		= va_arg(vl,  int);
	type		= va_arg(vl,  int);
	protocol	= va_arg(vl, int);
	(void) va_arg(vl, int);
	(void) va_arg(vl, int);
	(void) va_arg(vl, int);

	va_end(vl);

	logmsg(LOG_NOISY, 1, "CPU Emulation - Hooking WSASocket(%d, %d, %d, ...)\n", af, type, protocol);

	return socket(af, type, protocol);
}

void append(struct emu_string *to, const char *dir, char *data, int size)
{
	char *saveptr = data;

	struct emu_string *sanestr = emu_string_new();


	int i;
	for (i=0;i<size;i++)
	{
		if (data[i] == '\r')
		{

		}else
		if ( isprint(data[i]))// || isblank(data[i]))
		{
			emu_string_append_format(sanestr, "%c", data[i]);
		}
		else
		if (data[i] == '\n')
		{
			emu_string_append_char(sanestr, "\n");
		}
		else
		if (data[i] == '\t')
		{
			emu_string_append_char(sanestr, "\t");
		} 
		else
		{
			emu_string_append_format(sanestr, "\\x%02x", (unsigned char)data[i]);
		}
	}

	saveptr = NULL;


	char *tok;
	tok  = strtok_r(sanestr->data, "\n", &saveptr);
//	printf("line %s:%s\n",dir, tok);
	if (tok != NULL)
	{
		emu_string_append_format(to, "%s %s\n", dir, tok); 
		while ( (tok = strtok_r(NULL,"\n",&saveptr)) != NULL )
		{
			emu_string_append_format(to, "%s %s\n", dir, tok);
//		printf("line %s:%s\n",dir, tok);
		}

	}
	emu_string_free(sanestr);
}

uint32_t user_hook_CreateProcess(struct emu_env *env, struct emu_env_hook *hook, ...) {

	va_list vl;
	va_start(vl, hook);

	/* char *pszImageName				  = */ (void)va_arg(vl, char *);
	char *pszCmdLine                      = va_arg(vl, char *);               
	/* void *psaProcess, 				  = */ (void)va_arg(vl, void *);
	/* void *psaThread,  				  = */ (void)va_arg(vl, void *);
	/* bool fInheritHandles,              = */ (void)va_arg(vl, char *);
	/* uint32_t fdwCreate,                = */ (void)va_arg(vl, uint32_t);
	/* void *pvEnvironment             	  = */ (void)va_arg(vl, void *);
	/* char *pszCurDir                 	  = */ (void)va_arg(vl, char *);
	STARTUPINFO *psiStartInfo             = va_arg(vl, STARTUPINFO *);
	PROCESS_INFORMATION *pProcInfo        = va_arg(vl, PROCESS_INFORMATION *); 

	va_end(vl);

	logmsg(LOG_NOISY, 1, "CPU Emulation - Hooking CreateProcess(..., %s, ...)\n", pszCmdLine);

	if ( pszCmdLine != NULL && strncasecmp(pszCmdLine, "cmd", 3) == 0 ) {
		pid_t child;
		pid_t spy;


		if ( (spy = fork()) == 0 ) {
			// spy

			int in[2];
			int out[2];
			int err[2];

			if ((socketpair( AF_UNIX, SOCK_STREAM, 0, in ) == -1) ||
			    (socketpair( AF_UNIX, SOCK_STREAM, 0, out ) == -1) ||
			    (socketpair( AF_UNIX, SOCK_STREAM, 0, err ) == -1)) {
				logmsg(LOG_ERR, 1, "CPU Emulation Error - Unable to create spy socket pair: %s.\n", strerror(errno));
				return 0;
			}

			if ( (child = fork()) == 0 ) {
				// child

				logmsg(LOG_DEBUG, 1, "CPU Emulation - Executing \"%s\"\n", createprocess_cmd);
				close(in[0]);
				close(out[1]);
				close(err[1]);

				if ((dup2(in[1], fileno(stdin)) == -1) ||
				    (dup2(out[0], fileno(stdout)) == -1) ||
				    (dup2(err[0], fileno(stderr)) == -1)) {
					logmsg(LOG_ERR, 1, "CPU Emulation Error - Unable to duplicate file descriptors: %s.\n", strerror(errno));
					exit(EXIT_FAILURE);
				}

/*
				struct emu_hashtable_item *ehi = emu_hashtable_search(opts.override.commands.commands, "cmd");
				if ( ehi != NULL )
					system((char *)ehi->value);
				else
*/
//					system("/bin/sh -c \"cd /opt/honeytrap-libemu/.wine/drive_c/; wine 'c:\\windows\\system32\\cmd.exe'\"");
					system(createprocess_cmd);

				close(in[1]);
				close(out[0]);
				close(err[0]);


				exit(EXIT_SUCCESS);
			} else {
				// spy

				struct emu_string *io = emu_string_new();
				close(in[1]);
				close(out[0]);
				close(err[0]);

				fd_set socks;

				fcntl(psiStartInfo->hStdInput,F_SETFL,O_NONBLOCK);
				fcntl(out[1],F_SETFL,O_NONBLOCK);
				fcntl(err[1],F_SETFL,O_NONBLOCK);

				char buf[1025];

				for (;;) {
					FD_ZERO(&socks);
					FD_SET(psiStartInfo->hStdInput,&socks);
					FD_SET(out[1],&socks);
					FD_SET(err[1],&socks);

					int		action;
					int		highsock	= MAX(psiStartInfo->hStdInput, MAX(out[1], err[1]));
					struct timeval	timeout		= {10,0};

					switch (action = select(highsock+1, &socks, NULL, NULL, &timeout)) {
					case -1:
						break;
					case 0:
						logmsg(LOG_DEBUG, 1, "CPU Emulation - I/O spy timed out.\n");
						kill(child, SIGKILL);
exit_now:
						close(in[0]);
						close(out[1]);
						close(err[1]);

						logmsg(LOG_DEBUG, 1, "CPU Emulation - Creating virtual attack.\n");
						Attack *session;
						struct in_addr nulladdr;
						memset(&nulladdr, 0, sizeof(struct in_addr));
						if ((session = new_virtattack(nulladdr, nulladdr, 0, 0, 0)) == NULL) {
							logmsg(LOG_ERR, 1, "CPU Emulation Error - Unable to create virtual attack.\n");
							exit(EXIT_FAILURE);
						}

						session->a_conn.payload.data	= (u_char *) emu_string_char(io);
						session->a_conn.payload.size	= io->size;

						plughook_process_attack(funclist_attack_savedata, session);
						plughook_process_attack(funclist_attack_postproc, session);

						exit(EXIT_SUCCESS);
					default:
						if ( FD_ISSET(psiStartInfo->hStdInput, &socks) ) {
							int size = read(psiStartInfo->hStdInput, buf, 1024);
							if ( size > 0 ) write(in[0], buf, size);
							else goto exit_now;
							append(io, "in  >", buf, size);
						}
						if ( FD_ISSET(out[1], &socks) ) {
							int size = read(out[1], buf, 1024);
							if ( size > 0 ) write(psiStartInfo->hStdOutput, buf, size);
							else goto exit_now;
							append(io, "out <", buf, size);
						}
						if ( FD_ISSET(err[1], &socks) ) {
							int size = read(err[1], buf, 1024);
							if ( size > 0 ) write(psiStartInfo->hStdError, buf, size);
							else goto exit_now;
							append(io, "err <", buf, size);
						}
					}

				}
			}
		} else {
			// parent 
			pProcInfo->hProcess = spy;
		}
	}

	return 1;
}


uint32_t user_hook_WinExec(struct emu_env *env, struct emu_env_hook *hook, ...) {
	va_list 	vl;
	char		*path;

	va_start(vl, hook);

	path = va_arg(vl,  char *);

	va_end(vl);

	logmsg(LOG_NOISY, 1, "CPU Emulation - Hooking WinExec(%s) (ignored).\n", path);

	return 0;
}


uint32_t user_hook_accept(struct emu_env *env, struct emu_env_hook *hook, ...) {
	va_list 	vl;
	int		s, sockfd, flags;
	struct sockaddr	*saddr, daddr;
	socklen_t	*saddrlen, daddrlen;
	char		shost[16], dhost[16];
	fd_set		rfds;

#define INVALID_SOCKET	-1

	memset(shost, 0, 16);
	memset(dhost, 0, 16);

	va_start(vl, hook);

	s		= va_arg(vl,  int);
	saddr 		= va_arg(vl,  struct sockaddr *);
	saddrlen	= va_arg(vl,  socklen_t *);

	va_end(vl);

	logmsg(LOG_NOISY, 1, "CPU Emulation - Hooking accept(%d, %p, %p)\n", s, saddr, saddrlen);

	// set listening socket to non-blocking
	flags		 = 0;

	if ((flags = fcntl(s, F_GETFL, 0) < 0)) return(-1);
	if (fcntl(s, F_SETFL, flags | O_NONBLOCK) < 0) return(-1);

	// wait until listening socket is readable to make sure accept() does not block
	FD_ZERO(&rfds);
	FD_SET(sigpipe[0], &rfds);
	FD_SET(s, &rfds);

	switch (select(MAX(s, sigpipe[0])+1, &rfds, NULL, NULL, NULL)) {
	case -1:
		if (errno == EINTR) {
			if (check_sigpipe() == -1) return INVALID_SOCKET;
			break;
		}
		logmsg(LOG_DEBUG, 1, "CPU Emulation Error - Signal-aware select() failed: %s.\n", strerror(errno));
		return INVALID_SOCKET;
	default:
		if (FD_ISSET(sigpipe[0], &rfds) && (check_sigpipe() == -1)) return INVALID_SOCKET;
	}

	if (!FD_ISSET(s, &rfds)) {
		logmsg(LOG_DEBUG, 1, "CPU Emulation Error - Signal-aware select() returned, but socket is not readable.\n");
		return INVALID_SOCKET;
	}

	// accept() shouldn't block now
	if ((sockfd = accept(s, saddr, saddrlen)) == -1) {
		switch (errno) {
		case EWOULDBLOCK:
		case ECONNABORTED:
		case EPROTO:
			// ignore these for a non-blocking accept
			break;
		default:
			logmsg(LOG_ERR, 1, "CPU Emulation Error - accept() failed: %s.\n", strerror(errno));
			return INVALID_SOCKET;
		}
	}

	daddrlen = sizeof(struct sockaddr);
	if (getsockname(sockfd,&daddr, &daddrlen) == -1) {
		logmsg(LOG_ERR, 1, "CPU Emulation Error - Unable to get peer information: %s.\n", strerror(errno));
		return INVALID_SOCKET;
	}
	if (getpeername(sockfd,saddr, saddrlen) == -1) {
		logmsg(LOG_ERR, 1, "CPU Emulation Error - Unable to get peer information: %s.\n", strerror(errno));
		return INVALID_SOCKET;
	}

	if ((inet_ntop(AF_INET, &((struct sockaddr_in *)saddr)->sin_addr, shost, 16) == NULL) ||
	    (inet_ntop(AF_INET, &((struct sockaddr_in *)&daddr)->sin_addr, dhost, 16) == NULL)) {
		logmsg(LOG_ERR, 1, "CPU Emulation Error - Unable to convert IP address: %s.\n", strerror(errno));
		return INVALID_SOCKET;
	} 

	logmsg(LOG_NOISY, 1, "CPU Emulation - Connection accepted: %s:%u <- %s:%u.\n", 
		shost, ntohs(((struct sockaddr_in *)saddr)->sin_port), 
		dhost, ntohs(((struct sockaddr_in *)&daddr)->sin_port));

	// restore socket flags
	if (fcntl(s, F_SETFL, flags) < 0) return(-1);

	return sockfd;
}

uint32_t user_hook_closesocket(struct emu_env *env, struct emu_env_hook *hook, ...) {
	va_list vl;
	int s;

	va_start(vl, hook);

	s = va_arg(vl,  int);

	va_end(vl);

	logmsg(LOG_NOISY, 1, "CPU Emulation - Hooking closesocket(%d)\n", s);

	return close(s);
}

uint32_t user_hook_listen(struct emu_env *env, struct emu_env_hook *hook, ...) {
	va_list	vl;
	int	s, backlog;

	va_start(vl, hook);

	s	= va_arg(vl,  int);
	backlog	= va_arg(vl,  int);

	va_end(vl);

	logmsg(LOG_NOISY, 1, "CPU Emulation - Hooking listen(%d, %d)\n", s, backlog);

	return listen(s, backlog);
}

uint32_t user_hook_recv(struct emu_env *env, struct emu_env_hook *hook, ...) {
	va_list	vl;
	int	s, len, flags;
	char	*buf;

	va_start(vl, hook);

	s	= va_arg(vl,  int);
	buf	= va_arg(vl,  char *);
	len	= va_arg(vl,  int);
	flags	= va_arg(vl,  int);

	va_end(vl);

	logmsg(LOG_NOISY, 1, "CPU Emulation - Hooking recv(%d, %p, %d, %d)\n", s, buf, len, flags);

	return recv(s, buf, len,  flags);
}

uint32_t user_hook_send(struct emu_env *env, struct emu_env_hook *hook, ...) {
	va_list	vl;
	int	s, len, flags;
	char	*buf;

	va_start(vl, hook);

	s	= va_arg(vl,  int);
	buf	= va_arg(vl,  char *);
	len	= va_arg(vl,  int);
	flags	= va_arg(vl,  int);

	va_end(vl);

	logmsg(LOG_NOISY, 1, "CPU Emulation - Hooking send(%d, %p, %d, %d)\n", s, buf, len, flags);

	return send(s, buf, len,  flags);
}

uint32_t user_hook_exit(struct emu_env *env, struct emu_env_hook *hook, ...) {
	va_list	vl;
	int	code;

	va_start(vl, hook);

	code = va_arg(vl,  int);

	va_end(vl);

	logmsg(LOG_NOISY, 1, "CPU Emulation - Hooking exit(%d)\n", code);

	opts.steps = 0;

	return 0;
}

uint32_t user_hook_fclose(struct emu_env *env, struct emu_env_hook *hook, ...) {
	va_list vl;

	va_start(vl, hook);

	FILE *f = va_arg(vl, FILE *);

	va_end(vl);

	logmsg(LOG_NOISY, 1, "CPU Emulation - Hooking fclose(%p)\n", f);

	struct nanny_file *nf = nanny_get_file(hook->hook.win->userdata, (uint32_t)(uintptr_t)f);

	if (nf != NULL) {
		FILE *f = nf->real_file;
		nanny_del_file(hook->hook.win->userdata, (uint32_t)(uintptr_t)f);
		return fclose(f);
	}

	return 0;
}


uint32_t user_hook_fopen(struct emu_env *env, struct emu_env_hook *hook, ...) {
	va_list 	vl;
	int		fd;
	char		*localfile;
	FILE		*f;
	uint32_t	file;

	va_start(vl, hook);

	char *filename			= va_arg(vl,  char *);
	char *mode 			= va_arg(vl,  char *);

	va_end(vl);

	logmsg(LOG_NOISY, 1, "CPU Emulation - Hooking fopen(%s, %s)\n", filename, mode);

	if (asprintf(&localfile, "/tmp/%s-XXXXXX",filename) == -1) {
		logmsg(LOG_ERR, 1, "CPU Emulation Error - Unable to allocate memory: %s.\n", strerror(errno));
		return 0;
	}

	if ((fd = mkstemp(localfile)) == -1) {
		logmsg(LOG_ERR, 1, "CPU Emulation Error - Unable to create temporary file: %s.\n", strerror(errno));
		return 0;
	}
	if ((f = fdopen(fd, "w")) == NULL) {
		logmsg(LOG_ERR, 1, "CPU Emulation Error - Unable to reopen file as stream: %s.\n", strerror(errno));
		return 0;
	}
	close(fd);

	nanny_add_file(hook->hook.win->userdata, localfile, &file, f);

	return file;
}

uint32_t user_hook_fwrite(struct emu_env *env, struct emu_env_hook *hook, ...) {
	va_list vl;

	va_start(vl, hook);
	void *data = va_arg(vl, void *);
	size_t size = va_arg(vl, size_t);
	size_t nmemb = va_arg(vl, size_t);
	FILE *f = va_arg(vl, FILE *);

	va_end(vl);

	logmsg(LOG_NOISY, 1, "CPU Emulation - Hooking fwrite(%p, %lu, %lu, %p)\n",
		data, (long unsigned int) size, (long unsigned int) nmemb, f);

	struct nanny_file *nf = nanny_get_file(hook->hook.win->userdata, (uint32_t)(uintptr_t)f);

	if (nf != NULL)
		return fwrite(data, size, nmemb, nf->real_file);
	else 
		return size*nmemb;

}

uint32_t user_hook_CreateFile(struct emu_env *env, struct emu_env_hook *hook, ...) {
	va_list		vl;
	char		*localfile;
	uint32_t	handle;
	int		fd;
	FILE		*f;

#define INVALID_HANDLE_VALUE -1

	va_start(vl, hook);

	char *lpFileName			= va_arg(vl, char *);
	/*int dwDesiredAccess		=*/(void)va_arg(vl, int);
	/*int dwShareMode			=*/(void)va_arg(vl, int);
	/*int lpSecurityAttributes	=*/(void)va_arg(vl, int);
	/*int dwCreationDisposition	=*/(void)va_arg(vl, int);
	/*int dwFlagsAndAttributes	=*/(void)va_arg(vl, int);
	/*int hTemplateFile			=*/(void)va_arg(vl, int);

	va_end(vl);

	logmsg(LOG_NOISY, 1, "CPU Emulation - Hooking CreateFile(%s, ...)\n", lpFileName);

	if (asprintf(&localfile, "/tmp/%s-XXXXXX", lpFileName) == -1) {
		logmsg(LOG_ERR, 1, "CPU Emulation Error - Unable to allocate memory: %s.\n", strerror(errno));
		return INVALID_HANDLE_VALUE;
	}

	if ((fd = mkstemp(localfile)) == -1) {
		logmsg(LOG_ERR, 1, "CPU Emulation Error - Unable to create temporary file: %s.\n", strerror(errno));
		return INVALID_HANDLE_VALUE;
	}
	if ((f = fdopen(fd, "w")) == NULL) {
		logmsg(LOG_ERR, 1, "CPU Emulation Error - Unable to reopen file as stream: %s.\n", strerror(errno));
		return INVALID_HANDLE_VALUE;
	}
	close(fd);

	nanny_add_file(hook->hook.win->userdata, localfile, &handle, f);

	return handle;
}

uint32_t user_hook_WriteFile(struct emu_env *env, struct emu_env_hook *hook, ...) {
	va_list vl;

	va_start(vl, hook);

	FILE *hFile 					= va_arg(vl, FILE *);
	void *lpBuffer 					= va_arg(vl, void *);
	int   nNumberOfBytesToWrite 	= va_arg(vl, int);
	/* int *lpNumberOfBytesWritten  =*/(void)va_arg(vl, int*);
	/* int *lpOverlapped 		    =*/(void)va_arg(vl, int*);

	va_end(vl);

	logmsg(LOG_NOISY, 1, "CPU Emulation - Hooking WriteFile(%p, %p, %d, ...)\n", hFile, lpBuffer, nNumberOfBytesToWrite);

	struct nanny_file *nf = nanny_get_file(hook->hook.win->userdata, (uint32_t)(uintptr_t)hFile);

	if (nf != NULL)
		fwrite(lpBuffer, nNumberOfBytesToWrite, 1, nf->real_file);
	else
		logmsg(LOG_NOISY, 1, "shellcode tried to write data to not existing handle\n");

	return 1;

}


uint32_t user_hook_CloseHandle(struct emu_env *env, struct emu_env_hook *hook, ...) {
	va_list vl;

	va_start(vl, hook);

	FILE *hObject = va_arg(vl, FILE *);

	va_end(vl);

	logmsg(LOG_NOISY, 1, "CPU Emulation - Hooking CloseHandle(%p)\n", hObject);

	struct nanny_file *nf = nanny_get_file(hook->hook.win->userdata, (uint32_t)(uintptr_t)hObject);

	if (nf != NULL) {
		FILE *f = nf->real_file;
		nanny_del_file(hook->hook.win->userdata, (uint32_t)(uintptr_t)hObject);
		fclose(f);
	} else
		logmsg(LOG_NOISY, 1, "shellcode tried to close not existing handle (maybe closed it already?)\n");

	return 0;
}

uint32_t user_hook_URLDownloadToFile(struct emu_env *env, struct emu_env_hook *hook, ...) {
	va_list vl;

	va_start(vl, hook);

	/*void * pCaller    = */(void)va_arg(vl, void *);
	char * szURL      = va_arg(vl, char *);
	char * szFileName = va_arg(vl, char *);
	/*int    dwReserved = */(void)va_arg(vl, int   );
	/*void * lpfnCB     = */(void)va_arg(vl, void *);

	va_end(vl);

	logmsg(LOG_NOISY, 1, "CPU Emulation - Hooking URLDownloadToFile(..., %s, %s, ...)\n", szURL, szFileName);

	return 0;
}

struct nanny *nanny_new()
{
	struct nanny *na = malloc(sizeof(struct nanny));
	memset(na, 0, sizeof(struct nanny));

	na->files = emu_hashtable_new(16, emu_hashtable_ptr_hash, emu_hashtable_ptr_cmp);

	return na;
}

struct nanny_file *nanny_add_file(struct nanny *na, const char *path, uint32_t *emu_file, FILE *real_file)
{
	struct nanny_file *file = malloc(sizeof(struct nanny_file));
	memset(file, 0, sizeof(struct nanny_file));

	*emu_file = rand();

	file->path = strdup(path);
	file->emu_file = *emu_file;
	file->real_file = real_file;

	emu_hashtable_insert(na->files, (void *)(uintptr_t)file->emu_file, file);

	return file;
}

struct nanny_file *nanny_get_file(struct nanny *na, uint32_t emu_file)
{
	 struct emu_hashtable_item *item = emu_hashtable_search(na->files, (void *)(uintptr_t)emu_file);
	 if (item != NULL)
	 {
		 struct nanny_file *file = item->value;
		 return file;
	 }else
		 return NULL;
	 
}

bool nanny_del_file(struct nanny *na, uint32_t emu_file)
{
	struct emu_hashtable_item *item = emu_hashtable_search(na->files, (void *)(uintptr_t)emu_file);
	if (item != NULL)
	{
		free(item->value);
	}
	return emu_hashtable_delete(na->files, (void *)(uintptr_t)emu_file);
}

void nanny_free(struct nanny *nanny) {
}
