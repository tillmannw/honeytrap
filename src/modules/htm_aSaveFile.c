/* htm_aSaveFile.c
 * Copyright (C) 2006 Tillmann Werner <tillmann.werner@gmx.de>
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
 *   This honeytrap module dumps incoming traffic from incoming
 *   connections to a file.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>

#include <ip.h>
#include <logging.h>
#include <honeytrap.h>
#include <md5.h>
#include <attack.h>
#include <plughook.h>

#include "htm_aSaveFile.h"

void plugin_init(void) {
	plugin_register_hooks();
	return;
}

void plugin_unload(void) {
	unhook(PPRIO_SAVEDATA, module_name, "save_to_file");
	return;
}

void plugin_register_hooks(void) {
	DEBUG_FPRINTF(stdout, "    Plugin %s: Registering hooks.\n", module_name);
	add_attack_func_to_list(PPRIO_SAVEDATA, module_name, "save_to_file", (void *) save_to_file);

	return;
}

int save_to_file(Attack *attack) {
	struct tm *file_time;
	time_t loc_time;
	char *filename, *mwfilename, *proto_str;
	int i, dumpfile_fd;

	filename	= NULL;
	mwfilename	= NULL;
	proto_str	= NULL;

	logmsg(LOG_DEBUG, 1, "Dumping attack string into file.\n");

	/* do not create file if no data was received */
	if (!attack->a_conn.payload.size) {
		logmsg(LOG_DEBUG, 1, "No data received, no need for dumpfile creation.\n");
		return(0);
	}

	/* create filename */
	if (attack->a_conn.protocol == TCP) proto_str = strdup("tcp");
	else if (attack->a_conn.protocol == UDP) proto_str = strdup("udp");
	else {
		logmsg(LOG_ERR, 1, "Error - Protocol %u is not supported.\n", attack->a_conn.protocol);
		return(-1);
	}

	if ((filename = (char *) malloc(strlen(attacks_dir) + strlen(proto_str) + 34)) == NULL) {
		logmsg(LOG_ERR, 1, "Error - Unable to allocate memory: %s\n", strerror(errno));
		return(-1);
	}
	bzero(filename, strlen(attacks_dir)+34);

	/* assemble filename */
	loc_time = time(NULL);
	if((file_time = localtime(&loc_time)) == NULL) {
		logmsg(LOG_WARN, 1, "Warning - Unable to get local time for filename.\n");
		sprintf(filename, "%s/from_port_%u-%s_%u", attacks_dir, attack->a_conn.l_port, proto_str, getpid());
	} else {
		sprintf(filename, "%s/from_port_%u-%s_%u_%04d-%02d-%02d", attacks_dir, attack->a_conn.l_port, proto_str,
			getpid(), file_time->tm_year+1900, file_time->tm_mon+1, file_time->tm_mday);
	}

	/* open file and set access rights */
	if ((dumpfile_fd = open(filename, O_WRONLY | O_CREAT | O_EXCL)) < 0) {
		logmsg(LOG_ERR, 1, "Error - Unable to save attack string in attacks directory: %s\n", strerror(errno));
		return(-1);
	}
	if (chmod(filename, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH) != 0)
		logmsg(LOG_WARN, 1, "Warning - Unable to set proper acces rights\n");


	/* write data to file */
	if (write(dumpfile_fd, attack->a_conn.payload.data, attack->a_conn.payload.size) != attack->a_conn.payload.size) {
		logmsg(LOG_ERR, 1, "Error - Unable to write attack string into file: %s\n", strerror(errno));
		close(dumpfile_fd);
		return(-1);
	}
	close(dumpfile_fd);
	logmsg(LOG_DEBUG, 1, "Plugin aSaveFile: Attack string saved as %s.\n", filename);

	/* save malware */
	for (i=1; i<=attack->dl_count; i++) {
		/* save file */
		/* we need the length of directory + "/" + filename plus md5 checksum */
		mwfilename = (char *) malloc(strlen(dlsave_dir)+strlen(filename)+35);
		snprintf(mwfilename, strlen(dlsave_dir)+strlen(mwfilename) + 35, "%s/%s-%s",
			dlsave_dir, mem_md5sum(attack->download[i].dl_payload.data, attack->download[i].dl_payload.size), mwfilename);
		logmsg(LOG_DEBUG, 1, "Malware sample dump - File name is %s\n", mwfilename);
		if (((dumpfile_fd = open(mwfilename, O_WRONLY | O_CREAT | O_EXCL)) < 0) ||
		    (fchmod(dumpfile_fd, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH) != 0)) {
			logmsg(LOG_WARN, 1, "Malware sample dump - Unable to save %s: %s.\n", mwfilename,
				strerror(errno));
			close(dumpfile_fd);
			return(-1);
		}
		if (write(dumpfile_fd, attack->download[i].dl_payload.data, attack->download[i].dl_payload.size) != attack->download[i].dl_payload.size) { 
			logmsg(LOG_ERR, 1, "Malware sample dump error - Unable to write data to file: %s\n",
				strerror(errno));
			close(dumpfile_fd);
			return(-1);
		}
		close(dumpfile_fd);
		logmsg(LOG_NOTICE, 1, "Malware sample dump - %s saved.\n", attack->download[i].filename);
	}

	return(0);
}
