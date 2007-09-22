/* $Id */

/********************************************************************************
 *
 * Copyright (C) 2006  Paul Baecher & Markus Koetter
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 * 
 * 
 *             contact nepenthesdev@users.sourceforge.net  
 *
 *******************************************************************************/

/*
 * CSPM preprocessor
 * Authors: Markus Koetter, Paul Baecher
 */

#include <string.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <stdio.h>

#include <logging.h>

#include "sc_action.h"
#include "sc_parser.h"
#include "sc_buffer.h"
#include "sc_shellcodes.h"
#include "connectback.h"

struct sc_action *sc_action_new()
{
	struct sc_action *sa = (struct sc_action *)malloc(sizeof(struct sc_action));
	memset(sa,0,sizeof(struct sc_action));
	return sa;
}

void sc_action_free(struct sc_action *sa)
{
	switch (sa->m_shellcode->nspace)
	{
	case sc_bindfiletransfer:
	case sc_bindshell:
	case sc_connectbackfiletransfer:
	case sc_connectbackshell:
		break;

	case sc_execute:
		if (sa->m_action.m_execute.m_command != NULL)
        	free(sa->m_action.m_execute.m_command);
		
		break;

	case sc_url:
		if (sa->m_action.m_url.m_link != NULL)
			free(sa->m_action.m_url.m_link);
		break;

	default:
		break;
	}
	free(sa);
}

void sc_action_shellcode_set(struct sc_action *sa, struct sc_shellcode *sc)
{
	sa->m_shellcode = sc;
	return;
}
void sc_action_host_set_local(struct sc_action *sa, uint32_t localhost)
{
	sa->m_localhost = localhost;
	return;
}

void sc_action_host_set_remote(struct sc_action *sa, uint32_t remotehost)
{
	sa->m_remotehost = remotehost;
	return;
}

void sc_action_action_set_connectback(struct sc_action *sa, uint32_t remotehost, uint16_t remoteport)
{
	sa->m_action.m_connectback.m_remotehost = remotehost;
	sa->m_action.m_connectback.m_remoteport = remoteport;
	return;
}

void sc_action_action_set_bind(struct sc_action *sa, uint16_t localport)
{
	sa->m_action.m_bind.m_localport = localport;
	return;
}

void sc_action_action_set_execute(struct sc_action *sa, const char *command)
{
	sa->m_action.m_execute.m_command = strdup(command);
	return;
}

void sc_action_action_set_url(struct sc_action *sa, const char *url)
{
	sa->m_action.m_url.m_link = strdup(url);
	return;
}


void sc_action_debug_print(struct sc_action *sa)
{
	int haskey = 0;
	int i = 0;

	for (i=0; i < sa->m_shellcode->map_items; i++) {
		if (sa->m_shellcode->map[i] == sc_key) {
			haskey = 1;
			break;
		}
	}

	switch (sa->m_shellcode->nspace) {
	case sc_bindfiletransfer:
	case sc_bindshell:
//		logmsg(LOG_INFO, 1, "CSPM - \tsa->m_action.m_bind.m_localport  = %i\n",sa->m_action.m_bind.m_localport);
		logmsg(LOG_DEBUG, 1, "CSPM - Preparing local port %u/tcp for bindshell.\n", sa->m_action.m_bind.m_localport);

		break;

	case sc_connectbackfiletransfer:
	case sc_connectbackshell:
//		logmsg(LOG_INFO, 1, "CSPM - \tsa->m_action.m_connectback.m_remotehost = %s\n",inet_ntoa(*(struct in_addr *)&sa->m_action.m_connectback.m_remotehost));;
//		printf("\tsa->m_action.m_connectback.m_remoteport = %i\n",sa->m_action.m_connectback.m_remoteport);
		if (haskey == 1)
		{
/*
			printf("\tsa->m_action.m_connectback.m_key = 0x%02x%02x%02x%02x\n",
				   ((unsigned char *)&sa->m_action.m_connectback.m_key)[0],
				   ((unsigned char *)&sa->m_action.m_connectback.m_key)[1],
				   ((unsigned char *)&sa->m_action.m_connectback.m_key)[2],
				   ((unsigned char *)&sa->m_action.m_connectback.m_key)[4]
				   );
*/
		}
		break;

	case sc_execute:
//		printf("\tsa->m_action.m_execute.m_command  = %s\n",sa->m_action.m_execute.m_command);;
		break;

	case sc_url:
//		printf("\tsa->m_action.m_url.m_link  = %s\n",sa->m_action.m_url.m_link);;
		break;

	default:
		break;
	}
	return;
}



void sc_action_process(struct sc_action *sa) {
	sc_action_debug_print(sa);

	int haskey = 1;

	BUFFER *buffer = buffer_new();

	buffer_write_u8(buffer,(uint8_t)sa->m_shellcode->nspace);
	switch (sa->m_shellcode->nspace) {
	case sc_bindfiletransfer:
	case sc_bindshell:
		buffer_write_u8(buffer, sc_port);
		buffer_write_u16(buffer,htons((uint16_t)sa->m_action.m_bind.m_localport));

		if ( haskey ) {
			buffer_write_u8(buffer,sc_key);
			buffer_write_u32(buffer,htonl((uint32_t)sa->m_action.m_bind.m_key));
		}
		break;

	case sc_connectbackfiletransfer:
	case sc_connectbackshell:
		buffer_write_u8(buffer,sc_host);
		buffer_write_u32(buffer,htonl((uint16_t)sa->m_action.m_connectback.m_remotehost));
		buffer_write_u8(buffer,sc_port);
		buffer_write_u16(buffer,htons((uint16_t)sa->m_action.m_connectback.m_remoteport));
		if ( haskey )
		{
			buffer_write_u8(buffer,sc_key);
			buffer_write_u32(buffer,htonl((uint32_t)sa->m_action.m_connectback.m_key));
		}
		connectback(sa, haskey);
		break;

	case sc_execute:
		buffer_write_u8(buffer,sc_command);
		buffer_write_u8(buffer,strlen(sa->m_action.m_execute.m_command));
		buffer_write_string(buffer,sa->m_action.m_execute.m_command);
		break;

	case sc_url:
		buffer_write_u8(buffer,sc_uri);
		buffer_write_u8(buffer,strlen(sa->m_action.m_url.m_link));
		buffer_write_string(buffer,sa->m_action.m_url.m_link);
		break;

	default:
		break;
	}

//	int size = buffer_write_size_get(buffer);

	// send here

	buffer_free(buffer);

	return;
}

