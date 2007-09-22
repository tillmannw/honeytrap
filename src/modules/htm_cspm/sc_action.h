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
 *
 */

#ifndef HAVE_SC_ACTION_H
#define HAVE_SC_ACTION_H

#include "sc_shellcodes.h"

struct sc_action
{
	struct sc_shellcode *m_shellcode;

	union
	{
		struct
		{
			uint32_t m_remotehost;
			uint16_t m_remoteport;
			uint32_t m_key;
		}m_connectback;

		struct
		{
			uint16_t m_localport;
			uint32_t m_key;
		}m_bind;

		struct
		{
			char *m_command;
		}m_execute;

		struct
		{
			char *m_link;
		}m_url;

	} m_action;

	uint32_t m_localhost;
	uint32_t m_remotehost;

};

struct sc_action *sc_action_new();
void sc_action_free(struct sc_action *sa);

void sc_action_shellcode_set(struct sc_action *sa,struct sc_shellcode *sc);
void sc_action_host_set_local(struct sc_action *sa, uint32_t localhost);
void sc_action_host_set_remote(struct sc_action *sa, uint32_t remotehost);
void sc_action_action_set_connectback(struct sc_action *sa, uint32_t remotehost, uint16_t remoteport);
void sc_action_action_set_bind(struct sc_action *sa, uint16_t localport);
void sc_action_action_set_execute(struct sc_action *sa, const char *command);
void sc_action_action_set_url(struct sc_action *sa, const char *url);
void sc_action_debug_print(struct sc_action *sa);

void sc_action_process(struct sc_action *sa);

#endif // HAVE_SC_ACTION_H
