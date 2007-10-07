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


#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <string.h>

#include <pcre.h>

#include <logging.h>

//#include "sf_snort_packet.h"
//#include "sf_dynamic_preprocessor.h"
//#include "sf_snort_plugin_api.h"

#include "sc_shellcodes.h"
#include "sc_parser.h"
#include "sc_action.h"

extern struct sc_shellcode *sclist;
//extern DynamicPreprocessorData _dpd;

typedef uint8_t byte;

int prepare_sc(struct sc_shellcode *sc)
{
	const char * pcreEerror;
	int32_t pcreErrorPos;

	if ( (sc->compiled_pattern = pcre_compile(sc->pattern, PCRE_DOTALL, &pcreEerror, (int *)&pcreErrorPos, 0)) == NULL )
	{
		logmsg(LOG_ERR, 0, "    CSPM Error - Could not compile pattern \n\t\"%s\"\n\t Error:\"%s\" at Position %u", 
				sc->name, pcreEerror, pcreErrorPos);
		return 1;
	} else
	{
		logmsg(LOG_DEBUG, 0, "    CSPM - Shellcode signature %s::%s successfully loaded.\n",
			sc_get_namespace_by_numeric(sc->nspace), sc->name);
	}
	return 0;

}

sch_result eval_sc_mgr(void *data, uint32_t size, uint32_t remotehost, uint16_t remoteport, uint32_t localhost, uint16_t localport)
{
	if (size == 0) return SCH_NOTHING;

	unsigned char *cdata = (unsigned char *)malloc(size);
	uint32_t csize = size;
	memcpy(cdata,data,size);

	struct sc_shellcode *sc;

	for (sc=sclist;sc != NULL; ) {
		if (sc->name == NULL) {
			sc = sc->next;
			continue;
		}

		switch(eval_sc(sc,(void **)&cdata,&csize,remotehost,remoteport,localhost,localport)) {
		case SCH_DONE:
			 return SCH_DONE;

		 case SCH_NOTHING:
			 sc = sc->next;
			 break;

		case SCH_REPROCESS:
			sc=sclist;
			break;

		 case SCH_REPROCESS_BUT_NOT_ME:
			 break;
		}
	}
	free(cdata);
	return SCH_NOTHING;
}

sch_result eval_sc(struct sc_shellcode *sc, void **data, uint32_t *size, uint32_t remotehost, uint16_t remoteport, uint32_t localhost, uint16_t localport)
{
	
        switch(sc->nspace)
		{
		case sc_xor:
			return eval_xor(sc,data,size,remotehost,remoteport,localhost,localport);
			break;

		case sc_linkxor:
			return eval_linkxor(sc,data,size,remotehost,remoteport,localhost,localport);
			break;

		case sc_konstanzxor:
			return eval_konstanzxor(sc,data,size,remotehost,remoteport,localhost,localport);
			break;

		case sc_leimbachxor:
			break;

		case sc_connectbackshell:
			return eval_connectbackshell(sc,data,size,remotehost,remoteport,localhost,localport);
			break;

		case sc_connectbackfiletransfer:
			return eval_connectbackfiletransfer(sc,data,size,remotehost,remoteport,localhost,localport);
			break;

		case sc_bindshell:
			return eval_bindshell(sc,data,size,remotehost,remoteport,localhost,localport);
			break;

		case sc_execute:
			return eval_execute(sc,data,size,remotehost,remoteport,localhost,localport);
			break;

		case sc_download:
            break;

		case sc_url:
			return eval_url(sc,data,size,remotehost,remoteport,localhost,localport);
			break;

		case sc_bindfiletransfer:
			return eval_bindfiletransfer(sc,data,size,remotehost,remoteport,localhost,localport);
			break;

		case sc_base64:
            break;

		case sc_alphanumericxor:
			return eval_alphanumericxor(sc,data,size,remotehost,remoteport,localhost,localport);
            break;
		}
		return SCH_NOTHING;
	
}


sch_result eval_engine_unicode          (struct sc_shellcode *sc, void **data, uint32_t *size, uint32_t remotehost, uint16_t remoteport, uint32_t localhost, uint16_t localport)
{
	return SCH_NOTHING;
}

uint32_t eval_engine_unicode_unicodeLength(uint8_t *unicode, uint32_t len)
{
	return SCH_NOTHING;
}

uint32_t eval_engine_unicode_unicodeTryDecode(uint8_t *unicode, uint32_t len, uint8_t **decoded, uint32_t *decodedLength)
{
	return SCH_NOTHING;
}

sch_result eval_alphanumericxor         (struct sc_shellcode *sc, void **data, uint32_t *size, uint32_t remotehost, uint16_t remoteport, uint32_t localhost, uint16_t localport)
{

	char *shellcode = *data;
	uint32_t len = *size;

	int32_t ovec[10 * 3];
	int32_t matchCount; 

// data before xor
	const char  *preMatch   =   NULL;
	uint32_t    preSize     =   0;


// decoder
	const char  *decoderMatch=  NULL;
	uint32_t    decoderSize =   0;


// payload to xor
	const char  *payloadMatch  =   NULL;
	uint32_t    payloadSize    =   0;


// data after xor
	const char  *postMatch  =   NULL;
	uint32_t    postSize    =   0;




	if ( (matchCount = pcre_exec(sc->compiled_pattern, 0, (char *) shellcode, len, 0, 0, (int *)ovec, sizeof(ovec)/sizeof(int32_t))) > 0 ) {
		logmsg(LOG_NOISY, 1, "1 CSPM - Shellcode matches pattern '%s'.\n", sc->name);
		int32_t i;
		for ( i=0; i < sc->map_items; i++ )
		{
			if (sc->map[i] == sc_none)
					continue;

			const char *match = NULL;
			int matchSize = pcre_get_substring((char *) shellcode, (int *)ovec, (int)matchCount, i, &match);

			switch ( sc->map[i] )
			{

			case sc_pre:
				preMatch = match;
				preSize = matchSize;
				break;

			case sc_decoder:
				decoderMatch = match;
				decoderSize = matchSize;
				break;

			case sc_payload:
				payloadMatch = match;
				payloadSize = matchSize;
				break;

			case sc_post:
				postMatch = match;
				postSize = matchSize;
				break;

			default:
				logmsg(LOG_DEBUG, 1, "CSPM - %s not used mapping %s\n",sc->name, sc_get_mapping_by_numeric(sc->map[i]));
			}
		}


// create buffer for decoding part of the message
		byte *decodedMessage = (byte *)malloc(payloadSize);
		memset(decodedMessage,0x90,payloadSize);

		if (payloadSize % 2 != 0) payloadSize -=1;

		unsigned char mb;
		char lo, hi;
		unsigned int j;
		for (j=0;j<payloadSize;j+=2) {
			lo = (payloadMatch[j] - 1) ^ 0x41;
			hi = payloadMatch[j+1] & 0xf;
			mb = lo | (hi << 4);
			decodedMessage[j/2] = mb;
		}

		char *newshellcode = (char *)malloc(len*sizeof(char));
		memset(newshellcode,0x90,len);

// create the same message with stripped xor decoder

		// the pre section
		memcpy(newshellcode, preMatch, preSize);

		// the xor as 0x90 
		memset(newshellcode+preSize, 0x90, decoderSize);

		// the xor decoded data
		memcpy(newshellcode+preSize, decodedMessage, payloadSize/2);

		memcpy(newshellcode+preSize+payloadSize, postMatch, postSize);

		free(*data);

		*data = newshellcode;

		free(decodedMessage);

		pcre_free_substring(preMatch);
		pcre_free_substring(decoderMatch);
		pcre_free_substring(payloadMatch);
		pcre_free_substring(postMatch);

		return SCH_REPROCESS;
	}
	return SCH_NOTHING;
}

sch_result eval_base64 (struct sc_shellcode *sc, void **data, uint32_t *size, uint32_t remotehost, uint16_t remoteport, uint32_t localhost, uint16_t localport) {
	return SCH_NOTHING;
}

sch_result eval_bindfiletransfer        (struct sc_shellcode *sc, void **data, uint32_t *size, uint32_t remotehost, uint16_t remoteport, uint32_t localhost, uint16_t localport)
{
	char *shellcode = *data;
	uint32_t len = *size;

	int32_t ovec[10 * 3];
	int32_t matchCount; 

	// port
	const char  *portMatch	=  	NULL;
	uint16_t 	port		= 	0;
		

	// key
	const char  *keyMatch	=  	NULL;


	if ( (matchCount = pcre_exec(sc->compiled_pattern, 0, (char *) shellcode, len, 0, 0, (int *)ovec, sizeof(ovec)/sizeof(int32_t))) > 0 ) {
		if ( (matchCount = pcre_exec(sc->compiled_pattern, 0, (char *) shellcode, len, 0, 0, (int *)ovec, sizeof(ovec)/sizeof(int32_t))) > 0 ) {
			logmsg(LOG_NOISY, 1, "CSPM - Shellcode matches pattern '%s' (2).\n", sc->name);
			int32_t i;
			for ( i=0; i < sc->map_items; i++ ) {
				if (sc->map[i] == sc_none) continue;
				

				const char *match = NULL;
				pcre_get_substring((char *) shellcode, (int *)ovec, (int)matchCount, i, &match);

				switch ( sc->map[i] )
				{

				case sc_port:
					portMatch = match;
					port = *((uint16_t *)portMatch);
					port = ntohs(port);
					break;

				case sc_key:
					 keyMatch = match;
					 break;

				default:
					logmsg(LOG_DEBUG, 1, "CSPM - %s not used mapping %s\n",sc->name, sc_get_mapping_by_numeric(sc->map[i]));
				}

			}
		}

//		uint32_t host = remotehost;
		struct sc_action *sa = sc_action_new();
		sc_action_shellcode_set(sa,sc);
		sc_action_host_set_local(sa,localhost);
		sc_action_host_set_remote(sa,remotehost);
		sc_action_action_set_bind(sa,port);

		if (keyMatch != NULL) {
//			unsigned char *authKey = (unsigned char *)keyMatch;
			sa->m_action.m_bind.m_key = (unsigned int)*keyMatch;
		}

		sc_action_process(sa);
		sc_action_free(sa);

		pcre_free_substring(portMatch);
		pcre_free_substring(keyMatch);

		return SCH_DONE;
	}

	return SCH_NOTHING;
}

sch_result eval_bindshell               (struct sc_shellcode *sc, void **data, uint32_t *size, uint32_t remotehost, uint16_t remoteport, uint32_t localhost, uint16_t localport)
{
	char *shellcode = *data;
	uint32_t len = *size;

	int32_t ovec[10 * 3];
	int32_t matchCount; 

	int i;

	if ( (matchCount = pcre_exec(sc->compiled_pattern, 0, (char *) shellcode, len, 0, 0, (int *)ovec, sizeof(ovec)/sizeof(int32_t))) > 0 )
	{
        
		uint16_t port=0;
		for ( i=0; i < sc->map_items; i++ )
		{
			if ( sc->map[i] == sc_port )
			{
				const char * match;
				pcre_get_substring((char *) shellcode, (int *)ovec, (int)matchCount, 1, &match);
				port = ntohs(*(uint16_t *) match);
				pcre_free_substring(match);

				struct sc_action *sa = sc_action_new();
				sc_action_shellcode_set(sa,sc);
				sc_action_host_set_local(sa,localhost);
				sc_action_host_set_remote(sa,remotehost);
				sc_action_action_set_bind(sa,port);
				sc_action_process(sa);
				sc_action_free(sa);

			}
		}

		return SCH_DONE;
	}
	return SCH_NOTHING;
}

sch_result eval_connectbackfiletransfer (struct sc_shellcode *sc, void **data, uint32_t *size, uint32_t remotehost, uint16_t remoteport, uint32_t localhost, uint16_t localport)
{

	char *shellcode = *data;
	uint32_t len = *size;

	int32_t ovec[10 * 3];
	int32_t matchCount; 

	// host
	const char  *hostMatch	=	NULL;
	uint32_t 	host 		= 	0;

	// port
	const char  *portMatch	=  	NULL;
	uint16_t 	port		= 	0;
		

	// key
	const char  *keyMatch	=  	NULL;


	if ( (matchCount = pcre_exec(sc->compiled_pattern, 0, (char *) shellcode, len, 0, 0, (int *)ovec, sizeof(ovec)/sizeof(int32_t))) > 0 ) {
		if ( (matchCount = pcre_exec(sc->compiled_pattern, 0, (char *) shellcode, len, 0, 0, (int *)ovec, sizeof(ovec)/sizeof(int32_t))) > 0 ) {
			logmsg(LOG_NOISY, 1, "CSPM - Shellcode matches pattern '%s' (3).\n", sc->name);
			int32_t i;
			for ( i=0; i < sc->map_items; i++ ) {
				if (sc->map[i] == sc_none) continue;
				
				const char *match = NULL;
				pcre_get_substring((char *) shellcode, (int *)ovec, (int)matchCount, i, &match);

				switch ( sc->map[i] )
				{

				case sc_host:
					hostMatch = match;
					host = (uint32_t)*((uint32_t *)hostMatch);
					break;

				case sc_port:
					portMatch = match;
					port = *((uint16_t *)portMatch);
					port = ntohs(port);
					break;

				case sc_key:
					 keyMatch = match;
					 break;

				default:
					logmsg(LOG_DEBUG, 1, "CSPM - %s not used mapping %s\n",sc->name, sc_get_mapping_by_numeric(sc->map[i]));
				}

			}
		}

		struct sc_action *sa = sc_action_new();
		sc_action_shellcode_set(sa,sc);
		sc_action_host_set_local(sa,localhost);
		sc_action_host_set_remote(sa,remotehost);
		sc_action_action_set_connectback(sa,host,port);

		if (keyMatch != NULL) {
//			unsigned char *authKey = (unsigned char *)keyMatch;
			sa->m_action.m_connectback.m_key = (unsigned int)*keyMatch;
		}

		sc_action_process(sa);
		sc_action_free(sa);


		pcre_free_substring(hostMatch);
		pcre_free_substring(portMatch);
		pcre_free_substring(keyMatch);

		return SCH_DONE;
	}
	return SCH_NOTHING;
}

sch_result eval_connectbackshell        (struct sc_shellcode *sc, void **data, uint32_t *size, uint32_t remotehost, uint16_t remoteport, uint32_t localhost, uint16_t localport)
{

	char *shellcode = *data;
	uint32_t len = *size;

	int32_t ovec[10 * 3];
	int32_t matchCount; 

	// host
	const char  *hostMatch	=	NULL;
	uint32_t 	host 		= 	0;

	// port
	const char  *portMatch	=  	NULL;
	uint16_t 	port		= 	0;
		

	const char  *hkeyMatch	=	NULL;
	uint32_t 	hostKey 		= 	0;

	// port
	const char  *pkeyMatch	=  	NULL;
	uint16_t 	portKey		= 	0;


	if ( (matchCount = pcre_exec(sc->compiled_pattern, 0, (char *) shellcode, len, 0, 0, (int *)ovec, sizeof(ovec)/sizeof(int32_t))) > 0 )
	{
		if ( (matchCount = pcre_exec(sc->compiled_pattern, 0, (char *) shellcode, len, 0, 0, (int *)ovec, sizeof(ovec)/sizeof(int32_t))) > 0 )
		{
			logmsg(LOG_NOISY, 1, "CSPM - Shellcode matches pattern '%s' (4).\n", sc->name);
			int32_t i;
			for ( i=0; i < sc->map_items; i++ )
			{
				if (sc->map[i] == sc_none) continue;
				
				const char *match = NULL;
				pcre_get_substring((char *) shellcode, (int *)ovec, (int)matchCount, i, &match);

				switch ( sc->map[i] ) {

				case sc_host:
					hostMatch = match;
					break;

				case sc_hostkey:
					hkeyMatch = match;
					break;

				case sc_portkey:
					pkeyMatch = match;
					break;

				case sc_port:
					portMatch = match;
					break;

				default:
					logmsg(LOG_DEBUG, 1, "CSPM - %s not used mapping %s\n",sc->name, sc_get_mapping_by_numeric(sc->map[i]));
				}

			}
		}

		port = *((uint16_t *)portMatch);
		port = ntohs(port);

		host = (uint32_t)*((uint32_t *)hostMatch);

		if (hkeyMatch != NULL) {
			hostKey = *((uint32_t *)hkeyMatch);
			host = host ^ hostKey;
			pcre_free_substring(hkeyMatch);
		}

		if (pkeyMatch != NULL) {
			portKey = *((uint16_t *)pkeyMatch);
			port = port ^ portKey;
			pcre_free_substring(pkeyMatch);
		}
		
		pcre_free_substring(hostMatch);
		pcre_free_substring(portMatch);

		struct sc_action *sa = sc_action_new();
		sc_action_shellcode_set(sa,sc);
		sc_action_host_set_local(sa,localhost);
		sc_action_host_set_remote(sa,remotehost);
		sc_action_action_set_connectback(sa,host,port);
		sc_action_process(sa);
		sc_action_free(sa);

		return SCH_DONE;
	}

	return SCH_NOTHING;
}

sch_result eval_execute(struct sc_shellcode *sc, void **data, uint32_t *size, uint32_t remotehost, uint16_t remoteport, uint32_t localhost, uint16_t localport)
{

	char *shellcode = *data;
	uint32_t len = *size;

	int32_t ovec[10 * 3];
	int32_t matchCount; 


	if ((matchCount = pcre_exec(sc->compiled_pattern, 0, (char *) shellcode, len, 0, 0, (int *)ovec, sizeof(ovec)/sizeof(int32_t))) > 0)
	{
		 const char * match;


		 pcre_get_substring((char *) shellcode, (int *)ovec, (int)matchCount, 1, &match);

		 struct sc_action *sa = sc_action_new();
		 sc_action_shellcode_set(sa,sc);
		 sc_action_host_set_local(sa,localhost);
		 sc_action_host_set_remote(sa,remotehost);
		 sc_action_action_set_execute(sa,match);
		 sc_action_process(sa);
		 sc_action_free(sa);

		 pcre_free_substring(match);

		 return SCH_DONE;
	 }


	return SCH_NOTHING;
}

sch_result eval_konstanzxor             (struct sc_shellcode *sc, void **data, uint32_t *size, uint32_t remotehost, uint16_t remoteport, uint32_t localhost, uint16_t localport)
{

	char *shellcode = *data;
	uint32_t len = *size;

	int32_t ovec[10 * 3];
	int32_t matchCount; 

// size
	const char  *sizeMatch	=   NULL;
	uint16_t codeSize		= 	0;

// post
	const char  *postMatch	=   NULL;
	uint16_t 	postSize	= 	0;
	

	if ( (matchCount = pcre_exec(sc->compiled_pattern, 0, (char *) shellcode, len, 0, 0, (int *)ovec, sizeof(ovec)/sizeof(int32_t))) > 0 ) {
		logmsg(LOG_NOISY, 1, "CSPM - Shellcode matches pattern '%s' (5).\n", sc->name);
		int32_t i;
		for ( i=0; i < sc->map_items; i++ )
		{
			if (sc->map[i] == sc_none)
					continue;

			const char *match = NULL;
			int matchSize = pcre_get_substring((char *) shellcode, (int *)ovec, (int)matchCount, i, &match);

			switch ( sc->map[i] )
			{

			case sc_size:
				sizeMatch = match;
				codeSize = *(uint16_t *)match;
				break;

			case sc_post:
				postMatch = match;
				postSize = matchSize;
				break;

			default:
				logmsg(LOG_DEBUG, 1, "CSPM - %s not used mapping %s\n",sc->name, sc_get_mapping_by_numeric(sc->map[i]));
			}
		}


		if (codeSize > postSize )
		{
			postSize = codeSize;
		}

		byte *decodedMessage = (byte *)malloc((uint32_t)postSize);
		memcpy(decodedMessage,postMatch, (uint32_t)postSize);


		logmsg(LOG_DEBUG, 1, "CSPM - Found konstanzbot XOR decoder, size %i is %i bytes long.\n", codeSize,postSize);

		for( i = 0; i < postSize; i++ )
			decodedMessage[i] ^= (i+1);

		// recompose the message with our new shellcode.
		free(*data);
		*data = decodedMessage;

		free(decodedMessage);
		pcre_free_substring(postMatch);
		pcre_free_substring(sizeMatch);
	
		return SCH_REPROCESS;
	}

	return SCH_NOTHING;
}

sch_result eval_linkxor                 (struct sc_shellcode *sc, void **data, uint32_t *size, uint32_t remotehost, uint16_t remoteport, uint32_t localhost, uint16_t localport)
{

	char *shellcode = *data;
	uint32_t len = *size;

	int32_t ovec[10 * 3];
	int32_t matchCount; 

//	"\\xEB\\x15\\xB9(....)\\x81\\xF1(....)\\x5E\\x80\\x74\\x31\\xFF(.)\\xE2\\xF9\\xEB\\x05\\xE8\\xE6\\xFF\\xFF\\xFF(.*)";



// size
	const char  *sizeAMatch	=   NULL;
	uint32_t	sizeA 		= 	0;

	const char  *sizeBMatch	=	NULL;
	uint32_t	sizeB 		= 	0;

	uint32_t codeSize		= 	0;

// key
	const char *keyMatch	=	NULL;
	byte		byteKey		= 	0;


// data after xor
	const char  *postMatch  =   NULL;
	uint32_t    postSize    =   0;




	if ( (matchCount = pcre_exec(sc->compiled_pattern, 0, (char *) shellcode, len, 0, 0, (int *)ovec, sizeof(ovec)/sizeof(int32_t))) > 0 ) {
		logmsg(LOG_NOISY, 1, "CSPM - Shellcode matches pattern '%s' (6).\n", sc->name);
		int32_t i;
		for ( i=0; i < sc->map_items; i++ )
		{
			if (sc->map[i] == sc_none)
					continue;

			const char *match = NULL;
			int matchSize = pcre_get_substring((char *) shellcode, (int *)ovec, (int)matchCount, i, &match);

			switch ( sc->map[i] )
			{

			case sc_size:
				if (sizeAMatch == NULL) {
					sizeAMatch = match;
					sizeA = *((uint32_t *)match);
				} else {
					sizeBMatch = match;
					sizeB = *((uint32_t *)match);
				}
				break;

			case sc_key:
				keyMatch = match;
				byteKey = *(byte *)match;
				break;

			case sc_post:
				postMatch = match;
				postSize = matchSize;
				break;


			default:
				logmsg(LOG_DEBUG, 1, "CSPM - %s not used mapping %s\n",sc->name, sc_get_mapping_by_numeric(sc->map[i]));
			}
		}

		codeSize = sizeA ^ sizeB;
		logmsg(LOG_DEBUG, 1, "CSPM - Found linkbot XOR decoder, key 0x%02x, payload is 0x%04x bytes long.\n", byteKey, codeSize);
		
// create buffer for decoding part of the message
		byte *decodedMessage = (byte *)malloc(postSize);
		memcpy(decodedMessage, postMatch, postSize);



		if ( codeSize > postSize )
			logmsg(LOG_DEBUG, 1, "CSPM Warning - codeSize (%i) > postSize (%i), maybe broken xor?\n",codeSize,postSize);

		uint32_t j;
		for ( j = 0; j < codeSize && j < postSize; j++ )
			decodedMessage[j] ^= byteKey;

		free(*data);
		*data = decodedMessage;

		pcre_free_substring(sizeAMatch);
		pcre_free_substring(sizeBMatch);
		pcre_free_substring(keyMatch);
		pcre_free_substring(postMatch);

		return SCH_REPROCESS;
	}

	return SCH_NOTHING;
}

sch_result eval_url(struct sc_shellcode *sc, void **data, uint32_t *size, uint32_t remotehost, uint16_t remoteport, uint32_t localhost, uint16_t localport)
{

	char *shellcode = *data;
	uint32_t len = *size;

	int32_t ovec[10 * 3];
	int32_t matchCount; 
	const char *match;

	if ( (matchCount = pcre_exec(sc->compiled_pattern, 0, (char *) shellcode, len, 0, 0, (int *)ovec, sizeof(ovec)/sizeof(int32_t))) > 0 )
	{
		pcre_get_substring((char *) shellcode, (int *)ovec, (int)matchCount, 1, &match);

		struct sc_action *sa = sc_action_new();
		sc_action_shellcode_set(sa,sc);
		sc_action_host_set_local(sa,localhost);
		sc_action_host_set_remote(sa,remotehost);
		sc_action_action_set_url(sa,match);
		sc_action_process(sa);
		sc_action_free(sa);


		pcre_free_substring(match);
		return SCH_DONE;
	}

	return SCH_NOTHING;
}



sch_result eval_xor(struct sc_shellcode *sc, void **data, uint32_t *size, uint32_t remotehost, uint16_t remoteport, uint32_t localhost, uint16_t localport)
{
    char *shellcode = (char *)*data;
	uint32_t len = *size;

	int32_t ovec[10 * 3];
	int32_t matchCount; 

// data before xor
	const char  *preMatch   =   NULL;
	uint32_t    preSize     =   0;


// decoder
	const char  *decoderMatch=  NULL;
	uint32_t    decoderSize =   0;



// key
	const char  *keyMatch   =   NULL;
	char        byteKey     =   0;
	uint32_t    intKey      =   0;
	uint32_t    keySize     =   0;


// 'data to xor' size
	const char  *sizeMatch  =   NULL;
	uint32_t    codeSize    =   0;


// data after xor
	const char  *postMatch  =   NULL;
	uint32_t    postSize    =   0;




	if ( (matchCount = pcre_exec(sc->compiled_pattern, 0, (char *) shellcode, len, 0, 0, (int *)ovec, sizeof(ovec)/sizeof(int32_t))) > 0 ) {
		logmsg(LOG_NOISY, 1, "CSPM - Shellcode matches pattern '%s' (7).\n", sc->name);
		int32_t i;
		for ( i=0; i < sc->map_items; i++ ) {
			if (sc->map[i] == sc_none) continue;

			const char *match = NULL;
			int matchSize = pcre_get_substring((char *) shellcode, (int *)ovec, (int)matchCount, i, &match);

			switch ( sc->map[i] )
			{

			case sc_pre:
				preMatch = match;
				preSize = matchSize;
				break;

			case sc_decoder:
				decoderMatch = match;
				decoderSize = matchSize;
				break;


			case sc_size:
				sizeMatch = match;
				switch ( matchSize ) {
				case 4:
					codeSize = (uint32_t)*((uint32_t *)match);
					break;

				case 2:
					codeSize = (uint32_t)*((uint16_t *)match);
					break;

				case 1:
					codeSize = (uint32_t)*((byte *)match);
					break;
				}
				break;


			case sc_sizeinvert:
				sizeMatch = match;
				switch ( matchSize ) {
				case 4:
					codeSize = 0 - (uint32_t)*((uint32_t *)match);
					break;

				case 1:
					codeSize = 256 - (uint32_t)*((byte *)match);
					break;
				}
				break;

			case sc_key:
				keyMatch = match;
				keySize = matchSize;
				switch ( matchSize )
				{
				case 1:
					byteKey = *((byte *)match);
					break;

				case 4:
					intKey = *((uint32_t *)match);
					break;

				}
				break;

			case sc_post:
				postMatch = match;
				postSize = matchSize;
				break;


			default:
				logmsg(LOG_DEBUG, 1, "CSPM - %s not used mapping %s\n", sc->name, sc_get_mapping_by_numeric(sc->map[i]));
			}
		}


// create buffer for decoding part of the message
		byte *decodedMessage = (byte *)malloc(postSize);
		memcpy(decodedMessage, postMatch, postSize);

		uint32_t j;
		switch ( keySize )
		{
		case 1:
			if ( codeSize > postSize )
				logmsg(LOG_DEBUG, 1, "CSPM Warning - codeSize (%i) > postSize (%i), maybe broken xor?\n",codeSize,postSize);


			for ( j = 0; j < codeSize && j < postSize; j++ )
				decodedMessage[j] ^= byteKey;
			break;

		case 4:
			if ( codeSize*4 > postSize )
				logmsg(LOG_DEBUG, 1, "CSPM Warning - codeSize (%i) > postSize (%i), maybe broken xor?\n",codeSize,postSize);

			for ( j = 0; j < codeSize && (j+1)*4 < postSize; j++ )
				*(uint32_t *)(decodedMessage+(j*4) ) ^= intKey;
			break;
		}

		char *newshellcode = (char *)malloc(len*sizeof(char));
		memset(newshellcode,0x90,len);

// create the same message with stripped xor decoder

		// the pre section
		memcpy(newshellcode                         ,preMatch       ,preSize);

		// the xor as 0x90 
		memset(newshellcode+preSize                 ,0x90           ,decoderSize);

		// the xor decoded data
		memcpy(newshellcode+preSize+decoderSize     ,decodedMessage ,postSize);

//		g_Nepenthes->getUtilities()->hexdump(l_crit,(byte *)newshellcode, len);			


		free(*data);

		*data = newshellcode;

		free(decodedMessage);
        
		pcre_free_substring(preMatch);
		pcre_free_substring(decoderMatch);
		pcre_free_substring(keyMatch);
		pcre_free_substring(sizeMatch);
		pcre_free_substring(postMatch);

		return SCH_REPROCESS;
	}
	return SCH_NOTHING;
}








