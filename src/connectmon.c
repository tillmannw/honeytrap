/* connectmon.c
 * Copyright (C) 2006-2007 Tillmann Werner <tillmann.werner@gmx.de>
 *
 * This file is free software; as a special exception the author gives
 * unlimited permission to copy and/or distribute it, with or without
 * modifications, as long as this notice is preserved.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
 * implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */

#include <errno.h>
#include <stdlib.h>

#include "honeytrap.h"
#include "connectmon.h"
#include "logging.h"
#include "dynsrv.h"
#include "ctrl.h"
#include "pcapmon.h"
#include "ipqmon.h"
#include "nfqmon.h"


int start_connection_monitor(void) {
	/* call connection monitor for activated type */
#ifdef USE_IPQ_MON
	start_ipq_mon();
#else
#ifdef USE_PCAP_MON
	start_pcap_mon();
#else
#ifdef USE_NFQ_MON
	start_nfq_mon();
#else
#ifdef USE_IPFW_MON
#endif
#endif
#endif
#endif
	return(1);
}
