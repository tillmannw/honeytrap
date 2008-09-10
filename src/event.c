/* event.c
 * Copyright (C) 2008 Tillmann Werner <tillmann.werner@gmx.de>
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
#include <string.h>

#include "event.h"
#include "honeytrap.h"
#include "logging.h"

event *event_enqueue(time_t time, int (*handler)(void)) {
	event *e, *new;

	// put new element in event queue
	if ((new = calloc(1, sizeof(event))) == NULL) {
		logmsg(LOG_ERR, 1, "Error - Unable to ceate event: %s.\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	new->time	= time;
	new->handler	= handler;

	for (e = eventlist; e && e->next && time > e->next->time; e = e->next);

	if (e) {
		new->next = e->next;
		e->next = new;
	} else eventlist = new;

	return NULL;
}

event *event_dequeue(void) {
	event *e = eventlist;

	if (e == NULL) return NULL;

	e		= eventlist;
	eventlist	= eventlist->next;

	return e;
}

time_t event_execute(void) {
	if (eventlist == NULL)
		// event list is empty, return 1 second as new timeout
		return 1;

	event *e = event_dequeue();

	if (e) {
		if (!e->handler()) logmsg(LOG_WARN, 1, "Warning - Event execution failed.\n");
		free(e);
	}

	// set timeout to (next_event - now) seconds
	return eventlist ? MAX(1, eventlist->time - time(0)) : 1;
}
