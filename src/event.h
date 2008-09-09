/* event.h
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

#ifndef __HONEYTRAP_EVENT_H
#define __HONEYTRAP_EVENT_H 1

typedef struct event {
	time_t		time;
	struct event	*next;
	int		(*handler)(void);
} event;

event *eventlist;

event *event_enqueue(time_t time, int (*handler)(void));
event *event_dequeue(void);
time_t event_execute(void);

#endif
