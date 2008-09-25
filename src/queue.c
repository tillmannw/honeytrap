/* queue.c
 *
 * Copyright (C) 2007 Tillmann Werner <tillmann.werner@gmx.de>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "queue.h"

inline qelem *queue_prepend(queue *q, void *data) {
	qelem *new;
	
	if (!q || !data) return(NULL);

	if ((new = calloc(1, sizeof(qelem))) == NULL) return(NULL);
	new->data	= data;

	if (q->head) {
		q->head->prev	= new;
		new->next	= q->head;
	} else q->tail = new;

	new->prev	= NULL;
	q->head		= new;
	q->size++;

	return(new);
}


inline qelem *queue_append(queue *q, void *data) {
	qelem *new;
	
	if (!q || !data) return(NULL);

	if ((new = calloc(1, sizeof(qelem))) == NULL) return(NULL);
	new->data	= data;

	if (q->tail) {
		q->tail->next	= new;
		new->prev	= q->tail;
	} else q->head = new;

	new->next	= NULL;
	q->tail		= new;
	q->size++;

	return(new);
}


inline qelem *queue_cuthead(queue *q) {
	qelem *tmp;

	if (!q || q->head == NULL) return(NULL);

	tmp = q->head;
	q->head = q->head->next;
	if (q->head) q->head->prev = NULL;
	else q->tail = NULL;
	q->size--;

	return(tmp);
}


inline qelem *queue_cuttail(queue *q) {
	qelem *tmp;

	if (!q || q->tail == NULL) return(NULL);

	tmp = q->tail;
	q->tail = q->tail->prev;
	if (q->tail) q->tail->next = NULL;
	else q->head = NULL;
	q->size--;

	return(tmp);
}


qelem *queue_ins(queue *q, void *data, ssize_t max_size) {
	qelem* tmp = NULL;

	if (!q || !data) return(NULL);

	/* need to cut off last queue element? */
	if (q->size >= max_size) tmp = queue_cuttail(q);

	/* prepend new element */
	queue_prepend(q, data);

	return(tmp);
}


void *queue_unlink(queue *q, qelem *e) {
	void *data;

	if (!q || !e) return(NULL);

	if (e == q->head) {
		e = queue_cuthead(q);
	} else if (e == q->tail) {
		e = queue_cuttail(q);
	} else {
		e->prev->next = e->next;
		e->next->prev = e->prev;
		if (!q->size--) q->head = q->tail = NULL;
	}

	data = e->data;
	free(e);

	return(data);
}


queue *queue_new(void) {
	queue *q = calloc(1, sizeof(queue));

	return(q);
}


void queue_free(queue *q, void(*cbfn)(void *data)) {
	qelem *cur;

	if (!q) return;

	while (q->head) {
		cur = q->head;
		q->head = q->head->next;
		if (cbfn) cbfn(cur->data);
		free(cur);
	}

	free(q);

	return;
}
