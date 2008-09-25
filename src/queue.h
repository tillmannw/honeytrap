/* queue.h
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

#ifndef __HONEYTRAP_QUEUE_H
#define __HONEYTRAP_QUEUE_H 1

#if HAVE_CONFIG_H
# include <config.h>
#endif

typedef struct qelem {
	void		*data;
	struct qelem	*prev;
	struct qelem	*next;
} qelem;

typedef struct queue {
	ssize_t			size;
	qelem			*head;
	qelem			*tail;
} queue;


queue *queue_new(void);
void queue_free(queue *q, void(*cbfn)(void *data));
inline qelem *queue_append(queue *q, void *data);
inline qelem *queue_cuthead(queue *q);
qelem *queue_ins(queue *q, void *data, ssize_t max_size);
inline qelem *queue_cuttail(queue *q);
void *queue_unlink(queue *q, qelem *e);
inline qelem *queue_prepend(queue *q, void *data);

#endif
