/*
 * Copyright(c) 2007 Intel Corporation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef _LIBSA_SA_STATE_H_
#define _LIBSA_SA_STATE_H_

/*
 * State transition table handling.
 */
struct sa_state_table;

/*
 * State transition description.
 * There are the following entry types:
 * - END simply indicates the end of the table.
 * - STATE gives the number and name of a state.
 * - EVENT gives the number and name of an event
 * - HANDLER gives the number and function pointer to a handler.
 * - FROM sets the current state.
 * - NEXT gives a state transition from the current state on.
 * a given event; the next state and/or a handler to call are given.
 *
 * A handler can also be associated with a particular state, in which
 * case the handler will be called on every entry to the state.
 */
struct sa_state_desc {
	enum {
		SST_END,	/* end of table */
		SST_STATE,	/* state definition */
		SST_EVENT,	/* event definition */
		SST_HANDLER,	/* handler */
		SST_FROM,	/* old state definition */
		SST_NEXT,	/* state transition definition */
	} sd_type;
	u_char	sd_in;		/* event or state number */
	u_char	sd_next;	/* next state number */
	const char *sd_ptr;	/* name of state or event or function or NULL */
};

typedef void (sa_state_handler_t)(void *arg, u_int next_state, u_int event);

/*
 * Convenience macros for filling in descriptors.
 */

/**
 * SA_STATE_LABEL(state, name) - declare a state name and number.
 *
 * @param state symbol with value of state.
 * @param name human-readable name for state.
 *
 * This sets the current state for the following state event initializations.
 */
#define SA_STATE_LABEL(state, name) { \
        .sd_type = SST_STATE, .sd_ptr = name, .sd_in = state }

/**
 * SA_STATE_NAME(state) - declare a state name and number.
 *
 * @param state symbol with value of state, also used for state name
 *
 * This sets the current state for the following state event initializations.
 */
#define SA_STATE_NAME(state) SA_STATE_LABEL(state, #state)

/**
 * SA_STATE_HANDLER(state, handler) - declare function to handle entry to state.
 *
 * @param state the state number.
 * @param handler the handler function pointer.
 */
#define SA_STATE_HANDLER(state, handler) { \
        .sd_type = SST_HANDLER, .sd_ptr = (void *) handler, .sd_in = state }

/*
 * SA_STATE_EVENT(event)
 *
 * @param event symbol with value of event, also used for the event name.
 *
 * This declares an event which can be used in the state transition table.
 */
#define SA_STATE_EVENT(event) { \
        .sd_type = SST_EVENT, .sd_ptr = #event, .sd_in = event }

/**
 * SA_STATE_FROM(val) - set the state number for subsequent SA_STATE_NEXT*()s.
 */
#define SA_STATE_FROM(val) {            /* not really needed */ \
        .sd_type = SST_STATE, .sd_in = val }

/**
 * SA_STATE_NEXT_FUNC(event, next, handler) - declare transition entry.
 *
 * @param event the event number.
 * @param next the state to which to transition.
 * @param handler a pointer to a function to call before the transition.
 */
#define SA_STATE_NEXT_FUNC(event, next, handler) { \
        .sd_type = SST_NEXT, .sd_in = event, .sd_next = next, \
        .sd_ptr = (void *) handler }

/**
 * SA_STATE_NEXT(event, next) - declare transition entry.
 *
 * @param event the event number.
 * @param next the state to which to transition.
 */
#define SA_STATE_NEXT(event, next)  SA_STATE_NEXT_FUNC(event, next, NULL)

/**
 * SA_STATE_END - declare end of state table description.
 */
#define SA_STATE_END    { .sd_type = SST_END }

/*
 * State transition table initialization.
 */
struct sa_state_table *sa_state_table_alloc(const char *name,
					    const struct sa_state_desc
					    *state_desc);

/*
 * Free state table.
 */
void sa_state_table_free(struct sa_state_table *);

/*
 * Handle event for a state transition table.
 */
void sa_state_table_step(struct sa_state_table *tp, void *statep,
			 u_int event, void *arg);

/*
 * Transition to the specified state.  Run the handler if any.
 */
void sa_state_table_enter(struct sa_state_table *, void *statep,
			  u_int new_state, u_int event, void *arg);

/**
 * sa_state_table_log() - set function to log state table transitions.
 */
void sa_state_table_log(struct sa_state_table *tp,
			void (*log_func) (void *arg, const char *msg));

const char *sa_state_event_name(struct sa_state_table *, u_int);
const char *sa_state_name(struct sa_state_table *, u_int);

#endif /* _LIBSA_SA_STATE_H_ */
