/*
 * Copyright (c) 2018, Yaler GmbH, Oberon microsystems AG, Switzerland
 * All rights reserved
 *
 * See RFC 7159, http://www.rfc-editor.org/rfc/rfc7159.txt
 */

#include <assert.h>

#include "json_reader_utils.h"

#define STATE_READING_OBJECT 0
#define STATE_READING_ARRAY 1

#define SUBSTATE_EXPECTING_VALUE 0
#define SUBSTATE_READING_VALUE 1
#define SUBSTATE_COMPLETED_VALUE 2

#define SUBSTATE_EXPECTING_NAME 3
#define SUBSTATE_READING_NAME 4
#define SUBSTATE_COMPLETED_NAME 5

void json_reader_context_init(struct json_reader_context *c) {
		assert(c != NULL);
		c->state = JSON_READER_CONETXT_STATE_READING_VALUE;
		c->substate = SUBSTATE_EXPECTING_VALUE;
		c->stack = 0;
		c->stack_depth = 0;
}

/*
 * Stack of boolean values. Implementation based on Jurg Nievergelt and Klaus
 * Hinrichs, "Algorithms & Data Structures", 1993, Prentice-Hall, Inc.
 */

static int stack_is_empty(struct json_reader_context *c) {
		assert(c != NULL);
		return c->stack_depth == 0;
}

static int stack_is_full(struct json_reader_context *c) {
		assert(c != NULL);
		return c->stack_depth == (sizeof c->stack) * 8;
}

static int stack_top(struct json_reader_context *c) {
		assert(c != NULL);
		assert(c->stack_depth != 0);
		return (c->stack & 1) == 1;
}

static void stack_push(struct json_reader_context *c, int value) {
		assert(c != NULL);
		assert(c->stack_depth != (sizeof c->stack) * 8);
		if (value) {
			c->stack = (c->stack << 1) | 1;
		} else {
			c->stack = (c->stack << 1) | 0;
		}
		c->stack_depth++;
}

static void stack_pop(struct json_reader_context *c) {
		assert(c != NULL);
		assert(c->stack_depth != 0);
		c->stack = c->stack >> 1;
		c->stack_depth--;
}

size_t json_reader_utils_skip_value(
	struct json_reader *r,
	struct json_reader_context *c,
	char *buffer, size_t length)
{
	size_t n;
	assert(r != NULL);
	assert(c != NULL);
	assert(buffer != NULL);
	n = 0;
	if (n < length) {
		do {
			switch (c->state) {
			case JSON_READER_CONETXT_STATE_READING_VALUE:
				n += json_reader_read(r, &buffer[n], length - n);
				assert(n <= length);
				switch (r->state) {
				case JSON_READER_STATE_READING_WHITESPACE:
					assert(n == length);
					break;
				case JSON_READER_STATE_BEGINNING_OBJECT:
					if (c->substate == SUBSTATE_EXPECTING_VALUE) {
						if (!stack_is_full(c)) {
							stack_push(c, STATE_READING_OBJECT);
							c->substate = SUBSTATE_EXPECTING_NAME;
						} else {
							c->state = JSON_READER_CONETXT_STATE_STRUCTURE_TOO_DEEP;
						}
					} else {
						c->state = JSON_READER_CONETXT_STATE_STRUCTURE_INVALID;
					}
					break;
				case JSON_READER_STATE_BEGINNING_ARRAY:
					if (c->substate == SUBSTATE_EXPECTING_VALUE) {
						if (!stack_is_full(c)) {
							stack_push(c, STATE_READING_ARRAY);
							c->substate = SUBSTATE_EXPECTING_VALUE;
						} else {
							c->state = JSON_READER_CONETXT_STATE_STRUCTURE_TOO_DEEP;
						}
					} else {
						c->state = JSON_READER_CONETXT_STATE_STRUCTURE_INVALID;
					}
					break;
				case JSON_READER_STATE_BEGINNING_STRING:
					if (c->substate == SUBSTATE_EXPECTING_VALUE) {
						c->substate = SUBSTATE_READING_VALUE;
					} else if (c->substate == SUBSTATE_EXPECTING_NAME) {
						c->substate = SUBSTATE_READING_NAME;
					} else {
						c->state = JSON_READER_CONETXT_STATE_STRUCTURE_INVALID;
					}
					break;
				case JSON_READER_STATE_BEGINNING_NUMBER:
				case JSON_READER_STATE_BEGINNING_FALSE:
				case JSON_READER_STATE_BEGINNING_TRUE:
				case JSON_READER_STATE_BEGINNING_NULL:
					if (c->substate == SUBSTATE_EXPECTING_VALUE) {
						c->substate = SUBSTATE_READING_VALUE;
					} else {
						c->state = JSON_READER_CONETXT_STATE_STRUCTURE_INVALID;
					}
					break;
				case JSON_READER_STATE_READING_STRING:
				case JSON_READER_STATE_READING_NUMBER:
				case JSON_READER_STATE_READING_FALSE:
				case JSON_READER_STATE_READING_TRUE:
				case JSON_READER_STATE_READING_NULL:
					assert(n == length);
					break;
				case JSON_READER_STATE_COMPLETED_OBJECT:
					if (c->substate == SUBSTATE_EXPECTING_NAME) {
						assert(!stack_is_empty(c));
						assert(stack_top(c) == STATE_READING_OBJECT);
						stack_pop(c);
						c->substate = SUBSTATE_COMPLETED_VALUE;
						if (stack_is_empty(c)) {
							c->state = JSON_READER_CONETXT_STATE_COMPLETED_VALUE;
						}
					} else if (c->substate == SUBSTATE_COMPLETED_VALUE) {
						assert(!stack_is_empty(c));
						if (stack_top(c) == STATE_READING_OBJECT) {
							stack_pop(c);
							c->substate = SUBSTATE_COMPLETED_VALUE;
							if (stack_is_empty(c)) {
								c->state = JSON_READER_CONETXT_STATE_COMPLETED_VALUE;
							}
						} else {
							c->state = JSON_READER_CONETXT_STATE_STRUCTURE_INVALID;
						}
					} else {
						c->state = JSON_READER_CONETXT_STATE_STRUCTURE_INVALID;
					}
					break;
				case JSON_READER_STATE_COMPLETED_ARRAY:
					if ((c->substate == SUBSTATE_EXPECTING_VALUE)
						|| (c->substate == SUBSTATE_COMPLETED_VALUE))
					{
						assert(!stack_is_empty(c));
						if (stack_top(c) == STATE_READING_ARRAY) {
							stack_pop(c);
							c->substate = SUBSTATE_COMPLETED_VALUE;
							if (stack_is_empty(c)) {
								c->state = JSON_READER_CONETXT_STATE_COMPLETED_VALUE;
							}
						} else {
							c->state = JSON_READER_CONETXT_STATE_STRUCTURE_INVALID;
						}
					} else {
						c->state = JSON_READER_CONETXT_STATE_STRUCTURE_INVALID;
					}
					break;
				case JSON_READER_STATE_COMPLETED_STRING:
					if (c->substate == SUBSTATE_READING_VALUE) {
						c->substate = SUBSTATE_COMPLETED_VALUE;
						if (stack_is_empty(c)) {
							c->state = JSON_READER_CONETXT_STATE_COMPLETED_VALUE;
						}
					} else {
						assert(c->substate == SUBSTATE_READING_NAME);
						c->substate = SUBSTATE_COMPLETED_NAME;
					}
					break;
				case JSON_READER_STATE_COMPLETED_NUMBER:
				case JSON_READER_STATE_COMPLETED_FALSE:
				case JSON_READER_STATE_COMPLETED_TRUE:
				case JSON_READER_STATE_COMPLETED_NULL:
					assert(c->substate == SUBSTATE_READING_VALUE);
					c->substate = SUBSTATE_COMPLETED_VALUE;
					if (stack_is_empty(c)) {
						c->state = JSON_READER_CONETXT_STATE_COMPLETED_VALUE;
					}
					break;
				case JSON_READER_STATE_AFTER_NAME_SEPARATOR:
					if (c->substate == SUBSTATE_COMPLETED_NAME) {
						c->substate = SUBSTATE_EXPECTING_VALUE;
					} else {
						c->state = JSON_READER_CONETXT_STATE_STRUCTURE_INVALID;
					}
					break;
				case JSON_READER_STATE_AFTER_VALUE_SEPARATOR:
					if (c->substate == SUBSTATE_COMPLETED_VALUE) {
						assert(!stack_is_empty(c));
						if (stack_top(c) == STATE_READING_OBJECT) {
							c->substate = SUBSTATE_EXPECTING_NAME;
						} else {
							assert(stack_top(c) == STATE_READING_ARRAY);
							c->substate = SUBSTATE_EXPECTING_VALUE;
						}
					} else {
						c->state = JSON_READER_CONETXT_STATE_STRUCTURE_INVALID;
					}
					break;
				case JSON_READER_STATE_ERROR:
					c->state = JSON_READER_CONETXT_STATE_STRUCTURE_INVALID;
					break;
				default:
					assert(0);
					break;
				}
				break;
			case JSON_READER_CONETXT_STATE_COMPLETED_VALUE:
			case JSON_READER_CONETXT_STATE_STRUCTURE_INVALID:
			case JSON_READER_CONETXT_STATE_STRUCTURE_TOO_DEEP:
				break;
			default:
				assert(0);
				break;
			}
		} while ((n < length)
			&& (c->state != JSON_READER_CONETXT_STATE_COMPLETED_VALUE)
			&& (c->state != JSON_READER_CONETXT_STATE_STRUCTURE_INVALID)
			&& (c->state != JSON_READER_CONETXT_STATE_STRUCTURE_TOO_DEEP));
	}
	assert((n == length) || ((n < length) &&
		((c->state == JSON_READER_CONETXT_STATE_COMPLETED_VALUE)
		|| (c->state == JSON_READER_CONETXT_STATE_STRUCTURE_INVALID)
		|| (c->state == JSON_READER_CONETXT_STATE_STRUCTURE_TOO_DEEP))));
	return n;
}
