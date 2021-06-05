/*
 * Copyright (c) 2018, Yaler GmbH, Oberon microsystems AG, Switzerland
 * All rights reserved
 *
 * See RFC 7159, http://www.rfc-editor.org/rfc/rfc7159.txt
 */

#ifndef JSON_READER_UTILS_H
#define JSON_READER_UTILS_H

#include "json_reader.h"

#define JSON_READER_CONETXT_STATE_READING_VALUE 0
#define JSON_READER_CONETXT_STATE_COMPLETED_VALUE 1
#define JSON_READER_CONETXT_STATE_STRUCTURE_INVALID 2
#define JSON_READER_CONETXT_STATE_STRUCTURE_TOO_DEEP 3

struct json_reader_context {
	int state;
	int substate;
	unsigned long stack;
	size_t stack_depth;
};

extern void json_reader_context_init(
	struct json_reader_context *c);

extern size_t json_reader_utils_skip_value(
	struct json_reader *r,
	struct json_reader_context *c,
	char *buffer, size_t length);

#endif
