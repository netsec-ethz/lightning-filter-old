/*
 * Copyright (c) 2016 - 2018, Yaler GmbH, Oberon microsystems AG, Switzerland
 * All rights reserved
 *
 * See RFC 7159, http://www.rfc-editor.org/rfc/rfc7159.txt
 */

#include <assert.h>

#include "json_reader.h"

#define SUBSTATE_NONE 0

#define SUBSTATE_READING_STRING_AFTER_ESCAPE 1

#define SUBSTATE_READING_NUMBER_AFTER_MINUS 1
#define SUBSTATE_READING_NUMBER_AFTER_ZERO 2
#define SUBSTATE_READING_NUMBER_INTEGER_PART 3
#define SUBSTATE_READING_NUMBER_FRACTION_PART 4
#define SUBSTATE_READING_NUMBER_FRACTION_PART_AFTER_DIGIT 5
#define SUBSTATE_READING_NUMBER_EXPONENT_PART 6
#define SUBSTATE_READING_NUMBER_EXPONENT_PART_AFTER_SIGN 7
#define SUBSTATE_READING_NUMBER_EXPONENT_PART_AFTER_DIGIT 8

#define SUBSTATE_READING_FALSE_AFTER_F 1
#define SUBSTATE_READING_FALSE_AFTER_FA 2
#define SUBSTATE_READING_FALSE_AFTER_FAL 3
#define SUBSTATE_READING_FALSE_AFTER_FALS 4

#define SUBSTATE_READING_TRUE_AFTER_T 1
#define SUBSTATE_READING_TRUE_AFTER_TR 2
#define SUBSTATE_READING_TRUE_AFTER_TRU 3

#define SUBSTATE_READING_NULL_AFTER_N 1
#define SUBSTATE_READING_NULL_AFTER_NU 2
#define SUBSTATE_READING_NULL_AFTER_NUL 3

void json_reader_init(struct json_reader *r) {
	assert(r != NULL);
	r->state = JSON_READER_STATE_READING_WHITESPACE;
	r->substate = SUBSTATE_NONE;
}

static size_t skip_digits(char *buffer, size_t length) {
	size_t n; int x;
	assert(buffer != NULL);
	n = 0;
	if (n < length) {
		x = buffer[n];
		while (('0' <= x) && (x <= '9')) {
			n++;
			assert(n <= length);
			if (n < length) {
				x = buffer[n];
			} else {
				x = -1;
			}
		}
	}
	assert((n == length) || ((n < length)
		&& ((buffer[n] < '0') || (buffer[n] > '9'))));
	return n;
}

static size_t skip_whitespace(char *buffer, size_t length) {
	size_t n; int x;
	assert(buffer != NULL);
	n = 0;
	if (n < length) {
		x = buffer[n];
		while ((x == ' ') || (x == '\t') || (x == '\n') || (x == '\r')) {
			n++;
			assert(n <= length);
			if (n < length) {
				x = buffer[n];
			} else {
				x = -1;
			}
		}
	}
	assert((n == length) || ((n < length)
		&& (buffer[n] != ' ') && (buffer[n] != '\t')
		&& (buffer[n] != '\n') && (buffer[n] != '\r')));
	return n;
}

size_t json_reader_read(struct json_reader *r, char *buffer, size_t length) {
	size_t n; int post;
	assert(r != NULL);
	assert(buffer != NULL);
	n = 0;
	if (n < length) {
		do {
			switch (r->state) {
			case JSON_READER_STATE_READING_WHITESPACE:
				n += skip_whitespace(&buffer[n], length - n);
				assert(n <= length);
				if (n < length) {
					switch (buffer[n]) {
					case '{':
						n++;
						r->state = JSON_READER_STATE_BEGINNING_OBJECT;
						break;
					case '}':
						n++;
						r->state = JSON_READER_STATE_COMPLETED_OBJECT;
						break;
					case '[':
						n++;
						r->state = JSON_READER_STATE_BEGINNING_ARRAY;
						break;
					case ']':
						n++;
						r->state = JSON_READER_STATE_COMPLETED_ARRAY;
						break;
					case '-':
					case '0':
					case '1':
					case '2':
					case '3':
					case '4':
					case '5':
					case '6':
					case '7':
					case '8':
					case '9':
						r->state = JSON_READER_STATE_BEGINNING_NUMBER;
						break;
					case '"':
						r->state = JSON_READER_STATE_BEGINNING_STRING;
						break;
					case 'f':
						r->state = JSON_READER_STATE_BEGINNING_FALSE;
						break;
					case 't':
						r->state = JSON_READER_STATE_BEGINNING_TRUE;
						break;
					case 'n':
						r->state = JSON_READER_STATE_BEGINNING_NULL;
						break;
					case ':':
						n++;
						r->state = JSON_READER_STATE_AFTER_NAME_SEPARATOR;
						break;
					case ',':
						n++;
						r->state = JSON_READER_STATE_AFTER_VALUE_SEPARATOR;
						break;
					default:
						r->state = JSON_READER_STATE_ERROR;
						break;
					}
				}
				break;
			case JSON_READER_STATE_BEGINNING_OBJECT:
				r->state = JSON_READER_STATE_READING_WHITESPACE;
				break;
			case JSON_READER_STATE_COMPLETED_OBJECT:
				r->state = JSON_READER_STATE_READING_WHITESPACE;
				break;
			case JSON_READER_STATE_BEGINNING_ARRAY:
				r->state = JSON_READER_STATE_READING_WHITESPACE;
				break;
			case JSON_READER_STATE_COMPLETED_ARRAY:
				r->state = JSON_READER_STATE_READING_WHITESPACE;
				break;
			case JSON_READER_STATE_BEGINNING_NUMBER:
				switch (buffer[n]) {
				case '-':
					n++;
					r->state = JSON_READER_STATE_READING_NUMBER;
					r->substate = SUBSTATE_READING_NUMBER_AFTER_MINUS;
					break;
				case '0':
					n++;
					r->state = JSON_READER_STATE_READING_NUMBER;
					r->substate = SUBSTATE_READING_NUMBER_AFTER_ZERO;
					break;
				case '1':
				case '2':
				case '3':
				case '4':
				case '5':
				case '6':
				case '7':
				case '8':
				case '9':
					n++;
					r->state = JSON_READER_STATE_READING_NUMBER;
					r->substate = SUBSTATE_READING_NUMBER_INTEGER_PART;
					break;
				default:
					r->state = JSON_READER_STATE_ERROR;
					break;
				}
				break;
			case JSON_READER_STATE_READING_NUMBER:
				switch (r->substate) {
				case SUBSTATE_READING_NUMBER_AFTER_MINUS:
					switch (buffer[n]) {
					case '0':
						n++;
						r->substate = SUBSTATE_READING_NUMBER_AFTER_ZERO;
						break;
					case '1':
					case '2':
					case '3':
					case '4':
					case '5':
					case '6':
					case '7':
					case '8':
					case '9':
						n++;
						r->substate = SUBSTATE_READING_NUMBER_INTEGER_PART;
						break;
					default:
						r->state = JSON_READER_STATE_ERROR;
						r->substate = SUBSTATE_NONE;
						break;
					}
					break;
				case SUBSTATE_READING_NUMBER_AFTER_ZERO:
					switch (buffer[n]) {
					case '.':
						n++;
						r->substate = SUBSTATE_READING_NUMBER_FRACTION_PART;
						break;
					case 'e':
					case 'E':
						n++;
						r->substate = SUBSTATE_READING_NUMBER_EXPONENT_PART;
						break;
					case ' ':
					case '\t':
					case '\n':
					case '\r':
					case ']':
					case '}':
					case ',':
						r->state = JSON_READER_STATE_COMPLETED_NUMBER;
						r->substate = SUBSTATE_NONE;
						break;
					default:
						r->state = JSON_READER_STATE_ERROR;
						r->substate = SUBSTATE_NONE;
						break;
					}
					break;
				case SUBSTATE_READING_NUMBER_INTEGER_PART:
					n += skip_digits(&buffer[n], length - n);
					assert(n <= length);
					if (n < length) {
						switch (buffer[n]) {
						case '.':
							n++;
							r->substate = SUBSTATE_READING_NUMBER_FRACTION_PART;
							break;
						case 'e':
						case 'E':
							n++;
							r->substate = SUBSTATE_READING_NUMBER_EXPONENT_PART;
							break;
						case ' ':
						case '\t':
						case '\n':
						case '\r':
						case ']':
						case '}':
						case ',':
							r->state = JSON_READER_STATE_COMPLETED_NUMBER;
							r->substate = SUBSTATE_NONE;
							break;
						default:
							r->state = JSON_READER_STATE_ERROR;
							r->substate = SUBSTATE_NONE;
							break;
						}
					}
					break;
				case SUBSTATE_READING_NUMBER_FRACTION_PART:
					switch (buffer[n]) {
					case '0':
					case '1':
					case '2':
					case '3':
					case '4':
					case '5':
					case '6':
					case '7':
					case '8':
					case '9':
						n++;
						r->substate = SUBSTATE_READING_NUMBER_FRACTION_PART_AFTER_DIGIT;
						break;
					default:
						r->state = JSON_READER_STATE_ERROR;
						r->substate = SUBSTATE_NONE;
						break;
					}
					break;
				case SUBSTATE_READING_NUMBER_FRACTION_PART_AFTER_DIGIT:
					n += skip_digits(&buffer[n], length - n);
					assert(n <= length);
					if (n < length) {
						switch (buffer[n]) {
						case 'e':
						case 'E':
							n++;
							r->substate = SUBSTATE_READING_NUMBER_EXPONENT_PART;
							break;
						case ' ':
						case '\t':
						case '\n':
						case '\r':
						case ']':
						case '}':
						case ',':
							r->state = JSON_READER_STATE_COMPLETED_NUMBER;
							r->substate = SUBSTATE_NONE;
							break;
						default:
							r->state = JSON_READER_STATE_ERROR;
							r->substate = SUBSTATE_NONE;
							break;
						}
					}
					break;
				case SUBSTATE_READING_NUMBER_EXPONENT_PART:
					switch (buffer[n]) {
					case '-':
					case '+':
						n++;
						r->substate = SUBSTATE_READING_NUMBER_EXPONENT_PART_AFTER_SIGN;
						break;
					case '0':
					case '1':
					case '2':
					case '3':
					case '4':
					case '5':
					case '6':
					case '7':
					case '8':
					case '9':
						n++;
						r->substate = SUBSTATE_READING_NUMBER_EXPONENT_PART_AFTER_DIGIT;
						break;
					default:
						r->state = JSON_READER_STATE_ERROR;
						r->substate = SUBSTATE_NONE;
						break;
					}
					break;
				case SUBSTATE_READING_NUMBER_EXPONENT_PART_AFTER_SIGN:
					switch (buffer[n]) {
					case '0':
					case '1':
					case '2':
					case '3':
					case '4':
					case '5':
					case '6':
					case '7':
					case '8':
					case '9':
						n++;
						r->substate = SUBSTATE_READING_NUMBER_EXPONENT_PART_AFTER_DIGIT;
						break;
					default:
						r->state = JSON_READER_STATE_ERROR;
						r->substate = SUBSTATE_NONE;
						break;
					}
					break;
				case SUBSTATE_READING_NUMBER_EXPONENT_PART_AFTER_DIGIT:
					n += skip_digits(&buffer[n], length - n);
					assert(n <= length);
					if (n < length) {
						switch (buffer[n]) {
						case ' ':
						case '\t':
						case '\n':
						case '\r':
						case ']':
						case '}':
						case ',':
							r->state = JSON_READER_STATE_COMPLETED_NUMBER;
							r->substate = SUBSTATE_NONE;
							break;
						default:
							r->state = JSON_READER_STATE_ERROR;
							r->substate = SUBSTATE_NONE;
							break;
						}
					}
					break;
				default:
					assert(0);
					break;
				}
				break;
			case JSON_READER_STATE_COMPLETED_NUMBER:
				r->state = JSON_READER_STATE_READING_WHITESPACE;
				break;
			case JSON_READER_STATE_BEGINNING_STRING:
				if (buffer[n] == '"') {
					n++;
					r->state = JSON_READER_STATE_READING_STRING;
				} else {
					r->state = JSON_READER_STATE_ERROR;
				}
				break;
			case JSON_READER_STATE_READING_STRING:
				assert(n <= length);
				while ((n < length)
					&& ((r->substate != SUBSTATE_NONE) || (buffer[n] != '"')))
				{
					switch (r->substate) {
					case SUBSTATE_NONE:
						if (buffer[n] == '\\') {
							r->substate = SUBSTATE_READING_STRING_AFTER_ESCAPE;
						}
						break;
					case SUBSTATE_READING_STRING_AFTER_ESCAPE:
						r->substate = SUBSTATE_NONE;
						break;
					default:
						assert(0);
						break;
					}
					n++;
				}
				assert(n <= length);
				if (n < length) {
					n++;
					r->state = JSON_READER_STATE_COMPLETED_STRING;
				}
				break;
			case JSON_READER_STATE_COMPLETED_STRING:
				r->state = JSON_READER_STATE_READING_WHITESPACE;
				break;
			case JSON_READER_STATE_BEGINNING_FALSE:
				if (buffer[n] == 'f') {
					n++;
					r->state = JSON_READER_STATE_READING_FALSE;
					r->substate = SUBSTATE_READING_FALSE_AFTER_F;
				} else {
					r->state = JSON_READER_STATE_ERROR;
				}
				break;
			case JSON_READER_STATE_READING_FALSE:
				switch (r->substate) {
				case SUBSTATE_READING_FALSE_AFTER_F:
					if (buffer[n] == 'a') {
						n++;
						r->substate = SUBSTATE_READING_FALSE_AFTER_FA;
					} else {
						r->state = JSON_READER_STATE_ERROR;
						r->substate = SUBSTATE_NONE;
					}
					break;
				case SUBSTATE_READING_FALSE_AFTER_FA:
					if (buffer[n] == 'l') {
						n++;
						r->substate = SUBSTATE_READING_FALSE_AFTER_FAL;
					} else {
						r->state = JSON_READER_STATE_ERROR;
						r->substate = SUBSTATE_NONE;
					}
					break;
				case SUBSTATE_READING_FALSE_AFTER_FAL:
					if (buffer[n] == 's') {
						n++;
						r->substate = SUBSTATE_READING_FALSE_AFTER_FALS;
					} else {
						r->state = JSON_READER_STATE_ERROR;
						r->substate = SUBSTATE_NONE;
					}
					break;
				case SUBSTATE_READING_FALSE_AFTER_FALS:
					if (buffer[n] == 'e') {
						n++;
						r->state = JSON_READER_STATE_COMPLETED_FALSE;
						r->substate = SUBSTATE_NONE;
					} else {
						r->state = JSON_READER_STATE_ERROR;
						r->substate = SUBSTATE_NONE;
					}
					break;
				default:
					assert(0);
					break;
				}
				break;
			case JSON_READER_STATE_COMPLETED_FALSE:
				r->state = JSON_READER_STATE_READING_WHITESPACE;
				break;
			case JSON_READER_STATE_BEGINNING_TRUE:
				if (buffer[n] == 't') {
					n++;
					r->state = JSON_READER_STATE_READING_TRUE;
					r->substate = SUBSTATE_READING_TRUE_AFTER_T;
				} else {
					r->state = JSON_READER_STATE_ERROR;
				}
				break;
			case JSON_READER_STATE_READING_TRUE:
				switch (r->substate) {
				case SUBSTATE_READING_TRUE_AFTER_T:
					if (buffer[n] == 'r') {
						n++;
						r->substate = SUBSTATE_READING_TRUE_AFTER_TR;
					} else {
						r->state = JSON_READER_STATE_ERROR;
						r->substate = SUBSTATE_NONE;
					}
					break;
				case SUBSTATE_READING_TRUE_AFTER_TR:
					if (buffer[n] == 'u') {
						n++;
						r->substate = SUBSTATE_READING_TRUE_AFTER_TRU;
					} else {
						r->state = JSON_READER_STATE_ERROR;
						r->substate = SUBSTATE_NONE;
					}
					break;
				case SUBSTATE_READING_TRUE_AFTER_TRU:
					if (buffer[n] == 'e') {
						n++;
						r->state = JSON_READER_STATE_COMPLETED_TRUE;
						r->substate = SUBSTATE_NONE;
					} else {
						r->state = JSON_READER_STATE_ERROR;
						r->substate = SUBSTATE_NONE;
					}
					break;
				default:
					assert(0);
					break;
				}
				break;
			case JSON_READER_STATE_COMPLETED_TRUE:
				r->state = JSON_READER_STATE_READING_WHITESPACE;
				break;
			case JSON_READER_STATE_BEGINNING_NULL:
				if (buffer[n] == 'n') {
					n++;
					r->state = JSON_READER_STATE_READING_NULL;
					r->substate = SUBSTATE_READING_NULL_AFTER_N;
				} else {
					r->state = JSON_READER_STATE_ERROR;
				}
				break;
			case JSON_READER_STATE_READING_NULL:
				switch (r->substate) {
				case SUBSTATE_READING_NULL_AFTER_N:
					if (buffer[n] == 'u') {
						n++;
						r->substate = SUBSTATE_READING_NULL_AFTER_NU;
					} else {
						r->state = JSON_READER_STATE_ERROR;
						r->substate = SUBSTATE_NONE;
					}
					break;
				case SUBSTATE_READING_NULL_AFTER_NU:
					if (buffer[n] == 'l') {
						n++;
						r->substate = SUBSTATE_READING_NULL_AFTER_NUL;
					} else {
						r->state = JSON_READER_STATE_ERROR;
						r->substate = SUBSTATE_NONE;
					}
					break;
				case SUBSTATE_READING_NULL_AFTER_NUL:
					if (buffer[n] == 'l') {
						n++;
						r->state = JSON_READER_STATE_COMPLETED_NULL;
						r->substate = SUBSTATE_NONE;
					} else {
						r->state = JSON_READER_STATE_ERROR;
						r->substate = SUBSTATE_NONE;
					}
					break;
				default:
					assert(0);
					break;
				}
				break;
			case JSON_READER_STATE_COMPLETED_NULL:
				r->state = JSON_READER_STATE_READING_WHITESPACE;
				break;
			case JSON_READER_STATE_AFTER_NAME_SEPARATOR:
				r->state = JSON_READER_STATE_READING_WHITESPACE;
				break;
			case JSON_READER_STATE_AFTER_VALUE_SEPARATOR:
				r->state = JSON_READER_STATE_READING_WHITESPACE;
				break;
			case JSON_READER_STATE_ERROR:
				break;
			default:
				assert(0);
				break;
			}
		} while ((n < length)
			&& (r->state != JSON_READER_STATE_BEGINNING_OBJECT)
			&& (r->state != JSON_READER_STATE_COMPLETED_OBJECT)
			&& (r->state != JSON_READER_STATE_BEGINNING_ARRAY)
			&& (r->state != JSON_READER_STATE_COMPLETED_ARRAY)
			&& (r->state != JSON_READER_STATE_BEGINNING_NUMBER)
			&& (r->state != JSON_READER_STATE_COMPLETED_NUMBER)
			&& (r->state != JSON_READER_STATE_BEGINNING_STRING)
			&& (r->state != JSON_READER_STATE_COMPLETED_STRING)
			&& (r->state != JSON_READER_STATE_BEGINNING_FALSE)
			&& (r->state != JSON_READER_STATE_COMPLETED_FALSE)
			&& (r->state != JSON_READER_STATE_BEGINNING_TRUE)
			&& (r->state != JSON_READER_STATE_COMPLETED_TRUE)
			&& (r->state != JSON_READER_STATE_BEGINNING_NULL)
			&& (r->state != JSON_READER_STATE_COMPLETED_NULL)
			&& (r->state != JSON_READER_STATE_AFTER_NAME_SEPARATOR)
			&& (r->state != JSON_READER_STATE_AFTER_VALUE_SEPARATOR)
			&& (r->state != JSON_READER_STATE_ERROR));
	}
	post = (n == length) || ((n < length) &&
		((r->state == JSON_READER_STATE_ERROR)
		|| (r->state == JSON_READER_STATE_BEGINNING_OBJECT)
		|| (r->state == JSON_READER_STATE_COMPLETED_OBJECT)
		|| (r->state == JSON_READER_STATE_BEGINNING_ARRAY)
		|| (r->state == JSON_READER_STATE_COMPLETED_ARRAY)
		|| (r->state == JSON_READER_STATE_BEGINNING_NUMBER)
		|| (r->state == JSON_READER_STATE_COMPLETED_NUMBER)
		|| (r->state == JSON_READER_STATE_BEGINNING_STRING)
		|| (r->state == JSON_READER_STATE_COMPLETED_STRING)
		|| (r->state == JSON_READER_STATE_BEGINNING_FALSE)
		|| (r->state == JSON_READER_STATE_COMPLETED_FALSE)
		|| (r->state == JSON_READER_STATE_BEGINNING_TRUE)
		|| (r->state == JSON_READER_STATE_COMPLETED_TRUE)
		|| (r->state == JSON_READER_STATE_BEGINNING_NULL)
		|| (r->state == JSON_READER_STATE_COMPLETED_NULL)
		|| (r->state == JSON_READER_STATE_AFTER_NAME_SEPARATOR)
		|| (r->state == JSON_READER_STATE_AFTER_VALUE_SEPARATOR)));
	assert(post);
	return n;
}
