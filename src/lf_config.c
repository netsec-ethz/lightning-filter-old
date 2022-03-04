#include <assert.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <sys/errno.h>

#include "json_reader.h"
#include "json_reader_utils.h"

#include "lf_config.h"

#define READER_STATE_READING_JSON 0
#define READER_STATE_EOF 1
#define READER_STATE_ERROR 2

struct reader {
	int fd;
	int state;
	char buffer[256];
	size_t buffer_offset;
	size_t buffer_length;
	struct json_reader reader;
};

static void reader_init(struct reader *rd, int fd) {
	rd->fd = fd;
	rd->state = READER_STATE_READING_JSON;
	rd->buffer_offset = 0;
	rd->buffer_length = 0;
	json_reader_init(&rd->reader);
}

static void reader_read_file(struct reader *rd) {
	assert(rd->state == READER_STATE_READING_JSON);
	ssize_t n;
	do {
		n = read(rd->fd, rd->buffer, sizeof rd->buffer);
	} while ((n == -1) && (errno == EINTR));
	if (n < 0) {
		assert(n == -1);
		rd->state = READER_STATE_ERROR;
		rd->buffer_offset = 0;
		rd->buffer_length = 0;
	} else if (n == 0) {
		rd->state = READER_STATE_EOF;
		rd->buffer_offset = 0;
		rd->buffer_length = 0;
	} else {
		rd->buffer_offset = 0;
		rd->buffer_length = (size_t)n;
	}
}

static void reader_skip_forward(struct reader *rd) {
	assert(rd->state == READER_STATE_READING_JSON);
	assert((rd->reader.state == JSON_READER_STATE_READING_WHITESPACE)
		|| (rd->reader.state == JSON_READER_STATE_BEGINNING_OBJECT)
		|| (rd->reader.state == JSON_READER_STATE_COMPLETED_OBJECT)
		|| (rd->reader.state == JSON_READER_STATE_BEGINNING_ARRAY)
		|| (rd->reader.state == JSON_READER_STATE_COMPLETED_ARRAY)
		|| (rd->reader.state == JSON_READER_STATE_COMPLETED_NUMBER)
		|| (rd->reader.state == JSON_READER_STATE_COMPLETED_STRING)
		|| (rd->reader.state == JSON_READER_STATE_COMPLETED_FALSE)
		|| (rd->reader.state == JSON_READER_STATE_COMPLETED_TRUE)
		|| (rd->reader.state == JSON_READER_STATE_COMPLETED_NULL)
		|| (rd->reader.state == JSON_READER_STATE_AFTER_NAME_SEPARATOR)
		|| (rd->reader.state == JSON_READER_STATE_AFTER_VALUE_SEPARATOR));
	do {
		if (rd->buffer_offset == rd->buffer_length) {
			reader_read_file(rd);
		}
		if (rd->buffer_offset != rd->buffer_length) {
			rd->buffer_offset += json_reader_read(&rd->reader,
				&rd->buffer[rd->buffer_offset], rd->buffer_length - rd->buffer_offset);
		}
	} while ((rd->state == READER_STATE_READING_JSON)
		&& (rd->reader.state == JSON_READER_STATE_READING_WHITESPACE));
}

static void reader_skip_value(struct reader *rd) {
	assert(rd->state == READER_STATE_READING_JSON);
	struct json_reader_context jrc;
	json_reader_context_init(&jrc);
	do {
		if (rd->buffer_offset == rd->buffer_length) {
			reader_read_file(rd);
		}
		if (rd->buffer_offset != rd->buffer_length) {
			rd->buffer_offset += json_reader_utils_skip_value(&rd->reader, &jrc,
				&rd->buffer[rd->buffer_offset], rd->buffer_length - rd->buffer_offset);
		}
	} while ((rd->state == READER_STATE_READING_JSON)
		&& (jrc.state == JSON_READER_CONETXT_STATE_READING_VALUE));
	if (rd->state != READER_STATE_ERROR) {
		if (jrc.state != JSON_READER_CONETXT_STATE_COMPLETED_VALUE) {
			rd->state = READER_STATE_ERROR;
			return;
		}
	}
}

static void reader_read_string(struct reader *rd, char *val, size_t length) {
	assert(rd->state == READER_STATE_READING_JSON);
	if (rd->reader.state != JSON_READER_STATE_BEGINNING_STRING) {
		rd->state = READER_STATE_ERROR;
		return;
	}
	size_t i = 0;
	do {
		if (rd->buffer_offset == rd->buffer_length) {
			reader_read_file(rd);
		}
		if (rd->buffer_offset != rd->buffer_length) {
			int s = rd->reader.state;
			size_t o = rd->buffer_offset;
			rd->buffer_offset += json_reader_read(&rd->reader,
				&rd->buffer[rd->buffer_offset], rd->buffer_length - rd->buffer_offset);
			if ((rd->reader.state == JSON_READER_STATE_READING_STRING)
				|| (rd->reader.state == JSON_READER_STATE_COMPLETED_STRING))
			{
				if (s == JSON_READER_STATE_BEGINNING_STRING) {
					assert(o < rd->buffer_offset);
					assert(rd->buffer[o] == '"');
					o++;
				}
				size_t n = rd->buffer_offset - o;
				if (rd->reader.state == JSON_READER_STATE_COMPLETED_STRING) {
					assert(n > 0);
					assert(rd->buffer[o + n - 1] == '"');
					n--;
				}
				if (n >= length - i) {
					rd->state = READER_STATE_ERROR;
					return;
				}
				memcpy(&val[i], &rd->buffer[o], n);
				i += n;
			}
		}
	} while ((rd->state == READER_STATE_READING_JSON)
		&& (rd->reader.state == JSON_READER_STATE_READING_STRING));
	if (rd->state != READER_STATE_ERROR) {
		if (rd->reader.state != JSON_READER_STATE_COMPLETED_STRING) {
			rd->state = READER_STATE_ERROR;
			return;
		}
		assert(i < length);
		val[i] = '\0';
	}
}

static void reader_read_uint64(struct reader *rd, uint64_t *val) {
	assert(rd->state == READER_STATE_READING_JSON);
	if (rd->reader.state != JSON_READER_STATE_BEGINNING_NUMBER) {
		rd->state = READER_STATE_ERROR;
		return;
	}
	*val = 0;
	do {
		if (rd->buffer_offset == rd->buffer_length) {
			reader_read_file(rd);
		}
		if (rd->buffer_offset != rd->buffer_length) {
			size_t i = rd->buffer_offset;
			rd->buffer_offset += json_reader_read(&rd->reader,
				&rd->buffer[rd->buffer_offset], rd->buffer_length - rd->buffer_offset);
			if ((rd->reader.state == JSON_READER_STATE_READING_NUMBER)
				|| (rd->reader.state == JSON_READER_STATE_COMPLETED_NUMBER))
			{
				size_t j = rd->buffer_offset;
				while (i != j) {
					char x = rd->buffer[i];
					if (('0' <= x) && (x <= '9')) {
						x = x - '0';
						if (*val <= (UINT64_MAX - x) / 10) {
							*val = 10 * *val + x;
						} else {
							rd->state = READER_STATE_ERROR;
							return;
						}
					} else {
						rd->state = READER_STATE_ERROR;
						return;
					}
					i++;
				}
			}
		}
	} while ((rd->state == READER_STATE_READING_JSON)
		&& (rd->reader.state == JSON_READER_STATE_READING_NUMBER));
	if (rd->state != READER_STATE_ERROR) {
		if (rd->reader.state != JSON_READER_STATE_COMPLETED_NUMBER) {
			rd->state = READER_STATE_ERROR;
			return;
		}
	}
}

static void reader_read_uint16(struct reader *rd, uint16_t *val) {
	assert(rd->state == READER_STATE_READING_JSON);
	if (rd->reader.state != JSON_READER_STATE_BEGINNING_NUMBER) {
		rd->state = READER_STATE_ERROR;
		return;
	}
	*val = 0;
	do {
		if (rd->buffer_offset == rd->buffer_length) {
			reader_read_file(rd);
		}
		if (rd->buffer_offset != rd->buffer_length) {
			size_t i = rd->buffer_offset;
			rd->buffer_offset += json_reader_read(&rd->reader,
				&rd->buffer[rd->buffer_offset], rd->buffer_length - rd->buffer_offset);
			if ((rd->reader.state == JSON_READER_STATE_READING_NUMBER)
				|| (rd->reader.state == JSON_READER_STATE_COMPLETED_NUMBER))
			{
				size_t j = rd->buffer_offset;
				while (i != j) {
					char x = rd->buffer[i];
					if (('0' <= x) && (x <= '9')) {
						x = x - '0';
						if (*val <= (UINT16_MAX - x) / 10) {
							*val = 10 * *val + x;
						} else {
							rd->state = READER_STATE_ERROR;
							return;
						}
					} else {
						rd->state = READER_STATE_ERROR;
						return;
					}
					i++;
				}
			}
		}
	} while ((rd->state == READER_STATE_READING_JSON)
		&& (rd->reader.state == JSON_READER_STATE_READING_NUMBER));
	if (rd->state != READER_STATE_ERROR) {
		if (rd->reader.state != JSON_READER_STATE_COMPLETED_NUMBER) {
			rd->state = READER_STATE_ERROR;
			return;
		}
	}
}

static void reader_read_selector(struct reader *rd, char *val, size_t length) {
	assert(rd->state == READER_STATE_READING_JSON);
	assert((rd->reader.state == JSON_READER_STATE_BEGINNING_OBJECT)
		|| (rd->reader.state == JSON_READER_STATE_AFTER_VALUE_SEPARATOR));
	reader_skip_forward(rd);
	if (rd->state == READER_STATE_ERROR) {
		return;
	}
	reader_read_string(rd, val, length);
	if (rd->state == READER_STATE_ERROR) {
		return;
	}
	reader_skip_forward(rd);
	if (rd->state == READER_STATE_ERROR) {
		return;
	}
	if (rd->reader.state != JSON_READER_STATE_AFTER_NAME_SEPARATOR) {
		rd->state = READER_STATE_ERROR;
		return;
	}
}

static void reader_read_ether_addr(struct reader *rd, uint8_t val[6]) {
	reader_skip_forward(rd);
	if (rd->state == READER_STATE_ERROR) {
		return;
	}
	char addrstr[sizeof "aa:bb:cc:dd:ee:ff"];
	reader_read_string(rd, addrstr, sizeof addrstr);
	if (rd->state == READER_STATE_ERROR) {
		return;
	}
	size_t i = 0;
	size_t k = 0;
	do {
		if (k != 0) {
			assert(i < sizeof addrstr);
			if (addrstr[i] != ':') {
				rd->state = READER_STATE_ERROR;
				return;
			}
			i++;
		}
		val[k] = 0;
		size_t j = i;
		do {
			assert(j < sizeof addrstr);
			int x = addrstr[j];
			if (('0' <= x) && (x <= '9')) {
				val[k] = (val[k] << 4) | (x - '0');
			} else if (('a' <= x) && (x <= 'f')) {
				val[k] = (val[k] << 4) | (x - 'a' + 10);
			} else {
				rd->state = READER_STATE_ERROR;
				return;
			}
			j++;
		} while (j - i != 2);
		i += 2;
		k++;
	} while (k != 6);
	assert(i < sizeof addrstr);
	assert(addrstr[i] == '\0');
}

static void reader_read_ipv4_addr(struct reader *rd, uint32_t *val) {
	reader_skip_forward(rd);
	if (rd->state == READER_STATE_ERROR) {
		return;
	}
	char addrstr[INET_ADDRSTRLEN];
	reader_read_string(rd, addrstr, sizeof addrstr);
	if (rd->state == READER_STATE_ERROR) {
		return;
	}
	assert(sizeof *val == sizeof(struct in_addr));
	int r = inet_pton(AF_INET, addrstr, val);
	if (r != 1) {
		assert(r == 0);
		rd->state = READER_STATE_ERROR;
		return;
	}
}

static int32_t get_isd_num(char *str, size_t length) {
	int32_t isd_num;
	if (length == 0) {
		isd_num = -1;
	} else {
		isd_num = 0;
		size_t i = 0;
		do {
			int x = str[i];
			if (('0' <= x) && (x <= '9')) {
				x = x - '0';
				if (isd_num <= (65535 - x) / 10) {
					isd_num = 10 * isd_num + x;
				} else {
					isd_num = -1;
				}
			} else {
				isd_num = -1;
			}
			i++;
		} while ((isd_num >= 0) && (i != length));
	}
	return isd_num;
}

static int64_t get_bgp_as_num(char *str, size_t length) {
	int64_t as_num;
	if (length == 0) {
		as_num = -1;
	} else {
		as_num = 0;
		size_t i = 0;
		do {
			int x = str[i];
			if (('0' <= x) && (x <= '9')) {
				x = x - '0';
				if (as_num <= (4294967295 - x) / 10) {
					as_num = 10 * as_num + x;
				} else {
					as_num = -1;
				}
			} else {
				as_num = -1;
			}
			i++;
		} while ((as_num >= 0) && (i != length));
	}
	return as_num;
}

static int32_t get_as_num_part(char *str, size_t length) {
	int32_t as_num_part;
	if ((length == 0) || (length > 4)) {
		as_num_part = -1;
	} else {
		as_num_part = 0;
		size_t i = 0;
		do {
			int x = str[i];
			if (('0' <= x) && (x <= '9')) {
				as_num_part = (as_num_part << 4) | (x - '0');
			} else if (('A' <= x) && (x <= 'F')) {
				as_num_part = (as_num_part << 4) | (x - 'A' + 10);
			} else if (('a' <= x) && (x <= 'f')) {
				as_num_part = (as_num_part << 4) | (x - 'a' + 10);
			} else {
				as_num_part = -1;
			}
			i++;
		} while ((as_num_part >= 0) && (i != length));
	}
	return as_num_part;
}

static void reader_read_isd_as(struct reader *rd, uint64_t *val) {
	reader_skip_forward(rd);
	if (rd->state == READER_STATE_ERROR) {
		return;
	}
	char iastr[sizeof "65535-ffff:ffff:ffff"];
	reader_read_string(rd, iastr, sizeof iastr);
	if (rd->state == READER_STATE_ERROR) {
		return;
	}
	size_t i = 0;
	size_t j = 0;
	while ((iastr[j] != '\0') && (iastr[j] != '-')) {
		j++;
	}
	if (iastr[j] == '\0') {
		rd->state = READER_STATE_ERROR;
		return;
	}
	int64_t isd = get_isd_num(&iastr[i], j - i);
	if (isd < 0) {
		rd->state = READER_STATE_ERROR;
		return;
	}
	j++;
	i = j;
	while ((iastr[j] != '\0') && (iastr[j] != ':')) {
		j++;
	}
	uint64_t as;
	if (iastr[j] == '\0') {
		int64_t as0 = get_bgp_as_num(&iastr[i], j - i);
		if (as0 < 0) {
			rd->state = READER_STATE_ERROR;
			return;
		}
		as = (uint64_t)as0;
	} else {
		int64_t as0 = get_as_num_part(&iastr[i], j - i);
		if (as0 < 0) {
			rd->state = READER_STATE_ERROR;
			return;
		}
		j++;
		i = j;
		while ((iastr[j] != '\0') && (iastr[j] != ':')) {
			j++;
		}
		if (iastr[j] == '\0') {
			rd->state = READER_STATE_ERROR;
			return;
		}
		int64_t as1 = get_as_num_part(&iastr[i], j - i);
		if (as1 < 0) {
			rd->state = READER_STATE_ERROR;
			return;
		}
		j++;
		i = j;
		while (iastr[j] != '\0') {
			j++;
		}
		int64_t as2 = get_as_num_part(&iastr[i], j - i);
		if (as2 < 0) {
			rd->state = READER_STATE_ERROR;
			return;
		}
		as = ((uint64_t)as0 << 32) | ((uint64_t)as1 << 16) | (uint64_t)as2;
	}
	*val = ((uint64_t)isd << 48) | (uint64_t)as;
}

static void reader_read_rate_limit(struct reader *rd, uint64_t *val) {
	assert(rd->state == READER_STATE_READING_JSON);
	reader_skip_forward(rd);
	if (rd->state == READER_STATE_ERROR) {
		return;
	}
	reader_read_uint64(rd, val);
}

static void reader_read_dst_port(struct reader *rd, uint16_t *val) {
	assert(rd->state == READER_STATE_READING_JSON);
	reader_skip_forward(rd);
	if (rd->state == READER_STATE_ERROR) {
		return;
	}
	reader_read_uint16(rd, val);
}

static void reader_read_backends(struct reader *rd, struct lf_config *c) {
	assert(rd->state == READER_STATE_READING_JSON);
	struct lf_config_backend *b = c->backends;
	if (b != NULL) {
		while (b->next != NULL) {
			b = b->next;
		}
	}
	reader_skip_forward(rd);
	if (rd->state == READER_STATE_ERROR) {
		return;
	}
	if (rd->reader.state != JSON_READER_STATE_BEGINNING_ARRAY) {
		rd->state = READER_STATE_ERROR;
		return;
	}
	do {
		reader_skip_forward(rd);
		if (rd->state == READER_STATE_ERROR) {
			return;
		}
		if (rd->reader.state != JSON_READER_STATE_BEGINNING_OBJECT) {
			rd->state = READER_STATE_ERROR;
			return;
		}
		uint32_t public_addr = 0;
		uint32_t private_addr = 0;
		uint8_t ether_addr[6] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
		do {
			char selector[256];
			reader_read_selector(rd, selector, sizeof selector);
			if (rd->state == READER_STATE_ERROR) {
				return;
			}
			if (strncmp(selector, "public_addr", sizeof selector) == 0) {
				reader_read_ipv4_addr(rd, &public_addr);
			} else if (strncmp(selector, "private_addr", sizeof selector) == 0) {
				reader_read_ipv4_addr(rd, &private_addr);
			} else if (strncmp(selector, "ether_addr", sizeof selector) == 0) {
				reader_read_ether_addr(rd, ether_addr);
			} else {
				reader_skip_value(rd);
			}
			if (rd->state == READER_STATE_ERROR) {
				return;
			}
			reader_skip_forward(rd);
			if (rd->state == READER_STATE_ERROR) {
				return;
			}
		} while (rd->reader.state == JSON_READER_STATE_AFTER_VALUE_SEPARATOR);
		if (rd->reader.state != JSON_READER_STATE_COMPLETED_OBJECT) {
			rd->state = READER_STATE_ERROR;
			return;
		}
		struct lf_config_backend *x = malloc(sizeof *x);
		if (x == NULL) {
			rd->state = READER_STATE_ERROR;
			return;
		}
		x->next = NULL;
		x->public_addr = public_addr;
		x->private_addr = private_addr;
		x->ether_addr[0] = ether_addr[0];
		x->ether_addr[1] = ether_addr[1];
		x->ether_addr[2] = ether_addr[2];
		x->ether_addr[3] = ether_addr[3];
		x->ether_addr[4] = ether_addr[4];
		x->ether_addr[5] = ether_addr[5];
		if (b == NULL) {
			assert(c->backends == NULL);
			c->backends = x;
		} else {
			assert(b->next == NULL);
			b->next = x;
		}
		b = x;
		reader_skip_forward(rd);
		if (rd->state == READER_STATE_ERROR) {
			return;
		}
	} while (rd->reader.state == JSON_READER_STATE_AFTER_VALUE_SEPARATOR);
	if (rd->reader.state != JSON_READER_STATE_COMPLETED_ARRAY) {
		rd->state = READER_STATE_ERROR;
		return;
	}
}

static void reader_read_peers(struct reader *rd, struct lf_config *c) {
	assert(rd->state == READER_STATE_READING_JSON);
	struct lf_config_peer *p = c->peers;
	if (p != NULL) {
		while (p->next != NULL) {
			p = p->next;
		}
	}
	reader_skip_forward(rd);
	if (rd->state == READER_STATE_ERROR) {
		return;
	}
	if (rd->reader.state != JSON_READER_STATE_BEGINNING_ARRAY) {
		rd->state = READER_STATE_ERROR;
		return;
	}
	do {
		reader_skip_forward(rd);
		if (rd->state == READER_STATE_ERROR) {
			return;
		}
		if (rd->reader.state != JSON_READER_STATE_BEGINNING_OBJECT) {
			rd->state = READER_STATE_ERROR;
			return;
		}
		uint64_t isd_as = 0;
		uint32_t public_addr = 0;
		uint64_t rate_limit = 0;
		uint8_t ether_addr[6] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
		uint16_t dst_port = 0;
		do {
			char selector[256];
			reader_read_selector(rd, selector, sizeof selector);
			if (rd->state == READER_STATE_ERROR) {
				return;
			}
			if (strncmp(selector, "isd_as", sizeof selector) == 0) {
				reader_read_isd_as(rd, &isd_as);
			} else if (strncmp(selector, "public_addr", sizeof selector) == 0) {
				reader_read_ipv4_addr(rd, &public_addr);
			} else if (strncmp(selector, "rate_limit", sizeof selector) == 0) {
				reader_read_rate_limit(rd, &rate_limit);
			} else if (strncmp(selector, "ether_addr", sizeof selector) == 0) {
				reader_read_ether_addr(rd, ether_addr);
			} else if (strncmp(selector, "dst_port", sizeof selector) == 0){
				reader_read_dst_port(rd, &dst_port);
			} else {
				reader_skip_value(rd);
			}
			if (rd->state == READER_STATE_ERROR) {
				return;
			}
			reader_skip_forward(rd);
			if (rd->state == READER_STATE_ERROR) {
				return;
			}
		} while (rd->reader.state == JSON_READER_STATE_AFTER_VALUE_SEPARATOR);
		if (rd->reader.state != JSON_READER_STATE_COMPLETED_OBJECT) {
			rd->state = READER_STATE_ERROR;
			return;
		}
		struct lf_config_peer *x = malloc(sizeof *x);
		if (x == NULL) {
			rd->state = READER_STATE_ERROR;
			return;
		}
		x->next = NULL;
		x->isd_as = isd_as;
		x->dst_port = dst_port;
		x->public_addr = public_addr;
		x->rate_limit = rate_limit;
		x->ether_addr[0] = ether_addr[0];
		x->ether_addr[1] = ether_addr[1];
		x->ether_addr[2] = ether_addr[2];
		x->ether_addr[3] = ether_addr[3];
		x->ether_addr[4] = ether_addr[4];
		x->ether_addr[5] = ether_addr[5];
		if (p == NULL) {
			assert(c->peers == NULL);
			c->peers = x;
		} else {
			assert(p->next == NULL);
			p->next = x;
		}
		p = x;
		reader_skip_forward(rd);
		if (rd->state == READER_STATE_ERROR) {
			return;
		}
	} while (rd->reader.state == JSON_READER_STATE_AFTER_VALUE_SEPARATOR);
	if (rd->reader.state != JSON_READER_STATE_COMPLETED_ARRAY) {
		rd->state = READER_STATE_ERROR;
		return;
	}
}

static void reader_read_config(struct reader *rd, struct lf_config *c) {
	assert(rd->state == READER_STATE_READING_JSON);
	reader_skip_forward(rd);
	if (rd->state == READER_STATE_ERROR) {
		return;
	}
	if (rd->reader.state != JSON_READER_STATE_BEGINNING_OBJECT) {
		rd->state = READER_STATE_ERROR;
		return;
	}
	do {
		char selector[256];
		reader_read_selector(rd, selector, sizeof selector);
		if (rd->state == READER_STATE_ERROR) {
			return;
		}
		if (strncmp(selector, "system_limit", sizeof selector) == 0) {
			reader_read_rate_limit(rd, &c->system_limit);
		} else if (strncmp(selector, "isd_as", sizeof selector) == 0) {
			reader_read_isd_as(rd, &c->isd_as);
		} else if (strncmp(selector, "peers", sizeof selector) == 0) {
			reader_read_peers(rd, c);
		} else if (strncmp(selector, "backends", sizeof selector) == 0) {
			reader_read_backends(rd, c);
		} else {
			reader_skip_value(rd);
		}
		if (rd->state == READER_STATE_ERROR) {
			return;
		}
		reader_skip_forward(rd);
		if (rd->state == READER_STATE_ERROR) {
			return;
		}
	} while (rd->reader.state == JSON_READER_STATE_AFTER_VALUE_SEPARATOR);
	if (rd->reader.state != JSON_READER_STATE_COMPLETED_OBJECT) {
		rd->state = READER_STATE_ERROR;
		return;
	}
	reader_skip_forward(rd);
	if (rd->state == READER_STATE_ERROR) {
		return;
	}
	if (rd->state != READER_STATE_EOF) {
		rd->state = READER_STATE_ERROR;
		return;
	}
}

void lf_config_release(struct lf_config *c) {
	struct lf_config_peer *p = c->peers;
	while (p != NULL) {
		void *x = p;
		p = p->next;
		free(x);
	}
	c->peers = NULL;
	struct lf_config_backend *b = c->backends;
	while (b != NULL) {
		void *x = b;
		b = b->next;
		free(x);
	}
	c->backends = NULL;
}

int lf_config_load(struct lf_config *c, const char *path) {
	c->isd_as = 0;
	c->system_limit = 0;
	c->peers = NULL;
	c->backends = NULL;
	int fd;
	do {
		fd = open(path, O_RDONLY);
	} while ((fd == -1) && (errno == EINTR));
	if (fd < 0) {
		assert(fd == -1);
		return -1;
	}
	struct reader rd;
	reader_init(&rd, fd);
	reader_read_config(&rd, c);
	(void)close(fd);
	if (rd.state == READER_STATE_ERROR) {
		lf_config_release(c);
		return -1;
	}
	return 0;
}
