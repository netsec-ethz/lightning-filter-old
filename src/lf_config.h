#ifndef LF_CONFIG_H
#define LF_CONFIG_H

struct lf_config_backend {
	struct lf_config_backend *next;
	int32_t public_addr;
	int32_t private_addr;
};

struct lf_config_peer {
	struct lf_config_peer *next;
	int64_t isd_as;
	int32_t public_addr;
	uint64_t rate_limit;
};

struct lf_config {
	int64_t isd_as;
	uint64_t system_limit;
	struct lf_config_peer *peers;
	struct lf_config_backend *backends;
};

void lf_config_release(struct lf_config *c);
int lf_config_load(struct lf_config *c, const char *path);

#endif
