#ifndef STRATUM_TASK_H_
#define STRATUM_TASK_H_

typedef struct
{
    uint32_t stratum_difficulty;
} SystemTaskModule;

void stratum_task(void *pvParameters);

static inline uint8_t hexnibble2bin(unsigned char c) {
	return (c >= '0' && c <= '9') ? (c - '0') : ((c >= 'a' && c <= 'f') ? (c - 'a' + 10) : ((c >= 'A' && c <= 'F') ? (c - 'A' + 10) : 0));
}

#endif