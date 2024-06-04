#include "esp_log.h"
// #include "addr_from_stdin.h"
#include "bm1397.h"
#include "connect.h"
#include "global_state.h"
#include "lwip/dns.h"
#include "nvs_config.h"
#include "stratum_task.h"
#include "work_queue.h"
#include <esp_sntp.h>
#include <time.h>
#include <inttypes.h>

#define PORT CONFIG_STRATUM_PORT
#define STRATUM_URL CONFIG_STRATUM_URL

#define STRATUM_PW CONFIG_STRATUM_PW
#define STRATUM_DIFFICULTY CONFIG_STRATUM_DIFFICULTY

static const char * TAG = "stratum_task";
static ip_addr_t ip_Addr;
static bool bDNSFound = false;
static bool bDNSInvalid = false;

static StratumApiV1Message stratum_api_v1_message = {};

static SystemTaskModule SYSTEM_TASK_MODULE = {.stratum_difficulty = 8192};

void dns_found_cb(const char * name, const ip_addr_t * ipaddr, void * callback_arg)
{
    bDNSFound = true;
    if (ipaddr != NULL) {
        ip_Addr = *ipaddr;
    } else {
        bDNSInvalid = true;
    }
 }


int switch_coinbase_parser_chunk(uint16_t **p, int *chunk, StratumApiV1Message *m, uint16_t **fake_en2) {
	// The coinbase data in stratum has to be assembled for parsing
	// coinbase1 + extranonce1 + extranonce2 + coinbase2
	// We'll do this by just switching our pointer whenever we hit one of these boundaries

	(*chunk)++;
	if (*chunk == 1) {
		// setup extranonce2 to just be whatever is at the end of coinb1.
		// it doesn't matter what it is as long as the len is correct.
		// we just want that many bytes, and then a terminator again
		// the miner gets to decide extranonce2, so this can be anything for parsing
		*fake_en2 = *p - m->extranonce_2_len;
		
		// set to extranonce1 string from the pool
		*p = (uint16_t *)m->extranonce_str;
	} else if (*chunk == 2) {
		// extranonce2 (random)
		*p = *fake_en2;
	} else if (*chunk == 3) {
		// final part of the coinbase
		*p = (uint16_t *)m->mining_notification->coinbase_2;
	} else {
		return 0;
	}
	return *chunk;
}

uint64_t coinbase_parser_parse_cbvalue(uint16_t **p, int *chunk, StratumApiV1Message *m, uint16_t **fake_en2) {
	// extract a 64-bit hex value into a variable
	uint64_t cbvalue = 0;
	for (int shift = 0; shift <= 60; shift += 8) {
		if (!(**p & 0xff)) {
			if (!switch_coinbase_parser_chunk(p, chunk, m, fake_en2)) {
				return UINT64_MAX; // or handle the error as needed
			}
		}
		cbvalue += (uint64_t)(hexnibble2bin(**p >> 8) << shift) | (uint64_t)(hexnibble2bin(**p & 0xFF) << (shift + 4));
		(*p)++;
	}
	return cbvalue;
}

uint64_t coinbase_parser_parse_varint(uint16_t **p, int *chunk, StratumApiV1Message *m, uint16_t **fake_en2) {

	// parse a bitcoin varint in hex into a 64-bit value
	uint64_t varint = 0;
	uint8_t first_byte;
	if (!(**p & 0xff)) {
		if (!switch_coinbase_parser_chunk(p, chunk, m, fake_en2)) {
			return UINT64_MAX;
		}
	}	
	
	first_byte = (hexnibble2bin(**p >> 8)) | (hexnibble2bin(**p & 0xFF) << 4);
	(*p)++;
	if (!(first_byte & 0xff)) {
		if (!switch_coinbase_parser_chunk(p, chunk, m, fake_en2)) {
			return UINT64_MAX;
		}
	}

	if (first_byte < 0xfd) {
		varint = first_byte;
	} else if (first_byte == 0xfd) {
		for (int i = 0; i < 2; i++) {
			if (!(**p & 0xff)) {
				if (!switch_coinbase_parser_chunk(p, chunk, m, fake_en2)) {
					return UINT64_MAX;
				}
			}
			varint |= (((hexnibble2bin(**p >> 8)) | (hexnibble2bin(**p & 0xFF) << 4)) << (i * 8));
			(*p)++;
		}
	} else if (first_byte == 0xfe) {
		for (int i = 0; i < 4; i++) {
			if (!(**p & 0xff)) {
				if (!switch_coinbase_parser_chunk(p, chunk, m, fake_en2)) {
					return UINT64_MAX;
				}
			}
			varint |= (((hexnibble2bin(**p >> 8)) | (hexnibble2bin(**p & 0xFF) << 4)) << (i * 8));
			(*p)++;
		}
	} else {
		for (int i = 0; i < 8; i++) {
			if (!(**p & 0xff)) {
				if (!switch_coinbase_parser_chunk(p, chunk, m, fake_en2)) {
					return UINT64_MAX;
				}
			}
			varint |= (((hexnibble2bin(**p >> 8)) | (hexnibble2bin(**p & 0xFF) << 4)) << (i * 8));
			(*p)++;
		}
	}
	return varint;
}

void stratum_update_work_stats(StratumApiV1Message *m) {

	// decode the coinbase transaction for cool stats! moar data!
	// TODO: Do something with this data besides just logging it
	
	int chunk = 0;
	int i,j;
	unsigned char c;
	uint16_t *p = (uint16_t *)m->mining_notification->coinbase_1;
	uint32_t u;
	uint16_t *fake_en2 = p;
	uint64_t cbvalue = 0;
	char cbtext[96];
	
	// Some sanity checks, in case mining on non-bitcoin
	// check for version 1 or 2 txn, with 1 input
	if (((*p != 0x3130) && (*p != 0x3230)) || (p[4] != 0x3130)) return;

	// Coinbase var-length is always (supposed to be) at index 41
	// Technically a varint, but the coinbase is consensus limited to 100 bytes, which is never enough to trigger a multi-byte varint
	// highest should be 0x64
	p+=41;
	// poor man's hex to byte.  keep in mind the nibbles are reversed
	i = ((*p & 0xFF)-0x30)<<4; // we know this nibble will be 0-6
	i += hexnibble2bin(*p >> 8);
	p++;
	
	if (i > 100) return;
	
	ESP_LOGE("coinbase_parser", "Input length: %d bytes", i);
	
	// first part of the coinbase is the block height.
	// this byte should be 03 (0x3330) for several lifetimes.
	if (*p != 0x3330) return;
	p++;
	
	// next 3 bytes are the current block height
	u = (hexnibble2bin(*p >> 8) << 0) | (hexnibble2bin(*p & 0xFF) << 4);
	p++;
	u |= (hexnibble2bin(*p >> 8) << 8) | (hexnibble2bin(*p & 0xFF) << 12);
	p++;
	u |= (hexnibble2bin(*p >> 8) << 16) | (hexnibble2bin(*p & 0xFF) << 20);
	p++;
	i-=4;
	
	ESP_LOGE("coinbase_parser", "Block height: %" PRIu32, u);
	
	if (i) {
		// data remains in the coinbase
		// let's parse out the ascii printable characters to get a text
		// string to show the user about which pool their work is coming from
		j = 0;
		while ((i > 0) && (j< 95)) {
			if (!(*p & 0xff)) {	if (!switch_coinbase_parser_chunk(&p, &chunk, m, &fake_en2)) { return; } }
			c = (hexnibble2bin(*p >> 8)) | (hexnibble2bin(*p & 0xFF) << 4);
			p++;
			if ((c >= 32) && (c<=126) && (c != '\n') && (c != '\r')) {
				cbtext[j] = c;
			} else {
				cbtext[j] = '?';
			}
			j++;
			i--;
		}
		cbtext[j] = 0;
		ESP_LOGE("coinbase_parser", "Text: %s", cbtext);
	} else {
		// It's not required that the coinbase have additional data
		ESP_LOGE("coinbase_parser", "Text: (NULL)");
	}

	// continue parsing
	// skip 4 bytes for sequence
	for(i=0;i<4;i++) {
			if (!(*p & 0xff)) {	if (!switch_coinbase_parser_chunk(&p, &chunk, m, &fake_en2)) { return; } }
			p++;
	}

	// parse varint into i for the number of outputs in the coinbase
	if (!(*p & 0xff)) {	if (!switch_coinbase_parser_chunk(&p, &chunk, m, &fake_en2)) { return; } }
	c = (hexnibble2bin(*p >> 8)) | (hexnibble2bin(*p & 0xFF) << 4);
	p++;
	if (c <= 0xFC) {
		i = c;
	} else {
		if (c == 0xFD) {
			// 16-bit varint to follow
			if (!(*p & 0xff)) {	if (!switch_coinbase_parser_chunk(&p, &chunk, m, &fake_en2)) { return; } }
			i = (hexnibble2bin(*p >> 8) << 0) | (hexnibble2bin(*p & 0xFF) << 4);
			p++;
			if (!(*p & 0xff)) {	if (!switch_coinbase_parser_chunk(&p, &chunk, m, &fake_en2)) { return; } }
			i |= (hexnibble2bin(*p >> 8) << 8) | (hexnibble2bin(*p & 0xFF) << 12);
			p++;
		} else {
			ESP_LOGE("coinbase_parser", "Coinbase appears to have more than 65536 outputs? crazy.");
			return; // if the coinbase has more than 2^16 outputs just give up. we dont have time for that
		}
	}
	
	ESP_LOGE("coinbase_parser", "Output count: %d", i);
	
	
	// loop through all of the outputs, add up their values into cbvalue
	// abort on any issues.
	for(j=0;j<i;j++) {
		// add up value of all outputs
		uint64_t cb_temp = coinbase_parser_parse_cbvalue(&p, &chunk, m, &fake_en2);
		if (cb_temp == UINT64_MAX) return;
		
		cbvalue += cb_temp;
		
        // get the varlen from the next byte(s)
        uint64_t varlen = coinbase_parser_parse_varint(&p, &chunk, m, &fake_en2);

		if (varlen == UINT64_MAX) return;
		
        // discard that many bytes. possibly can decode output addresses here, if we really want that info
		// but this function is probably expensive enough as it is.
        for (uint64_t k = 0; k < varlen; k++) {
            if (!(*p & 0xff)) {
                if (!switch_coinbase_parser_chunk(&p, &chunk, m, &fake_en2)) {
                    return;
                }
            }
            p++;
        }	
	}
	
	ESP_LOGE("coinbase_parser", "Output value: %.8f BTC", (double)cbvalue/100000000.0);
	
	return;

}

void stratum_task(void * pvParameters)
{
    GlobalState * GLOBAL_STATE = (GlobalState *) pvParameters;

    STRATUM_V1_initialize_buffer();
    char host_ip[20];
    int addr_family = 0;
    int ip_protocol = 0;


    char *stratum_url = GLOBAL_STATE->SYSTEM_MODULE.pool_url;
    uint16_t port = GLOBAL_STATE->SYSTEM_MODULE.pool_port;

    // check to see if the STRATUM_URL is an ip address already
    if (inet_pton(AF_INET, stratum_url, &ip_Addr) == 1) {
        bDNSFound = true;
    }
    else
    {
        ESP_LOGI(TAG, "Get IP for URL: %s\n", stratum_url);
        dns_gethostbyname(stratum_url, &ip_Addr, dns_found_cb, NULL);
        while (!bDNSFound);

        if (bDNSInvalid) {
            ESP_LOGE(TAG, "DNS lookup failed for URL: %s\n", stratum_url);
            //set ip_Addr to 0.0.0.0 so that connect() will fail
            IP_ADDR4(&ip_Addr, 0, 0, 0, 0);
        }

    }

    // make IP address string from ip_Addr
    snprintf(host_ip, sizeof(host_ip), "%d.%d.%d.%d", ip4_addr1(&ip_Addr.u_addr.ip4), ip4_addr2(&ip_Addr.u_addr.ip4),
             ip4_addr3(&ip_Addr.u_addr.ip4), ip4_addr4(&ip_Addr.u_addr.ip4));
    ESP_LOGI(TAG, "Connecting to: stratum+tcp://%s:%d (%s)\n", stratum_url, port, host_ip);

    while (1) {
        struct sockaddr_in dest_addr;
        dest_addr.sin_addr.s_addr = inet_addr(host_ip);
        dest_addr.sin_family = AF_INET;
        dest_addr.sin_port = htons(port);
        addr_family = AF_INET;
        ip_protocol = IPPROTO_IP;

        GLOBAL_STATE->sock = socket(addr_family, SOCK_STREAM, ip_protocol);
        if (GLOBAL_STATE->sock < 0) {
            ESP_LOGE(TAG, "Unable to create socket: errno %d", errno);
            ESP_LOGI(TAG, "Restarting System because of ERROR: Unable to create socket");
            vTaskDelay(1000 / portTICK_PERIOD_MS);
            esp_restart();
            break;
        }
        ESP_LOGI(TAG, "Socket created, connecting to %s:%d", host_ip, port);

        int err = connect(GLOBAL_STATE->sock, (struct sockaddr *)&dest_addr, sizeof(struct sockaddr_in6));
        if (err != 0)
        {
            ESP_LOGE(TAG, "Socket unable to connect to %s:%d (errno %d)", stratum_url, port, errno);
            // close the socket
            shutdown(GLOBAL_STATE->sock, SHUT_RDWR);
            close(GLOBAL_STATE->sock);
            // instead of restarting, retry this every 5 seconds
            vTaskDelay(5000 / portTICK_PERIOD_MS);
            continue;
        }

        ///// Start Stratum Action
        // mining.subscribe - ID: 1
        STRATUM_V1_subscribe(GLOBAL_STATE->sock, GLOBAL_STATE->asic_model);

        // mining.configure - ID: 2
        STRATUM_V1_configure_version_rolling(GLOBAL_STATE->sock, &GLOBAL_STATE->version_mask);

        //mining.suggest_difficulty - ID: 3
        STRATUM_V1_suggest_difficulty(GLOBAL_STATE->sock, STRATUM_DIFFICULTY);

        char * username = nvs_config_get_string(NVS_CONFIG_STRATUM_USER, STRATUM_USER);
        char * password = nvs_config_get_string(NVS_CONFIG_STRATUM_PASS, STRATUM_PW);

        //mining.authorize - ID: 4
        STRATUM_V1_authenticate(GLOBAL_STATE->sock, username, password);
        free(password);
        free(username);

        while (1) {
            char * line = STRATUM_V1_receive_jsonrpc_line(GLOBAL_STATE->sock);
            ESP_LOGI(TAG, "rx: %s", line); // debug incoming stratum messages
            STRATUM_V1_parse(&stratum_api_v1_message, line);
            free(line);

            if (stratum_api_v1_message.method == MINING_NOTIFY) {
                SYSTEM_notify_new_ntime(&GLOBAL_STATE->SYSTEM_MODULE, stratum_api_v1_message.mining_notification->ntime);
                if (stratum_api_v1_message.should_abandon_work &&
                    (GLOBAL_STATE->stratum_queue.count > 0 || GLOBAL_STATE->ASIC_jobs_queue.count > 0)) {
                    ESP_LOGI(TAG, "abandoning work");

                    GLOBAL_STATE->abandon_work = 1;
                    queue_clear(&GLOBAL_STATE->stratum_queue);

                    pthread_mutex_lock(&GLOBAL_STATE->valid_jobs_lock);
                    ASIC_jobs_queue_clear(&GLOBAL_STATE->ASIC_jobs_queue);
                    for (int i = 0; i < 128; i = i + 4) {
                        GLOBAL_STATE->valid_jobs[i] = 0;
                    }
                    pthread_mutex_unlock(&GLOBAL_STATE->valid_jobs_lock);
                }
                if (GLOBAL_STATE->stratum_queue.count == QUEUE_SIZE) {
                    mining_notify * next_notify_json_str = (mining_notify *) queue_dequeue(&GLOBAL_STATE->stratum_queue);
                    STRATUM_V1_free_mining_notify(next_notify_json_str);
                }

                stratum_api_v1_message.mining_notification->difficulty = SYSTEM_TASK_MODULE.stratum_difficulty;
                queue_enqueue(&GLOBAL_STATE->stratum_queue, stratum_api_v1_message.mining_notification);
				
				stratum_update_work_stats(&stratum_api_v1_message);
				
            } else if (stratum_api_v1_message.method == MINING_SET_DIFFICULTY) {
                if (stratum_api_v1_message.new_difficulty != SYSTEM_TASK_MODULE.stratum_difficulty) {
                    SYSTEM_TASK_MODULE.stratum_difficulty = stratum_api_v1_message.new_difficulty;
                    ESP_LOGI(TAG, "Set stratum difficulty: %ld", SYSTEM_TASK_MODULE.stratum_difficulty);
                }
            } else if (stratum_api_v1_message.method == MINING_SET_VERSION_MASK ||
                       stratum_api_v1_message.method == .0) {
                // 1fffe000
                ESP_LOGI(TAG, "Set version mask: %08lx", stratum_api_v1_message.version_mask);
                GLOBAL_STATE->version_mask = stratum_api_v1_message.version_mask;
            } else if (stratum_api_v1_message.method == STRATUM_RESULT_SUBSCRIBE) {
                GLOBAL_STATE->extranonce_str = stratum_api_v1_message.extranonce_str;
                GLOBAL_STATE->extranonce_2_len = stratum_api_v1_message.extranonce_2_len;
            } else if (stratum_api_v1_message.method == STRATUM_RESULT) {
                if (stratum_api_v1_message.response_success) {
                    ESP_LOGI(TAG, "message result accepted");
                    SYSTEM_notify_accepted_share(&GLOBAL_STATE->SYSTEM_MODULE);
                } else {
                    ESP_LOGE(TAG, "message result rejected");
                    SYSTEM_notify_rejected_share(&GLOBAL_STATE->SYSTEM_MODULE);
                }
            } else if (stratum_api_v1_message.method == STRATUM_RESULT_SETUP) {
                if (stratum_api_v1_message.response_success) {
                    ESP_LOGI(TAG, "setup message accepted");
                } else {
                    ESP_LOGE(TAG, "setup message rejected");
                }
            }
        }

        if (GLOBAL_STATE->sock != -1) {
            ESP_LOGE(TAG, "Shutting down socket and restarting...");
            shutdown(GLOBAL_STATE->sock, 0);
            close(GLOBAL_STATE->sock);
        }
    }
    vTaskDelete(NULL);
}
