// i2a.c - ITCMON ZMQ => ATCSMON bridge

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <zmq.h>
#include <cjson/cJSON.h>

#define MAX_ATCS_CONNECTIONS 100
#define DEFAULT_ATCS_PORT    4801
#define ZMQ_SUB_PORT         18001
#define KEEPALIVE_INTERVAL   120
#define MAX_PACKET           1024
#define RELOAD_INTERVAL      120 // seconds
#define STATUS_INTERVAL      3600 // write i2a.status once per hour
#define STATUS_FILE          "i2a.status"

#define BITS_CONTROL 0
#define BITS_STATUS  1

typedef unsigned char byte;

time_t get_file_mtime(const char *filename);

struct client {
    int udp_fd;
    struct sockaddr_in addr;
    time_t last_sent_to;
    time_t last_received_from;
    int active;
};

struct client clients[MAX_ATCS_CONNECTIONS];

/* Hourly status (i2a.status) */
static int max_clients_ever = 0;
static unsigned long zmq_packets_since_status = 0;
static time_t last_status_write = 0;

/* One field from the WIU "ind" array (switch / signal / hazard / bit / un). */
struct ind_field {
    char type;          /* 'w'=switch, 'g'=signal, 'h'=hazard, 'b'=bit, 'u'=un */
    char label[32];
};

struct wiu_map {
    char wiu_id[32];
    char mcp[20];
    char proto;
    int ibitsn;
    char *ibits;
    char sig[16];           /* signal table name, e.g. "UP" */
    struct ind_field *ind;  /* bit-field layout from WIU json (NULL if none) */
    int ind_count;
    struct wiu_map *next;
};

struct wiu_map *wiu_maps = NULL;
time_t last_wius_mtime = 0;
time_t last_reload_check = 0;

/* From rrdata.json — used to map signal bit values to aspect names */
cJSON *rrdata_root = NULL;
cJSON *signal_tables = NULL;

static void load_ind_from_json(struct wiu_map *m, cJSON *ind_arr);
cJSON *decode_data_to_indicators(struct wiu_map *map, const char *hex_data);

struct loaded_subdiv {
    char key[16];      // "802/041"
    time_t mtime;
    struct loaded_subdiv *next;
};

struct loaded_subdiv *loaded_subdivs = NULL;

char **stop_aspects = NULL;
int num_stops = 0;
int zsub_port = ZMQ_SUB_PORT;
char zsub_host[256] = "127.0.0.1";
int atcs_port = DEFAULT_ATCS_PORT;
int debug = 0;
int opposing_to_stop = 0; /* -a: treat opposing non-stop pair as stop */

// ====================== Helpers ======================

void bcd_encode(const char *str, byte *out, int digits) {
    int i = 0, j = 0;
    while (i < digits) {
        int d1 = (i < digits && str[i] >= '0' && str[i] <= '9') ? str[i++] - '0' : 0;
        int d2 = (i < digits && str[i] >= '0' && str[i] <= '9') ? str[i++] - '0' : 0;

        if (d1 == 0) d1 = 0xA;
        if (d2 == 0) d2 = 0xA;

        out[j++] = (d1 << 4) | d2;
    }
}

int find_bit_position(const char *ibits_list, const char *key) {
    if (!ibits_list || !key || !*key) return -1;

    char *list = strdup(ibits_list);
    if (!list) return -1;

    int pos = 0;
    char *ptr = list;
    char *token;

    while ((token = strsep(&ptr, ",")) != NULL) {
        // Trim leading/trailing whitespace
        while (*token == ' ' || *token == '\t') token++;
        char *end = token;
        while (*end) end++;
        while (end > token && (end[-1] == ' ' || end[-1] == '\t')) {
            end--;
            *end = '\0';
        }

        if (token[0] != '\0' && strcmp(token, key) == 0) {
            free(list);
            return pos;
        }
        pos++;
    }

    free(list);
    return -1;
}

void set_bit(byte *data, int list_pos, int num_bits) {
    if (list_pos < 0 || list_pos >= num_bits) return;

    int byte_idx = list_pos / 8;
    int bit_in_byte = 7 - (list_pos % 8);   // MSB-first: pos 0 = bit 7, pos 7 = bit 0

    data[byte_idx] |= (1u << bit_in_byte);
}

// ====================== WIU Subdivision On-Demand Loading ======================

int is_subdiv_loaded(const char *rr, const char *sub) {
    char key[16];
    snprintf(key, sizeof(key), "%s/%s", rr, sub);
    for (struct loaded_subdiv *ls = loaded_subdivs; ls; ls = ls->next) {
        if (strcmp(ls->key, key) == 0) return 1;
    }
    return 0;
}

void mark_subdiv_loaded(const char *rr, const char *sub, time_t mtime) {
    char key[16];
    snprintf(key, sizeof(key), "%s/%s", rr, sub);

    // Update if exists
    for (struct loaded_subdiv *ls = loaded_subdivs; ls; ls = ls->next) {
        if (strcmp(ls->key, key) == 0) {
            ls->mtime = mtime;
            return;
        }
    }

    // Add new
    struct loaded_subdiv *ls = calloc(1, sizeof(*ls));
    if (!ls) return;
    strncpy(ls->key, key, sizeof(ls->key)-1);
    ls->mtime = mtime;
    ls->next = loaded_subdivs;
    loaded_subdivs = ls;
}

time_t get_subdiv_mtime(const char *rr, const char *sub) {
    char path[256];
    snprintf(path, sizeof(path), "wius/%s/%s.json", rr, sub);
    return get_file_mtime(path);
}

void remove_wiu_mappings_for_subdiv(const char *rr, const char *sub) {
    struct wiu_map *prev = NULL;
    struct wiu_map *m = wiu_maps;
    while (m) {
        int match = 0;
        if (strlen(m->wiu_id) >= 12 && m->wiu_id[0] == '7' &&
            strncmp(m->wiu_id + 1, rr, 3) == 0 &&
            strncmp(m->wiu_id + 4, sub, 3) == 0) {
            match = 1;
        }
        if (match) {
            struct wiu_map *to_free = m;
            if (prev) {
                prev->next = m->next;
            } else {
                wiu_maps = m->next;
            }
            m = m->next;
            free(to_free->ibits);
            free(to_free->ind);
            free(to_free);
        } else {
            prev = m;
            m = m->next;
        }
    }
}

void load_wiu_subdiv(const char *rr, const char *sub) {
    char path[256];
    snprintf(path, sizeof(path), "wius/%s/%s%s.json", rr, rr, sub);

    remove_wiu_mappings_for_subdiv(rr, sub);  // clean old entries for reload

    FILE *f = fopen(path, "r");
    if (!f) {
        if (debug) printf("No subdiv file %s\n", path);
        return;
    }

    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *data = malloc(len + 1);
    if (!data) { fclose(f); return; }
    fread(data, 1, len, f);
    fclose(f);
    data[len] = '\0';

    cJSON *root = cJSON_Parse(data);
    free(data);
    if (!root) {
        printf("Failed to parse %s\n", path);
        return;
    }

    int count = 0;
    cJSON *waysides = cJSON_GetObjectItem(root, "waysides");
    if (waysides) {
        cJSON *w;
        cJSON_ArrayForEach(w, waysides) {
            cJSON *atcs = cJSON_GetObjectItem(w, "atcs");
            if (!atcs) continue;

            // Verify this WIU belongs to the subdiv
            const char *wid = w->string;
            if (strlen(wid) < 12 || wid[0] != '7' ||
                strncmp(wid + 1, rr, 3) != 0 ||
                strncmp(wid + 4, sub, 3) != 0) {
                continue;
            }

            struct wiu_map *m = calloc(1, sizeof(*m));
            if (!m) continue;
            strncpy(m->wiu_id, wid, sizeof(m->wiu_id)-1);
            cJSON *mcp_obj = cJSON_GetObjectItem(atcs, "mcp");
            if (mcp_obj && mcp_obj->valuestring) strncpy(m->mcp, mcp_obj->valuestring, sizeof(m->mcp)-1);
            cJSON *proto_obj = cJSON_GetObjectItem(atcs, "proto");
            if (proto_obj && proto_obj->valuestring) m->proto = proto_obj->valuestring[0];
            cJSON *ibitsn_obj = cJSON_GetObjectItem(atcs, "ibitsn");
            if (ibitsn_obj) m->ibitsn = ibitsn_obj->valueint;
            cJSON *ibits_obj = cJSON_GetObjectItem(atcs, "ibits");
            if (ibits_obj && ibits_obj->valuestring) m->ibits = strdup(ibits_obj->valuestring);

            cJSON *sig_obj = cJSON_GetObjectItem(w, "sig");
            if (sig_obj && cJSON_IsString(sig_obj) && sig_obj->valuestring)
                strncpy(m->sig, sig_obj->valuestring, sizeof(m->sig) - 1);

            /* Only use pre-defined ind templates — never invent them */
            load_ind_from_json(m, cJSON_GetObjectItem(w, "ind"));

            m->next = wiu_maps;
            wiu_maps = m;
            count++;
        }
    }
    cJSON_Delete(root);
    if (debug || count > 0) printf("Loaded %d WIU mappings from %s\n", count, path);
}

// ====================== Config ======================
void free_wiu_maps(void) {
    struct wiu_map *m = wiu_maps;
    while (m) {
        struct wiu_map *next = m->next;
        free(m->ibits);
        free(m->ind);
        free(m);
        m = next;
    }
    wiu_maps = NULL;
}

void free_rrdata(void) {
    if (rrdata_root) {
        cJSON_Delete(rrdata_root);
        rrdata_root = NULL;
        signal_tables = NULL;
    }
}

/* Open local/<name> first, then cwd. Copies the path used into used (if set). */
static FILE *fopen_config(const char *filename, char *used, size_t used_sz)
{
    char localpath[512];
    snprintf(localpath, sizeof(localpath), "local/%s", filename);
    FILE *f = fopen(localpath, "r");
    if (f) {
        if (used && used_sz) snprintf(used, used_sz, "%s", localpath);
        return f;
    }
    f = fopen(filename, "r");
    if (f && used && used_sz) snprintf(used, used_sz, "%s", filename);
    else if (used && used_sz) used[0] = '\0';
    return f;
}

/* Load signal aspect tables from rrdata.json */
void load_rrdata(const char *filename) {
    free_rrdata();
    char cfgpath[512];
    FILE *f = fopen_config(filename, cfgpath, sizeof(cfgpath));
    if (!f) {
        printf("No %s found (local/%s or ./%s) — signal aspects will show as [n]\n",
               filename, filename, filename);
        return;
    }
    filename = cfgpath;
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *data = malloc(len + 1);
    if (!data) { fclose(f); return; }
    size_t n = fread(data, 1, len, f);
    fclose(f);
    data[n] = '\0';

    rrdata_root = cJSON_Parse(data);
    free(data);
    if (!rrdata_root) {
        printf("Failed to parse %s\n", filename);
        return;
    }
    signal_tables = cJSON_GetObjectItem(rrdata_root, "signal_tables");
    if (signal_tables)
        printf("Config: loaded signal tables from %s\n", filename);
    else
        printf("Config: no signal_tables in %s\n", filename);
}

static const char *lookup_aspect(const char *sig_name, int val, char *fallback, size_t fb_len) {
    snprintf(fallback, fb_len, "[%d]", val);
    if (!signal_tables || !sig_name || !sig_name[0]) return fallback;
    cJSON *table = cJSON_GetObjectItem(signal_tables, sig_name);
    if (!table) return fallback;
    char key[16];
    snprintf(key, sizeof(key), "%d", val);
    cJSON *asp = cJSON_GetObjectItem(table, key);
    if (asp && cJSON_IsString(asp) && asp->valuestring)
        return asp->valuestring;
    return fallback;
}

/* Parse WIU "ind" array into map->ind / map->ind_count. Only defined fields are kept. */
static void load_ind_from_json(struct wiu_map *m, cJSON *ind_arr) {
    m->ind = NULL;
    m->ind_count = 0;
    if (!ind_arr || !cJSON_IsArray(ind_arr)) return;

    int n = cJSON_GetArraySize(ind_arr);
    if (n <= 0) return;
    m->ind = calloc((size_t)n, sizeof(struct ind_field));
    if (!m->ind) return;

    cJSON *item;
    cJSON_ArrayForEach(item, ind_arr) {
        if (!item || !cJSON_IsObject(item)) continue;
        cJSON *child = item->child; /* first key/value */
        if (!child || !child->string) continue;

        char type = 0;
        if (strcmp(child->string, "switch") == 0) type = 'w';
        else if (strcmp(child->string, "signal") == 0) type = 'g';
        else if (strcmp(child->string, "hazard") == 0) type = 'h';
        else if (strcmp(child->string, "bit") == 0) type = 'b';
        else if (strcmp(child->string, "un") == 0) type = 'u';
        else continue;

        m->ind[m->ind_count].type = type;
        m->ind[m->ind_count].label[0] = '\0';
        if (cJSON_IsString(child) && child->valuestring) {
            strncpy(m->ind[m->ind_count].label, child->valuestring,
                    sizeof(m->ind[m->ind_count].label) - 1);
        } else if (cJSON_IsNumber(child)) {
            snprintf(m->ind[m->ind_count].label, sizeof(m->ind[m->ind_count].label),
                     "%d", child->valueint);
        }
        m->ind_count++;
    }
    if (m->ind_count == 0) {
        free(m->ind);
        m->ind = NULL;
    }
}

time_t get_file_mtime(const char *filename) {
    struct stat st;
    if (stat(filename, &st) == 0) {
        return st.st_mtime;
    }
    return 0;
}

void load_i2a_config(const char *filename) {
    char cfgpath[512];
    FILE *f = fopen_config(filename, cfgpath, sizeof(cfgpath));
    if (!f) {
        printf("No %s found (local/%s or ./%s), using defaults\n",
               filename, filename, filename);
        return;
    }
    filename = cfgpath;
    
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *data = malloc(len + 1);
    fread(data, 1, len, f);
    fclose(f);
    data[len] = '\0';

    cJSON *root = cJSON_Parse(data);
    free(data);
    if (!root) {
        printf("Failed to parse %s\n", filename);
        return;
    }

    cJSON *port_obj = cJSON_GetObjectItem(root, "port");
    if (port_obj && cJSON_IsNumber(port_obj)) {
        atcs_port = port_obj->valueint;
        printf("Config: ATCSMON port set to %d\n", atcs_port);
    }

    /*
     * Optional ZMQ SUB source override (default 127.0.0.1:18001):
     *   "server": { "host": "127.0.0.1", "port": 20101 }
     * CLI -h / -r still override after this is loaded.
     */
    cJSON *server_obj = cJSON_GetObjectItem(root, "server");
    if (server_obj && cJSON_IsObject(server_obj)) {
        cJSON *host_obj = cJSON_GetObjectItem(server_obj, "host");
        cJSON *sport_obj = cJSON_GetObjectItem(server_obj, "port");
        if (host_obj && cJSON_IsString(host_obj) && host_obj->valuestring &&
            host_obj->valuestring[0]) {
            strncpy(zsub_host, host_obj->valuestring, sizeof(zsub_host) - 1);
            zsub_host[sizeof(zsub_host) - 1] = '\0';
        }
        if (sport_obj && cJSON_IsNumber(sport_obj) && sport_obj->valueint > 0) {
            zsub_port = sport_obj->valueint;
        }
        printf("Config: ZMQ SUB server set to %s:%d\n", zsub_host, zsub_port);
    }

    cJSON *stops_arr = cJSON_GetObjectItem(root, "stops");
    if (stops_arr && cJSON_IsArray(stops_arr)) {
        num_stops = cJSON_GetArraySize(stops_arr);
        stop_aspects = malloc(num_stops * sizeof(char*));
        int i = 0;
        cJSON *item;
        cJSON_ArrayForEach(item, stops_arr) {
            if (cJSON_IsString(item)) {
                stop_aspects[i++] = strdup(item->valuestring);
            }
        }
        printf("Config: Loaded %d stop aspects\n", num_stops);
    }

    cJSON_Delete(root);
}

// ====================== Config ======================

void load_wius_config(const char *filename) {
    free_wiu_maps();  // clear old mappings

    FILE *f = fopen(filename, "r");
    if (!f) { perror("can't open wius.json file"); return; }
    
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *data = malloc(len + 1);
    fread(data, 1, len, f);
    fclose(f);
    data[len] = '\0';

    cJSON *root = cJSON_Parse(data);
    free(data);
    if (!root) {printf("error loading wius.json"); return; }

    int count = 0;
    cJSON *waysides = cJSON_GetObjectItem(root, "waysides");
    if (waysides) {
        cJSON *w;
        cJSON_ArrayForEach(w, waysides) {
            cJSON *atcs = cJSON_GetObjectItem(w, "atcs");
            if (!atcs) continue;

            struct wiu_map *m = calloc(1, sizeof(*m));
            strncpy(m->wiu_id, w->string, sizeof(m->wiu_id)-1);
            cJSON *mcp_obj = cJSON_GetObjectItem(atcs, "mcp");
            if (mcp_obj) strncpy(m->mcp, mcp_obj->valuestring, sizeof(m->mcp)-1);
            cJSON *proto_obj = cJSON_GetObjectItem(atcs, "proto");
            if (proto_obj && proto_obj->valuestring) m->proto = proto_obj->valuestring[0];
            cJSON *ibitsn_obj = cJSON_GetObjectItem(atcs, "ibitsn");
            if (ibitsn_obj) m->ibitsn = ibitsn_obj->valueint;
            cJSON *ibits_obj = cJSON_GetObjectItem(atcs, "ibits");
            if (ibits_obj && ibits_obj->valuestring) m->ibits = strdup(ibits_obj->valuestring);

            m->next = wiu_maps;
            wiu_maps = m;
            count++;
        }
    }
    cJSON_Delete(root);
    printf("Loaded %d WIU mappings from %s\n", count, filename);
}

// ====================== Packet Builders ======================
/* ISO/IEC 13239 (formerly ISO/IEC 3309) */
void UpdateCrc(unsigned char ch, unsigned short *lpwCrc)
{
  ch = (ch^(unsigned char)((*lpwCrc) & 0x00FF));
  ch = (ch^(ch<<4));
  *lpwCrc = (*lpwCrc >> 8)^((unsigned short)ch << 8)^((unsigned short)ch<<3)^((unsigned short)ch>>4);
  return;
}

void ComputeCrc(byte *Data, int Length,
		byte *TransmitFirst, byte *TransmitSecond)
{
  unsigned char chBlock;
  unsigned short wCrc;

  wCrc = 0xFFFF;
  do {
    chBlock = *Data++;
    UpdateCrc(chBlock, &wCrc);
  } while (--Length);
  wCrc = ~wCrc;
  *TransmitFirst = (byte) (wCrc & 0xFF);
  *TransmitSecond = (byte) ((wCrc >> 8) & 0xFF);
  return;
}

int build_atcs_packet(byte *pkt, int btype, int genisys, const char *mcp, const byte *ind_data, int num_bits, int seq) {
    int num_bytes = (num_bits + 7) / 8;
    int n = 0;
    byte c1, c2;
    
    if (btype == BITS_STATUS)
	pkt[n++] = '#';  // 0x23
    else
	pkt[n++] = 0x01;
    // filled in at end
    pkt[n++] = 0;   // padding
    pkt[n++] = 0;   // blocks
    pkt[n++] = 0;   // header crc1
    pkt[n++] = 0;   // header crc2

    // atcs L3 header starts here
    pkt[n++] = 0x68; //[37] 2x = normal data (24 for atcs Ind?)
    pkt[n++] = 0;    // channel, should be zero
    pkt[n++] = seq  << 1; // tx seq#, bit 0 should be 0
    pkt[n++] = 0; // rx seq# (high 7 bits only)
    pkt[n++] = 0; // src/dst addr length //[45]

    // Destination (MCP) BCD
    byte dstbcd[16] = {0};
    bcd_encode("2802123456", dstbcd, 10);
    int dst_bytes = 10;
    memcpy(pkt + n, dstbcd, dst_bytes / 2);
    n += dst_bytes / 2;

    // Source
    byte srcbcd[16] = {0};
    int src_bytes = strlen(mcp);
    bcd_encode(mcp, srcbcd, src_bytes);
    memcpy(pkt + n, srcbcd, (src_bytes + 1) / 2);
    n += (src_bytes + 1) / 2;

    pkt[9] = ((src_bytes << 4 & 0xf0)) + (dst_bytes & 0x0f);

    // set dst address to be 2rrr (same rr as src)
    pkt[10] = 0x20 | (srcbcd[0] & 0x0f);
    pkt[11] = pkt[srcbcd[1]];

    pkt[n++] = 0; // facility length (low 7 bits), normally 0
    //L4-7 header starts here
    pkt[n++] = 0x24;  // message # (7 bits), more bit (lsb) is 1 if more parts
    pkt[n++] = 2;  // part # (7 bits), ack bit (lsb) is 1 if ack required
    pkt[n++] = 2;  // length (7 bits, uumber of parts to message), vital bit (lsb)
    
    // label, 2 bytes:
    int p1,p2,p3;
    if (btype == BITS_STATUS)
    { p1=9; p2=2; p3=11; }
    else
    { p1=9; p2=0; p3=1;  }
    pkt[n++] = ((p1 & 0x7f) << 1) | ((p2 & 0x04) >> 2);
    pkt[n++] = ((p2 & 0x03) << 6) | (p3 & 0x3f);

    pkt[n++] = 3;     // version#
    pkt[n++] = 0;     // data begins (first byte often revision #, starting at 1)
    if (genisys)
    {
	// send index,value pairs
	pkt[n++] = num_bytes * 2;
	pkt[n++] = 8;
	for (int nb = 0; nb < num_bytes; nb++)
	{
	    pkt[n++] = nb;
	    pkt[n++] = ind_data[nb];
	}
    }
    else // atcs
    {
	pkt[n++] = num_bytes;
	pkt[n++] = 8;
	memcpy(pkt + n, ind_data, num_bytes);
	n += num_bytes;
    }

    // this would be crc-16
    pkt[n++] = 0;
    pkt[n++] = 0;

    // n = total packet length including header and final crc)

    // build atcs packet header (5 bytes) after we know total length
    // 0x23, padding, #blocks, crc-16

// example: len=36 bytes  (data + 5 header + 2 crc)
// *8=288 bits
// +59/60 = 5.78   (5 blocks)
// 5*60=300 - 288 = 12 padding

    int totbits = n * 8;
    int blocks = (totbits + 59) / 60;
    int padding = (blocks * 60) - totbits;
    pkt[1] = padding;
    pkt[2] = blocks;
    //header crc
    ComputeCrc(pkt,3,&c1,&c2);
    pkt[3] = c1;
    pkt[4] = c2;

    // data crc
    ComputeCrc(pkt+5,n-7,&c1,&c2);
    pkt[n-2] = c1;
    pkt[n-1] = c2;

    return n;
}

int build_ares_packet(byte *pkt, int btype, const char *mcp, const byte *ind_data, int num_bits, int seq) {
    int num_bytes = (num_bits + 7) / 8;
    int n = 0;

    pkt[n++] = 0x7e;  
    pkt[n++] = 0x02;  // data channel 2
    pkt[n++] = 0;
    if (btype == BITS_STATUS)
	pkt[n++] = 0x26;  // 26=ARES Indication (24=ATCS I, 64=ATCS C, 66= ARES C)
    else
	pkt[n++] = 0x66;  // 26=ARES Indication (24=ATCS I, 64=ATCS C, 66= ARES C)
    pkt[n++] = 0;
    pkt[n++] = seq << 1; // tx seq#
    pkt[n++] = 0; // rx seq#
    pkt[n++] = 0; // src/dst addr length [+8]
    
    // Destination (MCP) BCD
    byte dstbcd[16] = {0};
    bcd_encode("2802123456", dstbcd, 10);
    int dst_bytes = 10;
    memcpy(pkt + n, dstbcd, dst_bytes / 2);
    n += dst_bytes / 2;

    // Source
    byte srcbcd[16] = {0};
    int src_bytes = strlen(mcp);
    bcd_encode(mcp, srcbcd, src_bytes);
    memcpy(pkt + n, srcbcd, (src_bytes + 1) / 2);
    n += (src_bytes + 1) / 2;

    pkt[7] = ((src_bytes << 4 & 0xf0)) + (dst_bytes & 0x0f);

    pkt[n++] = 0; pkt[n++] = 0; pkt[n++] = 0; pkt[n++] = 0; 

    // 9.2.11
    int p1,p2,p3;
    if (btype == BITS_STATUS)
    { p1=9; p2=2; p3=11;}
    else
    { p1=9; p2=0; p3=1;}
    pkt[n++] = ((p1 & 0x7f) << 1) | ((p2 & 0x04) >> 2);
    pkt[n++] = ((p2 & 0x03) << 6) | (p3 & 0x3f);

    pkt[n++] = 3;
    pkt[n++] = 0;
    pkt[n++] = num_bytes;
    pkt[n++] = 8;
    memcpy(pkt + n, ind_data, num_bytes);
    n += num_bytes;
    
#if 0
    // ares use 199.131 (C783 ares v0 indication)
    pkt[n++] = 199;
    pkt[n++] = 131;
    pkt[n++] = 0; pkt[n++] = 0; pkt[n++] = 0; pkt[n++] = 0; pkt[n++] = 0; pkt[n++] = 0; pkt[n++] = 0; pkt[n++] = 0; pkt[n++] = 0;
    pkt[n++] = num_bytes * 8;  //length of data (in BITS!)
    // convert data from bits to bytes (weird)
    for (int i = 0; i < num_bytes; i++)
    {
	    for (int j = 0; j < 8; j++)
	    {
		    // Extract the j-th bit from the current byte
		    if ((ind_data[i] & (0x80 >> j)) != 0)
			    pkt[n++] = 0x0a; // If bit is 1
		    else
			    pkt[n++] = 0x06; // If bit is 0
	    }
    }
#endif
    // this would be crc-16
    pkt[n++] = 0;
    pkt[n++] = 0;
    return n;
}

int build_genisys_packet(byte *pkt, int btype, const char *mcp, const byte *ind_data, int num_bits) {
    if (strlen(mcp) < 13) return 0;

    int num_bytes = (num_bits + 7) / 8;

    byte payload[512] = {0};
    int p = 0;

    if (btype == BITS_STATUS)
	payload[p++] = 0xf2;
    else
	payload[p++] = 0xfc;
    payload[p++] = atoi(mcp + 10) & 0x7F;

    for (int i = 0; i < num_bytes; i++) {
        payload[p++] = i;
        payload[p++] = ind_data[i];
    }

    payload[p++] = 0;
    payload[p++] = 0;

    pkt[0] = 'g';
    memcpy(pkt + 1, mcp+1, 9);

    int elen = 0;
    int data_pos = 11;

    pkt[data_pos + elen++] = 0xf2;

    for (int i = 1; i < p - 2; i++) {
        byte b = payload[i];
        if (b >= 0xf0) {
            pkt[data_pos + elen++] = 0xf0;
            pkt[data_pos + elen++] = b - 0xf0;
        } else {
            pkt[data_pos + elen++] = b;
        }
    }

    for (int i = p - 2; i < p; i++) {
        byte b = payload[i];
        if (b >= 0xf0) {
            pkt[data_pos + elen++] = 0xf0;
            pkt[data_pos + elen++] = b - 0xf0;
        } else {
            pkt[data_pos + elen++] = b;
        }
    }
    pkt[data_pos + elen++] = 0xf6;

    pkt[10] = elen;

    return data_pos + elen;
}

int build_scs_packet(byte *pkt, int btype, const char *mcp, const byte *ind_data, int num_bits) {
    if (strlen(mcp) < 13) return 0;

    int num_bytes = (num_bits + 7) / 8;
    int n = 0;

    pkt[n++] = 's';
    
    // MCP address chars 1-9
    memcpy(pkt + n, mcp + 1, 9);
    n += 9;

    // Station ID: last 3 digits as int & 0x7F
    //  *** supposed to set b7 high?
    int station_id = atoi(mcp + 10) & 0x7F;
    pkt[n++] = station_id;

    if (btype == BITS_STATUS)
	pkt[n++] = 0x81;    // Indication command
    else
	pkt[n++] = 0x83;    // Control command

    // Data length
    pkt[n++] = num_bytes;

    // Data bits
    memcpy(pkt + n, ind_data, num_bytes);
    n += num_bytes;

    // ** add 1 byte checksum?
    
    return n;
}


// ====================== Processing ======================

int is_stop_aspect(const char *aspect) {
    if (!aspect) return 0;
    for (int i = 0; i < num_stops; i++) {
        if (stop_aspects[i] && strstr(aspect, stop_aspects[i])) return 1;
    }
    return 0;
}

/*
 * Eligible for opposing-pair logic ONLY if label is exactly:
 *   optional digits + one of E|W|N|S
 * e.g. "E","W","1E","1W","2N","2S"
 * Labels with switch/track suffixes are NOT included (no stripping):
 *   "WN","WR","EN","ER","1EN","2ER", …
 * Returns 1 and fills prefix (e.g. "1" or "") and dir ('E'/'W'/'N'/'S').
 */
static int parse_eligible_opposing_label(const char *label, char *prefix, size_t prefix_sz, char *dir_out) {
    if (!label || !prefix || !dir_out || prefix_sz < 2) return 0;
    prefix[0] = '\0';
    *dir_out = 0;

    const char *p = label;
    size_t pi = 0;
    while (*p >= '0' && *p <= '9') {
        if (pi + 1 >= prefix_sz) return 0;
        prefix[pi++] = *p++;
    }
    prefix[pi] = '\0';

    if (!*p) return 0;
    char d = *p;
    if (d >= 'a' && d <= 'z') d = (char)(d - 'a' + 'A');
    if (d != 'E' && d != 'W' && d != 'N' && d != 'S') return 0;
    /* must be end of string — any suffix disqualifies the whole signal */
    if (p[1] != '\0') return 0;

    *dir_out = d;
    return 1;
}

static char opposing_dir(char d) {
    if (d == 'E') return 'W';
    if (d == 'W') return 'E';
    if (d == 'N') return 'S';
    if (d == 'S') return 'N';
    return 0;
}

struct wiu_map *find_map(const char *wiu_id) {
    for (struct wiu_map *m = wiu_maps; m; m = m->next)
        if (strcmp(m->wiu_id, wiu_id) == 0) return m;
    return NULL;
}

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Convert hex string (e.g. "34D5E6") to MSB-first bit chars '0'/'1'. Returns bit count. */
static int hex_to_bitstring(const char *hex, char *bits, int bits_cap) {
    int nbits = 0;
    int hi = -1;
    for (const char *p = hex; *p; p++) {
        if (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') continue;
        int nib = hex_nibble(*p);
        if (nib < 0) continue;
        if (hi < 0) {
            hi = nib;
        } else {
            int byte = (hi << 4) | nib;
            hi = -1;
            for (int b = 7; b >= 0; b--) {
                if (nbits + 1 >= bits_cap) return nbits;
                bits[nbits++] = (byte & (1 << b)) ? '1' : '0';
            }
        }
    }
    /* odd nibble: treat as high nibble of a partial byte (should not happen) */
    if (hi >= 0) {
        int byte = hi << 4;
        for (int b = 7; b >= 0; b--) {
            if (nbits + 1 >= bits_cap) break;
            bits[nbits++] = (byte & (1 << b)) ? '1' : '0';
        }
    }
    bits[nbits] = '\0';
    return nbits;
}

static int read_bits_val(const char *bits, int nbits, int *pos, int count) {
    if (*pos + count > nbits) return -1;
    int v = 0;
    for (int i = 0; i < count; i++)
        v = (v << 1) | (bits[(*pos)++] == '1' ? 1 : 0);
    return v;
}

/*
 * Build the same indicators JSON array the old ZMQ publisher used to send,
 * by walking map->ind against the raw data hex (same rules as itcmon.py):
 *   switch = 2 bits  (0=I,1=N,2=R,3=X) → {"switch":"<label><I|N|R|X>W"}
 *   signal = 5 bits reversed            → {"signal":"<label>","aspect":"..."}
 *   hazard = 1 bit                      → {"hazard":...,"ind":"X"|"OK"}
 *   bit/un = 1 bit                      → {key:label,"ind":val}
 *
 * If the WIU has no "ind" template, returns NULL (do not invent fields).
 */
cJSON *decode_data_to_indicators(struct wiu_map *map, const char *hex_data) {
    if (!map || !hex_data || !map->ind || map->ind_count <= 0) return NULL;

    char bits[4096];
    int nbits = hex_to_bitstring(hex_data, bits, (int)sizeof(bits));
    if (nbits <= 0) return NULL;

    cJSON *arr = cJSON_CreateArray();
    if (!arr) return NULL;

    int pos = 0;
    static const char swmap[] = "INRX";

    for (int i = 0; i < map->ind_count; i++) {
        struct ind_field *f = &map->ind[i];
        if (f->type == 'w') {
            int val = read_bits_val(bits, nbits, &pos, 2);
            if (val < 0) break;
            if (val > 3) val = 3;
            char swval[48];
            snprintf(swval, sizeof(swval), "%s%cW", f->label, swmap[val]);
            cJSON *obj = cJSON_CreateObject();
            cJSON_AddStringToObject(obj, "switch", swval);
            cJSON_AddItemToArray(arr, obj);
        } else if (f->type == 'g') {
            if (pos + 5 > nbits) break;
            /* Reverse the 5 bits (itcmon / ATCS signal encoding) */
            char b5[6];
            for (int k = 0; k < 5; k++) b5[k] = bits[pos + k];
            b5[5] = '\0';
            pos += 5;
            for (int k = 0; k < 2; k++) {
                char t = b5[k];
                b5[k] = b5[4 - k];
                b5[4 - k] = t;
            }
            int val = 0;
            for (int k = 0; k < 5; k++)
                val = (val << 1) | (b5[k] == '1' ? 1 : 0);

            char fallback[32];
            const char *aspect = lookup_aspect(map->sig, val, fallback, sizeof(fallback));
            cJSON *obj = cJSON_CreateObject();
            cJSON_AddStringToObject(obj, "signal", f->label);
            cJSON_AddStringToObject(obj, "aspect", aspect);
            cJSON_AddItemToArray(arr, obj);
        } else if (f->type == 'h') {
            int val = read_bits_val(bits, nbits, &pos, 1);
            if (val < 0) break;
            cJSON *obj = cJSON_CreateObject();
            /* label may be numeric string */
            char *end = NULL;
            long hnum = strtol(f->label, &end, 10);
            if (end && *end == '\0' && f->label[0] != '\0')
                cJSON_AddNumberToObject(obj, "hazard", (double)hnum);
            else
                cJSON_AddStringToObject(obj, "hazard", f->label);
            cJSON_AddStringToObject(obj, "ind", val == 0 ? "X" : "OK");
            cJSON_AddItemToArray(arr, obj);
        } else if (f->type == 'b' || f->type == 'u') {
            int val = read_bits_val(bits, nbits, &pos, 1);
            if (val < 0) break;
            cJSON *obj = cJSON_CreateObject();
            cJSON_AddStringToObject(obj, f->type == 'b' ? "bit" : "un", f->label);
            cJSON_AddNumberToObject(obj, "ind", val);
            cJSON_AddItemToArray(arr, obj);
        }
    }

    if (debug) {
        char *s = cJSON_PrintUnformatted(arr);
        printf("  decoded indicators from data: %s\n", s ? s : "(null)");
        free(s);
    }
    return arr;
}

/*
 * Pure opposing E↔W / N↔S (± numeric prefix) with the same aspect string
 * are treated as stops (do not set GK). Suffixed names (WN, ER, 1EN, …)
 * are never part of this pairing.
 */
#define MAX_OPPOSE_SIGS 64

byte *process_wiu(cJSON *indicators, struct wiu_map *map) {
    int num_bytes = (map->ibitsn + 7) / 8;
    byte *data = calloc(1, num_bytes);
    if (!data) return NULL;

    if (debug) {
        printf("  MCP %s ibits %s\n", map->mcp, map->ibits ? map->ibits : "NULL");
//        printf("  ibits for %s: %s\n", map->wiu_id, map->ibits ? map->ibits : "NULL");
    }

    /* --- Pass 1: collect pure-direction signals for opposing-pair check --- */
    struct {
        char label[32];
        char aspect[64];
        char prefix[16];
        char dir;
        int force_stop;
    } pure[MAX_OPPOSE_SIGS];
    int npure = 0;

    cJSON *item;
    cJSON_ArrayForEach(item, indicators) {
        cJSON *sig = cJSON_GetObjectItem(item, "signal");
        cJSON *asp = cJSON_GetObjectItem(item, "aspect");
        if (!sig || !sig->valuestring || !asp || !asp->valuestring) continue;
        if (npure >= MAX_OPPOSE_SIGS) break;

        char prefix[16];
        char dir = 0;
        if (!parse_eligible_opposing_label(sig->valuestring, prefix, sizeof(prefix), &dir))
            continue; /* has suffix or not pure E/W/N/S — skip pairing entirely */

        strncpy(pure[npure].label, sig->valuestring, sizeof(pure[npure].label) - 1);
        pure[npure].label[sizeof(pure[npure].label) - 1] = '\0';
        strncpy(pure[npure].aspect, asp->valuestring, sizeof(pure[npure].aspect) - 1);
        pure[npure].aspect[sizeof(pure[npure].aspect) - 1] = '\0';
        strncpy(pure[npure].prefix, prefix, sizeof(pure[npure].prefix) - 1);
        pure[npure].prefix[sizeof(pure[npure].prefix) - 1] = '\0';
        pure[npure].dir = dir;
        pure[npure].force_stop = 0;
        npure++;
    }

    /*
     * Optional (-a): pair E↔W and N↔S with same prefix; if BOTH are non-stop
     * aspects, force-stop both (opposing moves both showing proceed).
     */
    if (opposing_to_stop) {
        for (int i = 0; i < npure; i++) {
            char opp = opposing_dir(pure[i].dir);
            if (!opp) continue;
            /* only seed from E and N so each pair is handled once */
            if (pure[i].dir != 'E' && pure[i].dir != 'N') continue;

            for (int j = 0; j < npure; j++) {
                if (i == j) continue;
                if (pure[j].dir != opp) continue;
                if (strcmp(pure[i].prefix, pure[j].prefix) != 0) continue;
                if (is_stop_aspect(pure[i].aspect) || is_stop_aspect(pure[j].aspect))
                    continue; /* at least one is already stop — leave alone */

                pure[i].force_stop = 1;
                pure[j].force_stop = 1;
                if (debug) {
                    printf("  Opposing %s/%s non-stop ('%s'/'%s') → treat as stop\n",
                           pure[i].label, pure[j].label,
                           pure[i].aspect, pure[j].aspect);
                }
                break;
            }
        }
    }

    /* --- Pass 2: build ATCS indication bits --- */
    cJSON_ArrayForEach(item, indicators) {
        cJSON *sw = cJSON_GetObjectItem(item, "switch");
        cJSON *sig = cJSON_GetObjectItem(item, "signal");
        cJSON *asp = cJSON_GetObjectItem(item, "aspect");

        char key[32] = {0};

        if (sw && sw->valuestring) {
            snprintf(key, sizeof(key), "%sK", sw->valuestring);
	    
	    int pos = find_bit_position(map->ibits, key);
	    if (pos >= 0) {
                set_bit(data, pos, map->ibitsn);
                if (debug) printf("  Set switch %sK at pos %d\n", sw->valuestring, pos);
            } else if (debug) {
                printf("  No match for switch key %s\n", key);
            }
        } else if (sig && sig->valuestring && asp && asp->valuestring) {
            const char *sval = sig->valuestring;
            const char *aval = asp->valuestring;

            int force_stop = 0;
            for (int k = 0; k < npure; k++) {
                if (strcmp(pure[k].label, sval) == 0 && pure[k].force_stop) {
                    force_stop = 1;
                    break;
                }
            }

            char base[32] = {0};
            strncpy(base, sval, sizeof(base)-1);
            base[sizeof(base)-1] = '\0';   // ensure null termination

	    // signal format: [prefix]<direction>[N|R]
	    // check for prefix to find if direction is char  0 or 1
	    // then if a char N or R follows, remove it
            size_t len = strlen(base);
	    int dirp = 0;  // assume direction is [0]
	    if ((base[0] != 'E') && (base[0] != 'W') && (base[0] != 'N') && (base[0] != 'S'))
		    dirp = 1; // direction must be [1]
	    if ((base[dirp+1] == 'N') || (base[dirp+1] == 'R'))
		    base[dirp+1] = 0;
	    base[dirp+2] = 0;

#if 0
            // Stronger normalization for direction (strip N/R track suffix for ibits key)
            if (len >= 1) {
                char last = base[len-1];
                if (last == 'N' || last == 'R') {
                    base[len-1] = '\0';
                }
            }
#endif
            snprintf(key, sizeof(key), "%sGK", base);

            int treat_stop = force_stop || is_stop_aspect(aval);
            int pos = find_bit_position(map->ibits, key);
            if (pos >= 0 && !treat_stop) {
                set_bit(data, pos, map->ibitsn);
                if (debug) printf("  Set signal %s (aspect %s) -> key %s at pos %d\n", sval, aval, key, pos);
            } else if (debug && treat_stop) {
                printf("  Skip signal %s (aspect %s)%s\n",
                       sval, aval, force_stop ? " [opposing pair stop]" : " [stop aspect]");
            } else if (debug && !treat_stop) {
                printf("  No match for signal %s -> key %s in ibits\n", sval, key);
            }
        }
    }
    return data;
}

static int hex_char_to_int(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/**
 * Converts a hex string to a byte array.
 * 
 * @param hexs Pointer to the null-terminated hex string.
 * @param out  Pointer to the destination byte buffer.
 * @return     The number of bytes written, or -1 on failure.
 */
int hexstr_to_bytes(char *hexs, byte *out) {
    if (!hexs || !out) return -1;

    // Skip optional "0x" or "0X" prefix
    if (hexs[0] == '0' && (hexs[1] == 'x' || hexs[1] == 'X')) {
        hexs += 2;
    }

    int bytes_written = 0;

    while (*hexs != '\0') {
        int hi = hex_char_to_int(*hexs++);
        if (hi < 0) return -1; // Invalid hex digit

        if (*hexs == '\0') {
            // Odd length hex string is invalid
            return -1; 
        }

        int lo = hex_char_to_int(*hexs++);
        if (lo < 0) return -1; // Invalid hex digit

        out[bytes_written++] = (byte)((hi << 4) | lo);
    }

    return bytes_written;
}

// ====================== Client Mgmt ======================

static int count_active_clients(void) {
    int n = 0;
    for (int i = 0; i < MAX_ATCS_CONNECTIONS; i++)
        if (clients[i].active) n++;
    return n;
}

/* Overwrite STATUS_FILE with current stats; resets zmq packet counter. */
static void write_i2a_status(void) {
    int cur = count_active_clients();
    if (cur > max_clients_ever)
        max_clients_ever = cur;

    FILE *f = fopen(STATUS_FILE, "w");
    if (!f) {
        perror(STATUS_FILE);
        return;
    }
    time_t now = time(NULL);
    char tbuf[32];
    struct tm *tm = localtime(&now);
    if (tm)
        strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", tm);
    else
        snprintf(tbuf, sizeof(tbuf), "%ld", (long)now);

    fprintf(f, "timestamp: %s\n", tbuf);
    fprintf(f, "clients_connected: %d\n", cur);
    fprintf(f, "clients_max_ever: %d\n", max_clients_ever);
    fprintf(f, "zmq_packets_since_last_status: %lu\n", zmq_packets_since_status);
    fclose(f);

    if (debug)
        printf("Wrote %s: clients=%d max=%d zmq_pkts=%lu\n",
               STATUS_FILE, cur, max_clients_ever, zmq_packets_since_status);

    zmq_packets_since_status = 0;
    last_status_write = now;
}

int add_client(int tcp_fd) {
    struct sockaddr_in client_addr;
    socklen_t clen = sizeof(client_addr);
    int newtcp = accept(tcp_fd, (struct sockaddr*)&client_addr, &clen);
    if (newtcp < 0) return -1;

    char ipstr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr.sin_addr, ipstr, sizeof(ipstr));
    int client_port = ntohs(client_addr.sin_port);

    if (debug)
        printf("DEBUG: TCP connection from %s:%d\n", ipstr, client_port);

    for (int i = 0; i < MAX_ATCS_CONNECTIONS; i++) {
        if (clients[i].active) continue;

        int udp = socket(AF_INET, SOCK_DGRAM, 0);
        struct sockaddr_in local = {0};
        local.sin_family = AF_INET;
        local.sin_addr.s_addr = INADDR_ANY;
        local.sin_port = 0;

        bind(udp, (struct sockaddr*)&local, sizeof(local));
        socklen_t sl = sizeof(local);
        getsockname(udp, (struct sockaddr*)&local, &sl);
        int our_port = ntohs(local.sin_port);

        char buf[64];
        snprintf(buf, sizeof(buf), "%d\n", our_port);
        write(newtcp, buf, strlen(buf));
        close(newtcp);

        clients[i].udp_fd = udp;
        clients[i].addr.sin_family = AF_INET;
        clients[i].addr.sin_addr = client_addr.sin_addr;
        clients[i].addr.sin_port = htons(client_port);

        // Initialize both timers to current time on connection
        time_t now = time(NULL);
        clients[i].last_sent_to = now;
        clients[i].last_received_from = now;
        clients[i].active = 1;
        {
            int cur = count_active_clients();
            if (cur > max_clients_ever)
                max_clients_ever = cur;
        }

        if (debug)
            printf("Client registered: %s:%d (our UDP port %d) at slot %d\n", ipstr, client_port, our_port, i);
        return i;
    }

    close(newtcp);
    return -1;
}

void broadcast_packet(const byte *pkt, int plen) {
    if (plen <= 0) return;

    time_t now = time(NULL);
    
    for (int i = 0; i < MAX_ATCS_CONNECTIONS; i++) {
        if (!clients[i].active) continue;

        sendto(clients[i].udp_fd, pkt, plen, 0,
               (struct sockaddr*)&clients[i].addr, sizeof(clients[i].addr));
        
        // Since we just sent them a valid data packet, reset their outbound 2-minute timer
        clients[i].last_sent_to = now;
    }
}

void check_keepalives(void) {
    time_t now = time(NULL);
    static const char keep[] = "*KEEPALIVE";
    
    for (int i = 0; i < MAX_ATCS_CONNECTIONS; i++) {
        if (!clients[i].active) continue;

        // 1. Inbound Check: Time out client if no messages received from them in 5 minutes (300s)
        if (now - clients[i].last_received_from > 300) {
            if (debug) {
                char ipstr[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &clients[i].addr.sin_addr, ipstr, sizeof(ipstr));
                printf("Client %s:%d timed out (no inbound traffic for 5 mins). Disconnecting slot %d.\n", 
                       ipstr, ntohs(clients[i].addr.sin_port), i);
            }
            close(clients[i].udp_fd);
            memset(&clients[i], 0, sizeof(struct client));
            continue;
        }

        // 2. Outbound Check: Ensure they get *something* every 2 minutes (120s)
        if (now - clients[i].last_sent_to > KEEPALIVE_INTERVAL) {
            sendto(clients[i].udp_fd, keep, 10, 0,
                   (struct sockaddr*)&clients[i].addr, sizeof(clients[i].addr));
            
            // Reset outbound timer now that a keepalive was pushed out
            clients[i].last_sent_to = now;
        }
    }
}

// ====================== Main ======================

/* Must run before any ZMQ context/socket — libzmq I/O threads do not survive fork(). */
static void go_background(void)
{
    pid_t pid = fork();
    if (pid < 0) {
        perror("[i2a] fork");
        exit(1);
    }
    if (pid > 0)
        exit(0);
    if (setsid() < 0) {
        perror("[i2a] setsid");
        exit(1);
    }
    int fd = open("/dev/null", O_RDWR);
    if (fd >= 0) {
        dup2(fd, STDIN_FILENO);
        dup2(fd, STDOUT_FILENO);
        dup2(fd, STDERR_FILENO);
        if (fd > 2)
            close(fd);
    }
}

int main(int argc, char **argv) {
    int opt;
    int wantctc = 0;
    int ctc = 0, ptc = 0;
    int background = 0;
    
    printf("BEGIN  V1.0\n");
    
    load_i2a_config("i2a.json");
    load_rrdata("rrdata.json");

    while ((opt = getopt(argc, argv, "Dr:h:cab")) != -1) {
        switch (opt) {
        case 'c': wantctc = 1;  break;
        case 'a': opposing_to_stop = 1; break;
        case 'b': background = 1; break;
        case 'r': zsub_port = atoi(optarg);  break;
        case 'h':
            strncpy(zsub_host, optarg, sizeof(zsub_host) - 1);
            zsub_host[sizeof(zsub_host) - 1] = '\0';
            break;
        case 'D': debug = 1; break;
        }
    }
    if (opposing_to_stop)
        printf("Opposing non-stop pair => force stop enabled (-a)\n");

    if (background && !debug) {
        printf("[i2a] background (-b): daemonizing before ZMQ init\n");
        fflush(stdout);
        go_background();
    }

    void *ctx = zmq_ctx_new();
    void *sub = zmq_socket(ctx, ZMQ_SUB);
    char addr[320];

    snprintf(addr, sizeof(addr), "tcp://%s:%d", zsub_host, zsub_port);
    if (!background || debug)
        printf("ZMQ SUB connecting to %s\n", addr);
    zmq_connect(sub, addr);
    zmq_setsockopt(sub, ZMQ_SUBSCRIBE, "", 0);

    int tcp = socket(AF_INET, SOCK_STREAM, 0);
    int sopt = 1;
    setsockopt(tcp, SOL_SOCKET, SO_REUSEADDR, &sopt, sizeof(sopt));

    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(atcs_port);
    sa.sin_addr.s_addr = INADDR_ANY;
    bind(tcp, (struct sockaddr*)&sa, sizeof(sa));
    listen(tcp, 8);

    byte pktbuf[MAX_PACKET];

    // Allocate variable poll items to accommodate the base sockets + active client UDP descriptors
    zmq_pollitem_t items[2 + MAX_ATCS_CONNECTIONS];

    if (debug) printf("Waiting...\n");
    last_status_write = time(NULL);
    max_clients_ever = 0;
    zmq_packets_since_status = 0;
    
    while (1) {
        // Setup fixed pollers
        items[0].socket = sub;
        items[0].fd = 0;
        items[0].events = ZMQ_POLLIN;
        items[0].revents = 0;

        items[1].socket = NULL;
        items[1].fd = tcp;
        items[1].events = ZMQ_POLLIN;
        items[1].revents = 0;

        // Dynamically add active client UDP sockets to the poll group
        int active_client_map[MAX_ATCS_CONNECTIONS];
        int item_count = 2;

        for (int i = 0; i < MAX_ATCS_CONNECTIONS; i++) {
            if (clients[i].active) {
                items[item_count].socket = NULL;
                items[item_count].fd = clients[i].udp_fd;
                items[item_count].events = ZMQ_POLLIN;
                items[item_count].revents = 0;
                active_client_map[item_count - 2] = i; // Store back-reference to our clients array
                item_count++;
            }
        }

        int rc = zmq_poll(items, item_count, 500);

         // Periodic reload check for all loaded subdivision files (~every 2 minutes)
        time_t now = time(NULL);
        if (now - last_reload_check >= RELOAD_INTERVAL) {
            struct loaded_subdiv *ls = loaded_subdivs;
            while (ls) {
                // Parse key "802/041" into rr and sub
                char rr[4] = {0}, sub[5] = {0};
                char *slash = strchr(ls->key, '/');
                if (slash) {
                    strncpy(rr, ls->key, slash - ls->key);
                    strncpy(sub, slash + 1, 3);
                }
                time_t current_mtime = get_subdiv_mtime(rr, sub);
                if (current_mtime > ls->mtime && current_mtime > 0) {
                    printf("Subdiv %s changed, reloading...\n", ls->key);
                    load_wiu_subdiv(rr, sub);
                    ls->mtime = current_mtime;
                }
                ls = ls->next;
            }
            last_reload_check = now;
        }

        /* Overwrite i2a.status once per hour */
        if (now - last_status_write >= STATUS_INTERVAL)
            write_i2a_status();
    
        if (rc > 0) {
            // 1. ZMQ processing
            if (items[0].revents & ZMQ_POLLIN) {
                char zmsg[4096] = {0};
                int zlen = zmq_recv(sub, zmsg, sizeof(zmsg)-1, 0);
                if (zlen > 0) {
                    zmq_packets_since_status++;
                    zmsg[zlen] = '\0';
                    //if (debug) printf("Rcvd %s\n", zmsg);
                    cJSON *root = cJSON_Parse(zmsg);
                    if (root) {
  		        cJSON *protocol = cJSON_GetObjectItem(root, "proto");
			if (wantctc)
			{
			    if (!strcmp(protocol->valuestring,"CTC")) ctc = 1; else ctc = 0;
			    if (debug && ctc) printf("Rcvd %s\n", zmsg);
			}
			else
			{
			    if (!strcmp(protocol->valuestring,"PTC")) ptc = 1; else ptc = 0;
			    if (debug && ptc) printf("Rcvd %s\n", zmsg);
			}
  		        cJSON *subtype = cJSON_GetObjectItem(root, "type");
                        cJSON *wiu_id_obj = cJSON_GetObjectItem(root, "WIUID");
                        cJSON *data_obj = cJSON_GetObjectItem(root, "data");
                        cJSON *inds_in = cJSON_GetObjectItem(root, "indicators"); /* legacy optional */
                        const char *wiu_id_str = NULL;
                        char wiu_id_buf[32] = {0};
                        if (wiu_id_obj && cJSON_IsString(wiu_id_obj) && wiu_id_obj->valuestring) {
                            wiu_id_str = wiu_id_obj->valuestring;
                        } else if (wiu_id_obj && cJSON_IsNumber(wiu_id_obj)) {
                            /* itcmon sometimes used numeric WIUID */
                            snprintf(wiu_id_buf, sizeof(wiu_id_buf), "%.0f", wiu_id_obj->valuedouble);
                            wiu_id_str = wiu_id_buf;
                        }

                        // On-demand load of subdivision file if needed
                        if (wiu_id_str && strlen(wiu_id_str) >= 12 && wiu_id_str[0] == '7') {
                            char rr[4] = {0}, sub[5] = {0};
                            strncpy(rr, wiu_id_str + 1, 3);
                            strncpy(sub, wiu_id_str + 4, 3);
                            if (!is_subdiv_loaded(rr, sub)) {
                                load_wiu_subdiv(rr, sub);
                                time_t mt = get_subdiv_mtime(rr, sub);
                                mark_subdiv_loaded(rr, sub, mt);
                            }
                        }

                        struct wiu_map *map = NULL;
                        if (wiu_id_str)
                            map = find_map(wiu_id_str);

			if (map && (ctc || ptc))
			{
			int bitcount = 0;
			byte *bits = NULL;
		        if (ctc)
			{
			    int dcount = 0;
			    char dbytes[256];
			    // printf(" ctc hex data %s\n",data_obj->valuestring);
			    int bcount = hexstr_to_bytes(data_obj->valuestring,dbytes);
			    // printf("  bcount %d\n",bcount);
			    if (bcount > 3)
			    {
				bits = calloc(1, 256);
				dcount = dbytes[1];
				if ((dbytes[0] == 0) && (dbytes[2] == 8))  // fmt 0: count rembits [bytes...]
				{
				    memcpy(bits,dbytes+3,dcount);
				}
#if 0			
				// can't do these unless we keep memory of previous bits
				else if (dbytes[0] < 3) // fmt 1 or 2: count of pairs
				{
				    dcount *= 2;  if (dcount > 254) dcount = 254;
				    memcpy(bits,dbytes+1,dcount);
				}
#endif
				bitcount = 8 * dcount;
				//printf("  bitcount %d\n",bitcount);
			    }
			}
			else
			{
			    /* Prefer data hex → decode via WIU "ind"; fall back to legacy indicators */
			    cJSON *inds = NULL;
			    int inds_owned = 0;
			    if (map && data_obj && cJSON_IsString(data_obj) && data_obj->valuestring) {
				if (map->ind && map->ind_count > 0) {
				    inds = decode_data_to_indicators(map, data_obj->valuestring);
				    inds_owned = (inds != NULL);
				} else if (debug) {
				    printf("  WIU %s has data but no ind template — skip\n", wiu_id_str);
				}
			    } else if (map && inds_in && cJSON_IsArray(inds_in)) {
				inds = inds_in;
				inds_owned = 0;
			    }
			    if (map && inds) {
				bits = process_wiu(inds, map);
				if (inds_owned) cJSON_Delete(inds);
				bitcount = map->ibitsn;
			    }
			}

			if (bits) {
			    int plen = 0;
			    int seq = 0;
			    cJSON *seq_obj = cJSON_GetObjectItem(root, "seq");
			    if (seq_obj && cJSON_IsNumber(seq_obj)) {
				seq = seq_obj->valueint;
			    }
			    int btype = BITS_STATUS;
			    if (ctc && (*subtype->valuestring == 'C')) btype = BITS_CONTROL;
			    if (map->proto == 'g') {
				plen = build_genisys_packet(pktbuf, btype, map->mcp, bits, bitcount);
			    } else if (map->proto == '#') {
				plen = build_atcs_packet(pktbuf, btype, 0,  map->mcp, bits, bitcount, seq); // atcs
			    } else if (map->proto == 'G') {
				plen = build_atcs_packet(pktbuf, btype, 1, map->mcp, bits, bitcount, seq);  // atcs-genisys
			    } else if (map->proto == 's') {
				plen = build_scs_packet(pktbuf, btype, map->mcp, bits, bitcount);
			    } else if (map->proto == 'a') {
				plen = build_ares_packet(pktbuf, btype, map->mcp, bits, bitcount, seq);
			    }
			    else
				plen = 0;
			    if (plen > 0) {
				if (debug)
				{
				    printf("   Send packet for %s proto '%c' len %d: ",map->mcp,map->proto,plen);
				    for (int i = 0; i < plen; i++)
					printf("%02x ",pktbuf[i]);
				    printf("\n");
				}
				broadcast_packet(pktbuf, plen);
			    }
			    free(bits);
			} // if (bits)
			} // if (map)
		    cJSON_Delete(root);
		} // if (root)
	    } // if zlen > 0
	    } // POLLIN

            // 2. New client handshake
            if (items[1].revents & ZMQ_POLLIN) {
                add_client(tcp);
            }

            // 3. Client inbound UDP check (Reads what they send to keep their session alive)
            for (int j = 2; j < item_count; j++) {
                if (items[j].revents & ZMQ_POLLIN) {
                    int client_idx = active_client_map[j - 2];
                    char inbound_buf[256];
                    struct sockaddr_in from_addr;
                    socklen_t from_len = sizeof(from_addr);

                    // Drain the socket so it doesn't spin the poller continuously
                    int rlen = recvfrom(items[j].fd, inbound_buf, sizeof(inbound_buf) - 1, 0,
                                        (struct sockaddr*)&from_addr, &from_len);
                    if (rlen > 0) {
                        // Any message of any kind from them resets their inbound timeout to "now"
                        clients[client_idx].last_received_from = time(NULL);

                        if (debug) {
                            inbound_buf[rlen] = '\0';
                            char ipstr[INET_ADDRSTRLEN];
                            inet_ntop(AF_INET, &from_addr.sin_addr, ipstr, sizeof(ipstr));
                            printf("DEBUG: Received traffic from client slot %d (%s): %s\n", 
                                   client_idx, ipstr, inbound_buf);
                        }
                    }
                }
            } // end of 3.
        }

        // Run structural evaluation on pings/dropouts
        check_keepalives();
    }  // while(1)

    return 0;
}

