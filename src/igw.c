#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <ctype.h>
#include <unistd.h>
#include <time.h>
#include <zmq.h>
#include <cjson/cJSON.h>

#define MAX_SERVERS 32
#define MAX_WIU_RECORDS 1024
#define MAX_CREDENTIALS 16
#define MAX_AUTHENTICATED_CLIENTS 128
#define ZJPUB_PORT 18001

#define DAYS (24*60*60)

int debug = 0;
int zjport = ZJPUB_PORT;
int zjin_port = 0;
char allowed_credentials[MAX_CREDENTIALS][64];
int credentials_count = 0;

typedef struct {
    uint8_t identity_bytes[64]; // Stores raw binary data
    int identity_len;           // Tracks if it's 16 bytes, 32 bytes, etc.
    bool authorized;
} AuthenticatedClient;

AuthenticatedClient allowed_list[MAX_AUTHENTICATED_CLIENTS];
int allowed_list_count = 0;

typedef struct {
    char host[128];
    int port;
    char secret[64];
    void *socket;
} OutboundDealer;

OutboundDealer outbound_dealers[MAX_SERVERS];
int outbound_dealers_count = 0;
void *zmq_pub;

char dealer_uuid[65] = {0};

typedef struct {
    const uint8_t *data;
    size_t length;
    size_t byte_idx;
    size_t bit_idx;
} BitReader;

typedef struct {
    uint64_t wiu_id;
    uint8_t ttl;
    uint8_t mtime;
    uint8_t seq;
    char data_bits_hex[256];
    bool is_active;
} WiuRecord;

WiuRecord wiu_table[MAX_WIU_RECORDS];
int wiu_count = 0;

uint8_t binary_id[16];
int binary_id_len = 16;

#define MAX_LOCOS 500
int loco_count = 0;
struct locos_s {
	uint32_t id;
	uint32_t by_id;
	char name[16];
	time_t last_seen;
	time_t last_sent;
} locos[MAX_LOCOS];


void gen_binary_dealer_identity(void) {

    FILE *f = fopen("/dev/urandom", "rb");
    if (f) {
        fread(binary_id, 1, 16, f);
        fclose(f);
    } else {
        for (int i = 0; i < 16; i++) binary_id[i] = rand() & 0xFF;
    }

    // CRITICAL: ZeroMQ identity frames cannot start with 0x00
    if (binary_id[0] == 0x00) {
        binary_id[0] = (rand() % 255) + 1; 
    }

    // Print out as hex string ONLY for terminal debugging visibility
    printf("[Startup] Binding native 16-byte BINARY identity: ");
    for(int i=0; i<16; i++) printf("%02x", binary_id[i]);
    printf("\n");
}

void bitreader_init(BitReader *br, const uint8_t *data, size_t length) {
    br->data = data;
    br->length = length;
    br->byte_idx = 0;
    br->bit_idx = 0;
}

uint64_t bitreader_read_bits(BitReader *br, size_t num_bits) {
    if (num_bits == 0) return 0;
    uint64_t value = 0;
    while (num_bits > 0) {
        if (br->byte_idx >= br->length) return value;
        uint8_t byte = br->data[br->byte_idx];
        size_t bits_available = 8 - br->bit_idx;
        size_t bits_to_take = (num_bits < bits_available) ? num_bits : bits_available;
        size_t shift = bits_available - bits_to_take;
        value = (value << bits_to_take) | ((byte >> shift) & ((1 << bits_to_take) - 1));
        num_bits -= bits_to_take;
        br->bit_idx += bits_to_take;
        if (br->bit_idx >= 8) { br->bit_idx = 0; br->byte_idx++; }
    }
    return value;
}

int update_wiu_table(uint64_t wiu_id, uint8_t ttl, uint8_t mtime, uint8_t seq, const char *hex_data) {
    int notdup = 0;
    for (int i = 0; i < wiu_count; i++) {
        if (wiu_table[i].wiu_id == wiu_id) {
	    //printf("  packet: %ld seq %d ttl %d data %s\n",wiu_id,seq,ttl,hex_data);
	    //printf("  table:  %ld seq %d ttl %d data %s\n",
	    //   wiu_table[i].wiu_id,wiu_table[i].seq,wiu_table[i].ttl,wiu_table[i].data_bits_hex);
            if (wiu_table[i].ttl != ttl) notdup = 1;
            if (wiu_table[i].seq != seq) notdup = 1;
            if (strcmp(wiu_table[i].data_bits_hex, hex_data) != 0) notdup = 1;
            wiu_table[i].ttl = ttl;
            wiu_table[i].mtime = mtime;
            wiu_table[i].seq = seq;
            strncpy(wiu_table[i].data_bits_hex, hex_data, sizeof(wiu_table[i].data_bits_hex) - 1);
	    wiu_table[i].data_bits_hex[sizeof(wiu_table[i].data_bits_hex) - 1] = '\0';
            return notdup;
        }
    }
    if (wiu_count < MAX_WIU_RECORDS) {
        wiu_table[wiu_count].wiu_id = wiu_id;
        wiu_table[wiu_count].ttl = ttl;
        wiu_table[wiu_count].mtime = mtime;
        wiu_table[wiu_count].seq = seq;
        strncpy(wiu_table[wiu_count].data_bits_hex, hex_data, sizeof(wiu_table[wiu_count].data_bits_hex) - 1);
	wiu_table[wiu_count].data_bits_hex[sizeof(wiu_table[wiu_count].data_bits_hex) - 1] = '\0';
        wiu_table[wiu_count].is_active = true;
        wiu_count++;
        return 1;
    }
    return 0;
}

void send_dealer_handshake(void *socket, const char *secret) {
    cJSON *h_pkt = cJSON_CreateObject();
    cJSON_AddStringToObject(h_pkt, "type", "handshake");
    cJSON_AddStringToObject(h_pkt, "uuid", dealer_uuid);
    cJSON_AddStringToObject(h_pkt, "key", secret);
    char *h_str = cJSON_PrintUnformatted(h_pkt);
    if (h_str) {
        zmq_send(socket, h_str, strlen(h_str), 0);
        free(h_str);
    }
    cJSON_Delete(h_pkt);
}

// send json to local zjpub and and zjout's
void publish_json(char *json_string)
{
	if (debug) printf("  send %s\n",json_string);
	// Local publish
	zmq_send(zmq_pub, json_string, strlen(json_string), 0);
            
	// Outbound stream sends PURE data. ZMQ adds the UUID identity automatically!
	for (int i = 0; i < outbound_dealers_count; i++) {
                if (outbound_dealers[i].socket) {
			zmq_send(outbound_dealers[i].socket, json_string, strlen(json_string), 0);
                }
	}
}

void process_json_wiu_msg(cJSON *payload_obj) {
    if (!payload_obj) return;
    cJSON *wiu_id_item = cJSON_GetObjectItem(payload_obj, "WIUID");
    cJSON *ttl_item = cJSON_GetObjectItem(payload_obj, "TTL");
    cJSON *seq_item = cJSON_GetObjectItem(payload_obj, "seq");
    cJSON *data_item = cJSON_GetObjectItem(payload_obj, "data");

    if (wiu_id_item && ttl_item && seq_item && data_item) {
        uint64_t wiu_id = (uint64_t)wiu_id_item->valuedouble;
        uint8_t ttl = (uint8_t)ttl_item->valueint;
        uint8_t seq = (uint8_t)seq_item->valueint;
        const char *hex_str = data_item->valuestring;
        
        int notdup = update_wiu_table(wiu_id, ttl, 0, seq, hex_str);
        
	if (notdup)
	{
		char *raw_json = cJSON_PrintUnformatted(payload_obj);
		publish_json(raw_json);
		free(raw_json);
	}
    }
}

// When a local radio packet comes in, dealer pushes pure JSON directly down the pipeline
void process_wiu_update(uint64_t wiu_id, uint8_t ttl, uint8_t mtime, uint8_t seq, const char *hex_str) {
    int notdup = update_wiu_table(wiu_id, ttl, mtime, seq, hex_str);
    if (notdup) {
	char wius[32];
        cJSON *root = cJSON_CreateObject();
        cJSON_AddStringToObject(root, "proto", "PTC");
        cJSON_AddStringToObject(root, "type", "WIU");
	sprintf(wius,"%ld",wiu_id);
        cJSON_AddStringToObject(root, "WIUID", wius);
        cJSON_AddNumberToObject(root, "TTL", ttl);
        cJSON_AddNumberToObject(root, "seq", seq);
        cJSON_AddStringToObject(root, "data", hex_str);

        char *json_string = cJSON_PrintUnformatted(root);
        if (json_string) {
		publish_json(json_string);
		free(json_string);
        }
        cJSON_Delete(root);
    }
}

void decode_wiu_status(const uint8_t *payload, size_t payload_len, uint8_t app_type) {
    BitReader br;
    bitreader_init(&br, payload, payload_len);
    
    uint64_t wiu_id = bitreader_read_bits(&br, 40);
    if ((wiu_id < 700000000000ULL) || (wiu_id >= 800000000000ULL)) return;  // invalid
    uint8_t ttl = (bitreader_read_bits(&br, 8) >> 7 & 0x01);
    uint8_t mtime = bitreader_read_bits(&br, 8) & 0x0f;
    uint8_t seq = bitreader_read_bits(&br, 8);
    
    size_t total_bits = payload_len * 8;
    size_t current_bit_pos = (br.byte_idx * 8) + br.bit_idx;
    int remaining_bits = (int)total_bits - (int)current_bit_pos;
    
    char hex_str[256] = {0};
    if (remaining_bits > 0) {
        int bytes_to_read = (remaining_bits + 7) / 8;
        for (int i = 0; i < bytes_to_read && i < 120; i++) {
            uint8_t byte_val = bitreader_read_bits(&br, 8);
            sprintf(&hex_str[i * 2], "%02X", byte_val);
        }
    }
    process_wiu_update(wiu_id, ttl, mtime, seq, hex_str);
}


void process_json_beacon(cJSON *payload_obj) {
    if (!payload_obj) return;
    cJSON *tid_item = cJSON_GetObjectItem(payload_obj, "TID");
    // don't need to check these for dup values
    // cJSON *lat_item = cJSON_GetObjectItem(payload_obj, "lat");
    // cJSON *lon_item = cJSON_GetObjectItem(payload_obj, "lon");
    cJSON *chn_item = cJSON_GetObjectItem(payload_obj, "chn");
    cJSON *ch1_item = cJSON_GetObjectItem(payload_obj, "ch1");
    cJSON *ch2_item = cJSON_GetObjectItem(payload_obj, "ch2");
    cJSON *ch3_item = cJSON_GetObjectItem(payload_obj, "ch3");
    cJSON *ch4_item = cJSON_GetObjectItem(payload_obj, "ch4");
    cJSON *ch5_item = cJSON_GetObjectItem(payload_obj, "ch5");
    cJSON *ch6_item = cJSON_GetObjectItem(payload_obj, "ch6");

    if (tid_item && chn_item && ch1_item && ch2_item && ch3_item && ch4_item && ch5_item && ch6_item) {
	char *ep;
	uint32_t tid = strtol(tid_item->valuestring,&ep,16);
	printf("got beacon tid %06x\n",tid);
        uint8_t chn = (uint8_t)chn_item->valueint;
        uint8_t ch1 = (uint8_t)ch1_item->valueint;
        uint8_t ch2 = (uint8_t)ch2_item->valueint;
        uint8_t ch3 = (uint8_t)ch3_item->valueint;
        uint8_t ch4 = (uint8_t)ch4_item->valueint;
        uint8_t ch5 = (uint8_t)ch5_item->valueint;
        uint8_t ch6 = (uint8_t)ch6_item->valueint;

        //int notdup = update_beacon_table(wiu_id, ttl, 0, seq, hex_str);
	int notdup = 1;
        
	if (notdup)
	{
		char *json_string = cJSON_PrintUnformatted(payload_obj);
		if (json_string) {
			publish_json(json_string);
			free(json_string);
		}
	}
    }
}

void process_beacon(uint32_t radio_id,float lat,float lon,uint8_t channel,uint8_t ch1,uint8_t ch2,uint8_t ch3,uint8_t ch4,uint8_t ch5,uint8_t ch6){
//    int notdup = update_wiu_table(wiu_id, ttl, mtime, seq, hex_str);
	int notdup = 1;
    if (notdup) {
	char s[32];
        cJSON *root = cJSON_CreateObject();
        cJSON_AddStringToObject(root, "proto", "PTC");
        cJSON_AddStringToObject(root, "type", "beacon");
	sprintf(s,"%06X",radio_id);
        cJSON_AddStringToObject(root, "TID", s);
	sprintf(s,"%.6f",lat);
        cJSON_AddStringToObject(root, "lat", s);
	sprintf(s,"%.6f",lon);
        cJSON_AddStringToObject(root, "lon", s);
        cJSON_AddNumberToObject(root, "chn", channel);
        cJSON_AddNumberToObject(root, "ch1", ch1);
        cJSON_AddNumberToObject(root, "ch2", ch2);
        cJSON_AddNumberToObject(root, "ch3", ch3);
        cJSON_AddNumberToObject(root, "ch4", ch4);
        cJSON_AddNumberToObject(root, "ch5", ch5);
        cJSON_AddNumberToObject(root, "ch6", ch6);

        char *json_string = cJSON_PrintUnformatted(root);
        if (json_string) {
		publish_json(json_string);
		free(json_string);
        }
        cJSON_Delete(root);
    }
}

void decode_beacon(const uint8_t *payload, size_t payload_len, uint8_t app_type) {
    BitReader br;
    bitreader_init(&br, payload, payload_len);
    
    uint8_t flags1 = bitreader_read_bits(&br, 8);
    uint32_t radio_id = bitreader_read_bits(&br, 24);
    int32_t latraw = bitreader_read_bits(&br, 32);
    int32_t lonraw = bitreader_read_bits(&br, 32);
    uint8_t channel = bitreader_read_bits(&br, 8);
    uint8_t rate = bitreader_read_bits(&br, 8);
    uint8_t util = bitreader_read_bits(&br, 8);
    uint8_t flag2 = bitreader_read_bits(&br, 8);
    uint8_t ch1 = bitreader_read_bits(&br, 8);
    uint8_t ch2 = bitreader_read_bits(&br, 8);
    uint8_t ch3 = bitreader_read_bits(&br, 8);
    uint8_t ch4 = bitreader_read_bits(&br, 8);
    uint8_t ch5 = bitreader_read_bits(&br, 8);
    uint8_t ch6 = bitreader_read_bits(&br, 8);
    float lat = latraw / 600000.0;
    float lon = lonraw / 600000.0;

    process_beacon(radio_id,lat,lon,channel,ch1,ch2,ch3,ch4,ch5,ch6);
}

// publish/forward this loco info
void publish_loco_update(int index)
{
	char s[32];
        cJSON *root = cJSON_CreateObject();
        cJSON_AddStringToObject(root, "proto", "PTC");
        cJSON_AddStringToObject(root, "type", "loco");
	sprintf(s,"%06X",locos[index].id);
        cJSON_AddStringToObject(root, "ID", s);
        cJSON_AddStringToObject(root, "name", locos[index].name);
	sprintf(s,"%06X",locos[index].by_id);
        cJSON_AddStringToObject(root, "BID", s);
	locos[index].last_sent = time(NULL);

        char *json_string = cJSON_PrintUnformatted(root);
        if (json_string) {
		publish_json(json_string);
		free(json_string);
        }	
        cJSON_Delete(root);
}

// maybe add new loco (got name, but might already be in table)
int new_loco(uint32_t id,uint32_t bid,char *name)
{
	int i, iold;
	time_t now, oldest;
	
	//if (debug) printf(" add new loco %06x by %06x name %s\n",id,bid,name);
	iold = 0;
	now = time(NULL);
	oldest = now + 1;
	for (i = 0; i < MAX_LOCOS; i++)
	{
		// find oldest entry
		if (locos[i].last_seen < oldest)
		{
			iold = i;
			oldest = locos[i].last_seen;
		}
		if (locos[i].id == id) return(i);
		if (locos[i].id == 0) break; // free slot
	}
	if (i == MAX_LOCOS) // no room
		i = iold;  // replace oldest entry
	// if (debug) printf(" new loco at %d: %06X\n",i,id);
	locos[i].id = id;
	locos[i].by_id = bid;
	locos[i].last_sent = 0;
	locos[i].last_seen = now;
	strncpy(locos[i].name,name,15); locos[i].name[15] = 0;
	loco_count++;
	return(i);
}

// update loco table at index with by_id and current time
void update_loco(int index, uint32_t loco_id, uint32_t by_id)
{
	// if (debug) printf(" update loco at %d: %06X\n",index,loco_id);
	locos[index].by_id = by_id;
	time_t t = time(NULL);
	locos[index].last_seen = t;
	time_t last = locos[index].last_sent;
	if ((t - last) > 60)
	{
		publish_loco_update(index);
	}
}

// return index of loco or -1 if not found
int find_loco(uint32_t id)
{
	for (int i = 0; i < loco_count; i++)
		if (locos[i].id == id) return(i);
	return(-1);
}

void check_loco_seen(uint32_t tid, uint32_t rid)
{
   // if tid or rid is in the loco table then update its last seen time
   int index = find_loco(tid);
   if (index >= 0) { update_loco(index,tid,rid); return; }
   index = find_loco(rid);
   if (index >= 0) { update_loco(index,rid,tid); return; }
   return;	   
}

void process_json_loco(cJSON *payload_obj) {
    if (!payload_obj) return;
    cJSON *id_item = cJSON_GetObjectItem(payload_obj, "ID");
    cJSON *bid_item = cJSON_GetObjectItem(payload_obj, "BID");
    cJSON *name_item = cJSON_GetObjectItem(payload_obj, "name");

    if (id_item && bid_item && name_item) {
        char *ep;
        uint32_t id, bid;
	id  = strtol(id_item->valuestring,&ep,16);
	bid = strtol(bid_item->valuestring,&ep,16);
	int index = find_loco(id);
	if (index >= 0) // found it
	{
		update_loco(index,id,bid);
	}
	else
	{
		index = new_loco(id,bid,name_item->valuestring);
		if (index >= 0) update_loco(index,id,bid);
	}
    }
}

void decode_qstat_ack(const uint8_t *payload, size_t payload_len)
{
    BitReader br;
    bitreader_init(&br, payload, payload_len);
    
    // only need these, skip rest of packet
    uint32_t tid = bitreader_read_bits(&br, 24);
    uint32_t rid = bitreader_read_bits(&br, 24);
    check_loco_seen(tid,rid);
}

void decode_acq(const uint8_t *payload, size_t payload_len)
{
    BitReader br;
    bitreader_init(&br, payload, payload_len);
    
    // only need these, skip rest of packet
    uint8_t uti = bitreader_read_bits(&br, 8);
    uint32_t tid = bitreader_read_bits(&br, 24);
    uint32_t rid = bitreader_read_bits(&br, 24);
    check_loco_seen(tid,rid);
}

// extract loco name from "l.up.up+1234"), return true if ok
int extract_loco_name(char *in, char *out)
{
	char *p, *q;
	p = in; q = out;
	if (*p++ != 'l') return(0);
	if (*p++ != '.') return(0);
	while (*p != '.')
	{
		if (*p == '\0') return(0);
		p++;
	}
	p++;
	while (*p != '\0')
	{
		if (*p == '.') break;
		if (*p == '+')
			*q++ = ' ';
		else
			*q++ = toupper(*p);
		p++;
	}
	*q++ = 0;
	return(1);
}

// type 0x70 packets
void decode_t70(const uint8_t *payload, size_t payload_len)
{
    BitReader br;
    bitreader_init(&br, payload, payload_len);
    char *p, *q;
    char name[128];
    char loconame[128];
    
    //if (debug) printf("got type 70\n");
    if (payload_len < 9) return;
    uint32_t tid = bitreader_read_bits(&br, 24);
    uint32_t rid = bitreader_read_bits(&br, 24);
    uint8_t flags1 = bitreader_read_bits(&br, 8);
    uint8_t seq = bitreader_read_bits(&br, 8);
    uint32_t msgnum = bitreader_read_bits(&br, 8);
    if (msgnum != 0x21)
    {
	    check_loco_seen(tid,rid);
	    return;
    }
    if (payload_len < 23) return;
    uint32_t radio_id = (payload[17] << 16) | (payload[18] << 8) |  payload[19];
    int offset = 20;
    if (offset >= payload_len) return;
    offset++;
    if (offset >= payload_len) return;
    int namelen = payload[offset++];
    if (namelen > 126) return;
    if ((offset+namelen) >= payload_len) return;
    p = (char *) payload+offset;
    q = name;
    for (int i = 0; i < namelen; i++)
    {
	    *q++ = *p++;
    }
    *q = 0;
    if (!extract_loco_name(name,loconame)) return;
    int index = new_loco(radio_id,rid,loconame);
    if (index >= 0) update_loco(index,radio_id,rid);
}


// figure out what type and call the right decoder
void process_json_msg(cJSON *payload_obj) {
    if (!payload_obj) return;
    cJSON *proto_item = cJSON_GetObjectItem(payload_obj, "proto");
    if (!strcmp(proto_item->valuestring,"PTC"))
    {
	    cJSON *type_item = cJSON_GetObjectItem(payload_obj, "type");
	    if (debug) printf(" got PTC type %s\n",type_item->valuestring);
	    if (!strcmp(type_item->valuestring,"WIU"))
		    process_json_wiu_msg(payload_obj);
	    else if (!strcmp(type_item->valuestring,"beacon"))
		    process_json_beacon(payload_obj);
	    else if (!strcmp(type_item->valuestring,"loco"))
		    process_json_loco(payload_obj);
    }
}



void process_packet(const uint8_t *packet, size_t len) {
    if (len < 4) return;
    uint8_t proto = packet[0]; 
    if (proto != 'I') return;
    uint8_t app_type = packet[3]; 
    if (app_type == 0x02) {
	if (debug) printf(" got beacon packet from s2p\n");
        decode_beacon(packet + 5, len - 5, app_type);
    }
    else if ((app_type == 0x01) || (app_type == 0x03))
    {
	decode_qstat_ack(packet+5, len-5);
    }
    else if (app_type == 0x04)
    {
	decode_acq(packet+5, len-5);
    }
    else if (app_type == 0x33 || app_type == 0x34) {
	if (debug) printf(" got wiu packet from s2p\n");
        decode_wiu_status(packet + 5, len - 5, app_type);
    }
    else if (app_type == 0x70)
    {
	decode_t70(packet+5, len-5);
    }
}

void handle_router_inbound(void *router_socket) {
    uint8_t current_zmq_id[256] = {0};
    char client_uuid[37] = {0};
    char msg_buffer[4096] = {0};
    char frame_buffer[4096] = {0};
    int64_t more_frames = 0;
    size_t more_size = sizeof(more_frames);
    int frame_count = 0;

    // 1. Read Frame 1: Always the Native Routing Identity (The dealer's UUID)
    int id_bytes = zmq_recv(router_socket, current_zmq_id, sizeof(current_zmq_id) - 1, 0);
    if (id_bytes <= 0) return;
    //if (debug) printf(" handle_router_inbound got %d id_bytes\n",id_bytes);

    // 2. Loop through all subsequent frames dynamically
    zmq_getsockopt(router_socket, ZMQ_RCVMORE, &more_frames, &more_size);
    
    while (more_frames) {
        memset(frame_buffer, 0, sizeof(frame_buffer));
        int bytes_read = zmq_recv(router_socket, frame_buffer, sizeof(frame_buffer) - 1, 0);
        
        if (bytes_read >= 0) {
            frame_buffer[bytes_read] = '\0';
	    // if (debug) printf(" handle_router_inbound got more %d msg_bytes: %s\n",bytes_read,msg_buffer);
            // Keep overwriting msg_buffer. The very last frame in the stack is our payload!
            if (bytes_read > 0) {
                strncpy(msg_buffer, frame_buffer, sizeof(msg_buffer) - 1);
		msg_buffer[sizeof(msg_buffer) - 1] = '\0';
            }
        }
        
        frame_count++;
        zmq_getsockopt(router_socket, ZMQ_RCVMORE, &more_frames, &more_size);
    }

    // Safety check: Did we actually get a message payload?
    if (strlen(msg_buffer) == 0) return;

    // --- Authentication Database Matching via BINARY MEMCMP ---
    int list_idx = -1;
    for (int i = 0; i < allowed_list_count; i++) {
        // Must match BOTH byte length and exact memory values
        if (allowed_list[i].identity_len == id_bytes && 
            memcmp(allowed_list[i].identity_bytes, current_zmq_id, id_bytes) == 0) {
            list_idx = i;
            break;
        }
    }

    // Is the payload string an exact match for one of our allowed authentication keys?
    bool is_handshake = false;
    for (int i = 0; i < credentials_count; i++) {
        if (strcmp(allowed_credentials[i], msg_buffer) == 0) {
            is_handshake = true;
            break;
        }
    }

    if (is_handshake) {
        // Reply frame stack: identity -> empty delimiter -> return code
        zmq_send(router_socket, current_zmq_id, id_bytes, ZMQ_SNDMORE);
        zmq_send(router_socket, "", 0, ZMQ_SNDMORE);

	if (list_idx == -1 && allowed_list_count < MAX_AUTHENTICATED_CLIENTS) {
            list_idx = allowed_list_count++;
            allowed_list[list_idx].identity_len = id_bytes;
            memcpy(allowed_list[list_idx].identity_bytes, current_zmq_id, id_bytes);
        }
        allowed_list[list_idx].authorized = true;

        zmq_send(router_socket, "ok", 2, 0);
        printf("[Router] Identity UUID [%s] successfully authenticated via key match.\n", client_uuid);
        return;
    }

    // If it's a telemetry update packet, process it if authorized
    if (list_idx != -1 && allowed_list[list_idx].authorized) {
	if (debug) printf(" got packet from zjin\n");
        cJSON *payload_json = cJSON_Parse(msg_buffer);
        if (payload_json) {
            process_json_msg(payload_json);
            cJSON_Delete(payload_json);
        } else {
            printf("[Router] Received invalid JSON string from authorized client [%s]\n", client_uuid);
        }
    } else {
        // Server reboot recovery cascade
        zmq_send(router_socket, current_zmq_id, id_bytes, ZMQ_SNDMORE);
        zmq_send(router_socket, "", 0, ZMQ_SNDMORE);
        zmq_send(router_socket, "need_auth", 9, 0);
        printf("[Router] Unknown Identity [%s] sent data. Demanding auth re-sync.\n", client_uuid);
    }
}

int load_config(const char *filename, char servers[MAX_SERVERS][256]) {
    FILE *f = fopen(filename, "r");
    if (!f) { perror("Failed to open config file"); return 0; }
    fseek(f, 0, SEEK_END); long size = ftell(f); fseek(f, 0, SEEK_SET);
    char *data = malloc(size + 1);
    if (!data) { fclose(f); return 0; }
    fread(data, 1, size, f); data[size] = '\0'; fclose(f);
    
    cJSON *json = cJSON_Parse(data); 
    free(data);
    if (!json) {
        // ERROR LOGGING: This will tell you exactly where your JSON string has syntax flaws
        printf("[Config] JSON Syntax Error before: [%s]\n", cJSON_GetErrorPtr());
        return 0; 
    }
    
    cJSON *zjp_obj = cJSON_GetObjectItem(json, "zjpub");
    if (cJSON_IsObject(zjp_obj)) {
        cJSON *port_item = cJSON_GetObjectItem(zjp_obj, "port");
        if (port_item) zjport = port_item->valueint;
    }
    
    cJSON *zjin_obj = cJSON_GetObjectItem(json, "zjin");
    if (cJSON_IsObject(zjin_obj)) {
        cJSON *port_item = cJSON_GetObjectItem(zjin_obj, "port");
        if (port_item) zjin_port = port_item->valueint;
        
        cJSON *creds = cJSON_GetObjectItem(zjin_obj, "credentials");
        if (cJSON_IsArray(creds)) {
            int c_size = cJSON_GetArraySize(creds);
            for (int i = 0; i < c_size && i < MAX_CREDENTIALS; i++) {
                cJSON *c_item = cJSON_GetArrayItem(creds, i);
                if (cJSON_IsObject(c_item)) {
                    cJSON *sec = cJSON_GetObjectItem(c_item, "key"); // Updated to look for "key"
                    if (sec && cJSON_IsString(sec)) {
                        strncpy(allowed_credentials[credentials_count++], sec->valuestring, 63);
                    }
                }
            }
        }
    }

    cJSON *zjout_obj = cJSON_GetObjectItem(json, "zjout");
    if (cJSON_IsObject(zjout_obj)) {
        cJSON *out_servers = cJSON_GetObjectItem(zjout_obj, "servers");
        if (cJSON_IsArray(out_servers)) {
            int out_size = cJSON_GetArraySize(out_servers);
            for (int i = 0; i < out_size && i < MAX_SERVERS; i++) {
                cJSON *srv = cJSON_GetArrayItem(out_servers, i);
                cJSON *h = cJSON_GetObjectItem(srv, "host");
                cJSON *p = cJSON_GetObjectItem(srv, "port");
                cJSON *s = cJSON_GetObjectItem(srv, "key"); // Updated to look for "key"
                if (h && p && s) {
                    strncpy(outbound_dealers[outbound_dealers_count].host, h->valuestring, 127);
		    outbound_dealers[outbound_dealers_count].host[127] = '\0';
                    outbound_dealers[outbound_dealers_count].port = p->valueint;
                    strncpy(outbound_dealers[outbound_dealers_count].secret, s->valuestring, 63);
                    outbound_dealers[outbound_dealers_count].socket = NULL;
                    outbound_dealers_count++;
                }
            }
        }
    }
		
    cJSON *servers_arr = cJSON_GetObjectItem(json, "servers");
    int count = 0;
    if (cJSON_IsArray(servers_arr)) {
        int arr_size = cJSON_GetArraySize(servers_arr);
        for (int i = 0; i < arr_size && i < MAX_SERVERS; i++) {
            cJSON *server_obj = cJSON_GetArrayItem(servers_arr, i);
            if (cJSON_IsObject(server_obj)) {
                cJSON *host_item = cJSON_GetObjectItem(server_obj, "host");
                cJSON *port_item = cJSON_GetObjectItem(server_obj, "port");
                if (host_item && port_item) {
                    snprintf(servers[count], sizeof(servers[count]), "tcp://%s:%d", 
                             host_item->valuestring, port_item->valueint);
                    count++;
                }
            }
        }
    }
    cJSON_Delete(json);
    return count;
}

int main(int argc, char **argv) {
    int opt;
    char pubname[256];
    char servers[MAX_SERVERS][256];

    while ((opt = getopt(argc, argv, "D")) != -1) {
        switch (opt) {
        case 'D': debug = 1; break;
        }
    }
    
    gen_binary_dealer_identity();
    if (debug) printf("Generated System Dealer Session Identity UUID: %s\n", dealer_uuid);
    memset(locos,0,sizeof(struct locos_s) * MAX_LOCOS);

    int server_count = load_config("igw.json", servers);

    void *ctx = zmq_ctx_new();
    
    zmq_pub = zmq_socket(ctx, ZMQ_PUB);
    sprintf(pubname, "tcp://*:%d", zjport);
    zmq_bind(zmq_pub, pubname);
    printf("Outbound ZMQ PUB json server active on %s\n", pubname);

    void *sub_socket = zmq_socket(ctx, ZMQ_SUB);
    for (int i = 0; i < server_count; i++) {
        zmq_connect(sub_socket, servers[i]);
    }
    zmq_setsockopt(sub_socket, ZMQ_SUBSCRIBE, "", 0);

    void *router_socket = NULL;
    if (zjin_port > 0) {
        router_socket = zmq_socket(ctx, ZMQ_ROUTER);
        char router_bind_path[256];
        sprintf(router_bind_path, "tcp://*:%d", zjin_port);
        zmq_bind(router_socket, router_bind_path);
        printf("Inbound Router Listening on port %d\n", zjin_port);
    }

    // Connect outbound dealer networks
    for (int i = 0; i < outbound_dealers_count; i++) {
        void *dealer = zmq_socket(ctx, ZMQ_DEALER);
        if (!dealer) { perror("Failed to create dealer socket"); continue; }

        // 1. CHOOSE IDENTITY FIRST (Must happen before connect!)
        //printf("[Startup] Binding native ZMQ Identity UUID: %s (Len: %zu)\n", dealer_uuid, strlen(dealer_uuid));
        int rc = zmq_setsockopt(dealer, ZMQ_IDENTITY, binary_id, binary_id_len);
        if (rc != 0) {
            printf("[ERROR] Failed to set ZMQ_IDENTITY, error code: %d\n", zmq_errno());
        }
        
        char target_addr[256];
        sprintf(target_addr, "tcp://%s:%d", outbound_dealers[i].host, outbound_dealers[i].port);
        printf("Connecting to peer gateway engine: %s\n", target_addr);
        
        // 2. NOW CONNECT THE SOCKET
        if (zmq_connect(dealer, target_addr) == 0) {
            outbound_dealers[i].socket = dealer;
            
            // Give background thread a tiny window to negotiate TCP
            usleep(50000); 
            
            // 3. Send ONLY the plain text key string for authorization pass
            zmq_send(dealer, outbound_dealers[i].secret, strlen(outbound_dealers[i].secret), 0);
        } else {
            printf("[ERROR] zmq_connect failed for %s\n", target_addr);
        }
    }
    
    zmq_pollitem_t items[3];
    items[0].socket = sub_socket;
    items[0].events = ZMQ_POLLIN;
    items[1].socket = router_socket;
    items[1].events = (router_socket != NULL) ? ZMQ_POLLIN : 0;
    items[2].socket = (outbound_dealers_count > 0) ? outbound_dealers[0].socket : NULL;
    items[2].events = (items[2].socket != NULL) ? ZMQ_POLLIN : 0;

    uint8_t buffer[8192];
    while (true) {
        int rc = zmq_poll(items, 3, -1);
        if (rc < 0) break;

        // Packet parsing from input stream feeds
        if (items[0].revents & ZMQ_POLLIN) {
            int bytes_recv = zmq_recv(sub_socket, buffer, sizeof(buffer), 0);
            if (bytes_recv > 0) {
                process_packet(buffer, bytes_recv);
            }
        }

        // Processing incoming data requests
        if (router_socket && (items[1].revents & ZMQ_POLLIN)) {
            handle_router_inbound(router_socket);
        }

        // Dealer input monitor: Checks for authorization state messages from upstream server
        if (items[2].socket && (items[2].revents & ZMQ_POLLIN)) {
            char reply_delim[16];
            char reply_body[64] = {0};
            zmq_recv(items[2].socket, reply_delim, sizeof(reply_delim), 0);
            zmq_recv(items[2].socket, reply_body, sizeof(reply_body)-1, 0);
            
            printf("[Dealer] Upstream message received: %s\n", reply_body);
            
	    if (strcmp(reply_body, "need_auth") == 0) {
		    printf("[Dealer] Server state missing. Re-transmitting handshake credentials...\n");
		    
		    // Send ONLY the raw text key string. ZeroMQ handles the identity frame automatically.
		    zmq_send(items[2].socket, outbound_dealers[0].secret, strlen(outbound_dealers[0].secret), 0);
	    }
	}
    }

    zmq_close(sub_socket);
    if (router_socket) zmq_close(router_socket);
    for (int i = 0; i < outbound_dealers_count; i++) {
        if (outbound_dealers[i].socket) zmq_close(outbound_dealers[i].socket);
    }
    zmq_close(zmq_pub);
    zmq_ctx_destroy(ctx);
    return 0;
}
