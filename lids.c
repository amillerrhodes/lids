#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>
#include <signal.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
//#include <sqlite3.h>
#include "sqlite3.h"

#include <libnetfilter_log/libnetfilter_log.h>

#include "list.h"

typedef struct _service {
    uint32_t proto;
    uint32_t port;
} service_t;

typedef struct _threat {
    service_t service;
    struct in_addr src_ip;
    uid_t uid;
    gid_t gid;
    uint8_t *rule;
    uint8_t *pkt;
    uint32_t pkt_len;
    struct list_head list;
} threat_t;

LIST_HEAD(threat_list);

#define LIDS_PTR_ERR NULL
#define LIDS_INT_ERR -1
#define LIDS_OK 0

static uint8_t lids_interrupted = 0;
static sqlite3 *db;

void sigint_handler(int val) {
    lids_interrupted = 1;
}

static void insert_db(threat_t *threat) {
    char buffer[] = "INSERT INTO THREATS VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)";
    /* IP = 1 PROTO = 2 PORT = 3 UID = 4 GID = 5 RULE = 6 PAYLOAD = 7 */
    char *ipstr = NULL;
    int rc = 0;
    sqlite3_stmt *stmt;

    sqlite3_prepare_v2(db, buffer, strlen(buffer), &stmt, NULL);

    ipstr = inet_ntoa(threat->src_ip);
    sqlite3_bind_text(stmt, 1, ipstr, strlen(ipstr), SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, threat->service.proto);
    sqlite3_bind_int(stmt, 3, threat->service.port);
    sqlite3_bind_int(stmt, 4, threat->uid);
    sqlite3_bind_int(stmt, 5, threat->gid);
    sqlite3_bind_text(stmt, 6, threat->rule, strlen(threat->rule), SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 7, threat->pkt, threat->pkt_len, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        printf("Commit Failed! %d\n", rc);
    }

    sqlite3_finalize(stmt);
}

static void dissect_packet(struct iphdr *ip_header, threat_t *threat)
{
    threat->src_ip.s_addr = ip_header->saddr;
    if (ip_header->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp_header = (struct tcphdr *)(ip_header + 1);
        service_t tcp_service = { .proto = IPPROTO_TCP,
            .port = htons(tcp_header->dest) };
        threat->service = tcp_service;

        threat->pkt_len = ntohs(ip_header->tot_len) - sizeof(struct iphdr) 
            - (sizeof(int) * tcp_header->doff);
        if (threat->pkt_len > 0) {
            threat->pkt = malloc(threat->pkt_len);
            memcpy(threat->pkt, ((char *)(tcp_header) + (sizeof(int) * tcp_header->doff)), threat->pkt_len);
        }
    } else if (ip_header->protocol == IPPROTO_UDP) {
        struct udphdr *udp_header = (struct udphdr *)(ip_header + 1);
        service_t udp_service = { .proto = IPPROTO_UDP,
            .port = htons(udp_header->dest) };
        threat->service = udp_service;

        threat->pkt_len = htons(udp_header->len) - sizeof(struct udphdr);

        if (threat->pkt_len > 0) {
            threat->pkt = malloc(threat->pkt_len);
            memcpy(threat->pkt, (char *)(udp_header + 1), threat->pkt_len);
        }
    }
}

static threat_t *create_threat(struct nflog_data *ldata)
{
    threat_t *new_threat = NULL;
    char *payload = NULL;
    char *prefix = NULL;

    int uid = 0;
    nflog_get_uid(ldata, &uid);
    printf("%d ", uid);


    new_threat = malloc(sizeof(threat_t));
    if (NULL == new_threat) {
        return LIDS_PTR_ERR;
    }

    prefix = nflog_get_prefix(ldata);
    new_threat->rule = malloc(strlen(prefix) + 1);
    if (NULL == new_threat->rule) {
        free(new_threat);
        return LIDS_PTR_ERR;
    }

    new_threat->pkt_len = nflog_get_payload(ldata, &payload);

    dissect_packet((struct iphdr *)payload, new_threat);

    strncpy(new_threat->rule, prefix, strlen(prefix));

    return new_threat;
}

static int cb(struct nflog_g_handle *gh, struct nfgenmsg *nfmsg,
        struct nflog_data *nfa, void *data)
{
    struct nfulnl_msg_packet_hdr *ph = nflog_get_msg_packet_hdr(nfa);
    threat_t *new_threat = NULL;

    new_threat = create_threat(nfa);
    if (NULL == new_threat) {
        return -1;
    }

    insert_db(new_threat);

    free(new_threat->rule);
    free(new_threat->pkt);
    free(new_threat);
    /*
       destroy_threat(new_threat);
     */
    return 0;
}

int main(int argc, char **argv)
{
    struct nflog_handle *h;
    struct nflog_g_handle *qh1337;
    int fd;
    char buf[4096];
    struct sigaction act;
    int rc;
    char *zErrMsg;

    rc = sqlite3_open("lids.db", &db);

    char *sql = "CREATE TABLE IF NOT EXISTS THREATS("  \
                 "IP      TEXT NOT NULL," \
                 "PROTO   UNSIGNED INT NOT NULL," \
                 "PORT    UNSIGNED INT NOT NULL," \
                 "UID     UNSIGNED INT NOT NULL," \
                 "GID     UNSIGNED INT NOT NULL," \
                 "RULE    TEXT," \
                 "PAYLOAD BLOB);";

    /* Execute SQL statement */
    rc = sqlite3_exec(db, sql, NULL, 0, &zErrMsg);

    act.sa_handler = sigint_handler;
    sigaction(SIGINT, &act, NULL);

    h = nflog_open();
    nflog_bind_pf(h, AF_INET);
    qh1337 = nflog_bind_group(h, 1337);
    nflog_set_mode(qh1337, NFULNL_COPY_PACKET, 0xffff);
    fd = nflog_fd(h);
    nflog_callback_register(qh1337, &cb, NULL);

    while (!lids_interrupted) {
        int num_bytes = recv(fd, buf, sizeof(buf), 0);
        if (num_bytes < 0) {
            perror("recv");
        }
        nflog_handle_packet(h, buf, num_bytes);
    }

    nflog_unbind_group(qh1337);
    nflog_close(h);
    sqlite3_close(db);

    return EXIT_SUCCESS;
}

