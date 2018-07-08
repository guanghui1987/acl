#include "lib_acl.h"
#include "lib_protocol.h"
#include "lib_acl.h"
#include <signal.h>

static int __delay = 1;
static int __timeout = 1;

static void add_ip_list(ICMP_CHAT *chat, const ACL_ARGV *domain_list, int npkt)
{
	ACL_DNS_DB* dns_db;
	const char* ptr;
	int   i, j;
	char *pdomain, *pip;
	ACL_ARGV* ip_list = acl_argv_alloc(10);

	for (i = 0; i < domain_list->argc; i++) {
		dns_db = acl_gethostbyname(domain_list->argv[i], NULL);
		if (dns_db == NULL) {
			acl_msg_warn("Can't find domain %s", domain_list->argv[i]);
			continue;
		}

		for (j = 0; j < acl_netdb_size(dns_db); j++) {
			ptr = acl_netdb_index_ip(dns_db, j);
			if (ptr == NULL)
				continue;
			acl_argv_add(ip_list, domain_list->argv[i], ptr, NULL);
		}
		acl_netdb_free(dns_db);
	}

	for (i = 0; i < ip_list->argc;) {
		pdomain = ip_list->argv[i++];
		pip = ip_list->argv[i++];

		if (strcmp(pdomain, pip) == 0)
			icmp_ping_one(chat, NULL, pip, npkt, __delay, __timeout);
		else
			icmp_ping_one(chat, pdomain, pip, npkt, __delay, __timeout);
	}
}

static ICMP_CHAT *__chat = NULL;

static void display_res2(ICMP_CHAT *chat)
{
	if (chat) {
		/* ÏÔÊ¾ PING µÄ½á¹û×Ü½á */
		icmp_stat(chat);
		printf(">>>max pkts: %d\r\n", icmp_chat_seqno(chat));
	}
}

static void display_res(void)
{
	if (__chat) {
		display_res2(__chat);

		/* ÊÍ·Å ICMP ¶ÔÏó */
		icmp_chat_free(__chat);
		__chat = NULL;
	}
}

/* µ¥Ïß³ÌÒì²½ PING ¶à¸öµØÖ·µÄº¯ÊýÈë¿Ú */
static void ping_main_async(const ACL_ARGV *ip_list, int npkt)
{
	ACL_AIO *aio;

	/* ´´½¨·Ç×èÈûÒì²½Í¨ÐÅ¾ä±ú */
	aio = acl_aio_create(ACL_EVENT_SELECT);
	acl_aio_set_keep_read(aio, 0);

	/* ´´½¨ ICMP ¶ÔÏó */
	__chat = icmp_chat_create(aio, 1);

	/* Ìí¼ÓÐèÒª PING µÄµØÖ·ÁÐ±í */

	add_ip_list(__chat, ip_list, npkt);

	while (1) {
		/* Èç¹û PING ½áÊø£¬ÔòÍË³öÑ­»· */
		if (icmp_chat_finish(__chat)) {
			printf("over now!, hosts' size=%d, count=%d\r\n",
				icmp_chat_size(__chat), icmp_chat_count(__chat));
			break;
		}

		/* Òì²½ÊÂ¼þÑ­»·¹ý³Ì */
		acl_aio_loop(aio);
	}

	/* ÏÔÊ¾ PING ½á¹û */
	display_res();

	/* Ïú»Ù·Ç×èÈû¾ä±ú */
	acl_aio_free(aio);
}

/* µ¥Ïß³Ì PING µ¥¸öµØÖ·µÄº¯ÊýÈë¿Ú */
static void ping_main_sync(const char *dest, int npkt)
{
	ACL_DNS_DB* dns_db;
	const char* ip;

	/* ´´½¨ ICMP ¶ÔÏó */
	__chat = icmp_chat_create(NULL, 1);

	/* ÓÉÓòÃû½âÎö³ö IP µØÖ· */
	dns_db = acl_gethostbyname(dest, NULL);
	if (dns_db == NULL) {
		acl_msg_warn("Can't find domain %s", dest);
		return;
	}

	ip = acl_netdb_index_ip(dns_db, 0);
	if (ip == NULL || *ip == 0)
		acl_msg_fatal("ip invalid");

	/* ¿ªÊ¼ PING Ò»¸ö IP µØÖ· */
	if (strcmp(dest, ip) == 0)
		icmp_ping_one(__chat, NULL, ip, npkt, __delay, 1000);
	else
		icmp_ping_one(__chat, dest, ip, npkt, __delay, 1000);

	/* ÊÍ·Å DNS ²éÑ¯½á¹û */
	acl_netdb_free(dns_db);

	/* ÏÔÊ¾ PING ½á¹ûÐ¡½á */
	display_res();
}

/* PING Ïß³ÌÈë¿Ú */
static int __npkt = 10;
static void *ping_thread(void *arg)
{
	const char *ip, *dest = (char *) arg;
	ACL_DNS_DB* dns_db;
	ICMP_CHAT *chat;

	/* Í¨¹ýÓòÃû½âÎö³öIPµØÖ· */
	dns_db = acl_gethostbyname(dest, NULL);
	if (dns_db == NULL) {
		acl_msg_warn("Can't find domain %s", dest);
		return (NULL);
	}

	/* Ö»È¡³öÓòÃûµÚÒ»¸ö IP µØÖ· PING */
	ip = acl_netdb_index_ip(dns_db, 0);
	if (ip == NULL || *ip == 0) {
		acl_msg_error("ip invalid");
		acl_netdb_free(dns_db);
		return (NULL);
	}

	/* ´´½¨ ICMP ¶ÔÏó */
	chat = icmp_chat_create(NULL, 1);

	/* ¿ªÊ¼ PING */
	if (strcmp(dest, ip) == 0)
		icmp_ping_one(chat, NULL, ip, __npkt, __delay, 1000);
	else
		icmp_ping_one(chat, dest, ip, __npkt, __delay, 1000);
	acl_netdb_free(dns_db);  /* ÊÍ·ÅÓòÃû½âÎö¶ÔÏó */
	display_res2(chat);  /* ÏÔÊ¾ PING ½á¹û */
	icmp_chat_free(chat);  /* ÊÍ·Å ICMP ¶ÔÏó */
	return (NULL);
}

/* ¶àÏß³Ì·½Ê½ PING ¶à¸öÄ¿±êµØÖ·£¬Ã¿¸öÏß³Ì²ÉÓÃÍ¬²½ PING ·½Ê½ */
static void ping_main_threads(const ACL_ARGV *ip_list, int npkt)
{
	int   i, n;
	acl_pthread_t tids[128];
	acl_pthread_attr_t attr;

	__npkt = npkt;
	acl_pthread_attr_init(&attr);
	acl_pthread_attr_setdetachstate(&attr, 0);

	/* ÏÞ¶¨Ã¿´Î×î´óµÄÏß³ÌÊý£¬·ÀÖ¹ÏµÍ³¿ªÏúÌ«´ó */
	n = ip_list->argc > 128 ? 128 : ip_list->argc;
	for (i = 0; i < n; i++)
		/* ´´½¨ PING Ïß³Ì */
		acl_pthread_create(&tids[i], &attr, ping_thread, ip_list->argv[i]);

	for (i = 0; i < n; i++)
		/* »ØÊÕÏß³Ì×´Ì¬ */
		acl_pthread_join(tids[i], NULL);
}

static void usage(const char* progname)
{
	printf("usage: %s [-h help] -s [sync] -d delay -t [use thread mode] [-n npkt] [\"dest1 dest2 dest3...\"]\r\n", progname);
	printf("example: %s -n 10 www.sina.com.cn www.baidu.com www.qq.com\r\n", progname);
	printf("example: %s -s -n 10 www.sina.com.cn\r\n", progname);
#ifdef WIN32
	printf("please enter any key to exit\r\n");
	getchar();
#endif
}

/* µ±ÊÕµ½ SIGINT ÐÅºÅ(¼´ÔÚ PING ¹ý³ÌÖÐÓÃ»§°´ÏÂ ctrl + c)Ê±µÄÐÅºÅ´¦Àíº¯Êý */
static void OnSigInt(int signo acl_unused)
{
	display_res();
	exit(0);
}

int main(int argc, char* argv[])
{
	char  ch;
	int   npkt = 5, i, syn = 0, thread = 0;
	ACL_ARGV* dest_list = acl_argv_alloc(10);

	signal(SIGINT, OnSigInt);  /* ÓÃ»§°´ÏÂ ctr + c Ê±ÖÐ¶Ï PING ³ÌÐò */
	acl_socket_init();  /* ÔÚ WIN32 ÏÂÐèÒª³õÊ¼»¯È«¾ÖÌ×½Ó×Ö¿â */
	acl_msg_stdout_enable(1);  /* ÔÊÐí acl_msg_xxx ¼ÇÂ¼µÄÐÅÏ¢Êä³öÖÁÆÁÄ» */

	while ((ch = getopt(argc, argv, "htsl:n:d:")) > 0) {
		switch (ch) {
		case 'h':
			usage(argv[0]);
			return (0);
		case 's':
			syn = 1;
			break;
		case 't':
			thread = 1;
			break;
		case 'n':
			npkt = atoi(optarg);
			break;
		case 'd':
			__delay = atoi(optarg);
			break;
		default:
			usage(argv[0]);
			return (0);
		}
	}

	if (optind == argc) {
		usage(argv[0]);
		return (0);
	}

	for (i = optind; i < argc; i++) {
		acl_argv_add(dest_list, argv[i], NULL);
	}

	if (npkt <= 0)
		npkt = 0;

	/* Í¬²½ PING ·½Ê½£¬¶ÔÓÚ¶à¸öÄ¿±êµØÖ·£¬²ÉÓÃÒ»¸öÏß³Ì PING Ò»¸öµØÖ· */
	if (thread)
		ping_main_threads(dest_list, npkt);

	/* Í¬²½ PING ·½Ê½£¬Ö»ÄÜÍ¬Ê± PING Ò»¸öµØÖ· */
	else if (syn)
		ping_main_sync(dest_list->argv[0], npkt);

	/* Òì²½ PING ·½Ê½£¬¿ÉÒÔÔÚÒ»¸öÏß³ÌÖÐÍ¬Ê± PING ¶à¸öµØÖ· */
	else
		ping_main_async(dest_list, npkt);

	acl_argv_free(dest_list);

#ifdef WIN32
	printf("please enter any key to exit\r\n");
	getchar();
#endif

	acl_socket_end();
	return 0;
}
