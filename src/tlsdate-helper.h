/* Copyright (c) 2012, Jacob Appelbaum
 * Copyright (c) 2012, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
  * \file tlsdate-helper.h
  * \brief The secondary header for our clock helper.
  **/

#ifndef TLSDATEHELPER_H
#define TLSDATEHELPER_H

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <time.h>
#include <pwd.h>
#include <grp.h>
#include <arpa/inet.h>
#include <ctype.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>

#include "src/compat/clock.h"

/** Name of user that we feel safe to run SSL handshake with. */
#ifndef UNPRIV_USER
#define UNPRIV_USER "nobody"
#endif
#ifndef UNPRIV_GROUP
#define UNPRIV_GROUP "nogroup"
#endif

// We should never accept a time before we were compiled
// We measure in seconds since the epoch - eg: echo `date '+%s'`
// We set this manually to ensure others can reproduce a build;
// automation of this will make every build different!
#ifndef RECENT_COMPILE_DATE
#define RECENT_COMPILE_DATE 1342323666L
#endif

#ifndef MAX_REASONABLE_TIME
#define MAX_REASONABLE_TIME 1999991337L
#endif

#ifndef MIN_PUB_KEY_LEN
#define MIN_PUB_KEY_LEN (uint32_t) 1023
#endif

#ifndef MIN_ECC_PUB_KEY_LEN
#define MIN_ECC_PUB_KEY_LEN (uint32_t) 160
#endif

#ifndef MAX_ECC_PUB_KEY_LEN
#define MAX_ECC_PUB_KEY_LEN (uint32_t) 521
#endif
// After the duration of the TLS handshake exceeds this threshold
// (in msec), the time sync fails (see b/582991618). Note that if a
// brief suspend occurs across the handshake, the synced timestamp
// can be stale by up to TLS_RTT_THRESHOLD when tlsdate-helper is
// invoked with -Vraw/-n by tlsdated.
#define TLS_RTT_THRESHOLD      5000

// RFC 5280 says...
// ub-common-name-length INTEGER ::= 64
#define MAX_CN_NAME_LENGTH 64

// RFC 1034 and posix say...
#define TLSDATE_HOST_NAME_MAX 255

// To support our RFC 2595 wildcard verification
#define RFC2595_MIN_LABEL_COUNT 3

uint32_t get_certificate_keybits (EVP_PKEY *public_key);
uint32_t check_cn (SSL *ssl, const char *hostname);
uint32_t check_san (SSL *ssl, const char *hostname);
long openssl_check_against_host_and_verify (SSL *ssl);
uint32_t check_name (SSL *ssl, const char *hostname);
uint32_t verify_signature (SSL *ssl, const char *hostname);
void check_key_length (SSL *ssl);
void inspect_key (SSL *ssl, const char *hostname);
uint32_t dns_label_count (char *label, char *delim);
uint32_t check_wildcard_match_rfc2595 (const char *orig_hostname,
                                       const char *orig_cert_wild_card);
long long check_rtt (const struct tlsdate_time *start_time,
                     const struct tlsdate_time *end_time,
                     uint32_t server_time_s);
void init_server_time (uint32_t server_time_s,
                       long long rt_time_ms,
                       struct tlsdate_time *server_time);

#endif
