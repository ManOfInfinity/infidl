/*
    This file is a part of infidl.

    Copyright (C) 2026 ManOfInfinity <https://github.com/ManOfInfinity>
    https://github.com/ManOfInfinity/infidl

    infidl is free software: you can redistribute it and/or modify
    it under the terms of the Affero GNU General Public License as
    published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    Affero GNU General Public License for more details.

    You should have received a copy of the Affero GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#else
#include <pthread.h>
#include <unistd.h>
#endif

#include "m3u8.h"
#include "log.h"

/* strndup is not available on MinGW/Windows */
#ifndef HAVE_STRNDUP
#ifdef _WIN32
static char *infidl_strndup(const char *s, size_t n) {
  size_t len = strlen(s);
  if (n < len) len = n;
  char *result = malloc(len + 1);
  if (!result) return NULL;
  memcpy(result, s, len);
  result[len] = '\0';
  return result;
}
#define strndup infidl_strndup
#endif
#endif

/* ========================================================================= */
/*  AES-128-CBC (self-contained, no OpenSSL dependency)                      */
/* ========================================================================= */

static const uint8_t aes_sbox[256] = {
  0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
  0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
  0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
  0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
  0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
  0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
  0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
  0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
  0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
  0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
  0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
  0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
  0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
  0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
  0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
  0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static const uint8_t aes_inv_sbox[256] = {
  0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
  0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
  0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
  0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
  0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
  0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
  0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
  0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
  0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
  0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
  0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
  0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
  0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
  0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
  0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
  0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};

static const uint8_t rcon[11] = {
  0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36
};

static uint8_t gf_mul(uint8_t a, uint8_t b) {
  uint8_t p = 0;
  for (int i = 0; i < 8; i++) {
    if (b & 1) p ^= a;
    uint8_t hi = a & 0x80;
    a <<= 1;
    if (hi) a ^= 0x1b;
    b >>= 1;
  }
  return p;
}

typedef struct { uint8_t round_keys[176]; } aes128_ctx;

static void aes128_key_expand(aes128_ctx *ctx, const uint8_t key[16]) {
  memcpy(ctx->round_keys, key, 16);
  for (int i = 4; i < 44; i++) {
    uint8_t tmp[4];
    memcpy(tmp, ctx->round_keys + (i-1)*4, 4);
    if (i % 4 == 0) {
      uint8_t t = tmp[0];
      tmp[0] = aes_sbox[tmp[1]] ^ rcon[i/4];
      tmp[1] = aes_sbox[tmp[2]];
      tmp[2] = aes_sbox[tmp[3]];
      tmp[3] = aes_sbox[t];
    }
    for (int j = 0; j < 4; j++)
      ctx->round_keys[i*4+j] = ctx->round_keys[(i-4)*4+j] ^ tmp[j];
  }
}

static void aes128_decrypt_block(const aes128_ctx *ctx, const uint8_t in[16], uint8_t out[16]) {
  uint8_t state[16];
  memcpy(state, in, 16);

  /* AddRoundKey (round 10) */
  for (int i = 0; i < 16; i++) state[i] ^= ctx->round_keys[160+i];

  for (int round = 9; round >= 1; round--) {
    /* InvShiftRows */
    uint8_t t;
    t = state[13]; state[13] = state[9]; state[9] = state[5]; state[5] = state[1]; state[1] = t;
    t = state[2]; state[2] = state[10]; state[10] = t; t = state[6]; state[6] = state[14]; state[14] = t;
    t = state[3]; state[3] = state[7]; state[7] = state[11]; state[11] = state[15]; state[15] = t;

    /* InvSubBytes */
    for (int i = 0; i < 16; i++) state[i] = aes_inv_sbox[state[i]];

    /* AddRoundKey */
    for (int i = 0; i < 16; i++) state[i] ^= ctx->round_keys[round*16+i];

    /* InvMixColumns */
    for (int c = 0; c < 4; c++) {
      uint8_t s0 = state[c*4], s1 = state[c*4+1], s2 = state[c*4+2], s3 = state[c*4+3];
      state[c*4+0] = gf_mul(s0,0x0e) ^ gf_mul(s1,0x0b) ^ gf_mul(s2,0x0d) ^ gf_mul(s3,0x09);
      state[c*4+1] = gf_mul(s0,0x09) ^ gf_mul(s1,0x0e) ^ gf_mul(s2,0x0b) ^ gf_mul(s3,0x0d);
      state[c*4+2] = gf_mul(s0,0x0d) ^ gf_mul(s1,0x09) ^ gf_mul(s2,0x0e) ^ gf_mul(s3,0x0b);
      state[c*4+3] = gf_mul(s0,0x0b) ^ gf_mul(s1,0x0d) ^ gf_mul(s2,0x09) ^ gf_mul(s3,0x0e);
    }
  }

  /* Round 0: InvShiftRows, InvSubBytes, AddRoundKey */
  uint8_t t;
  t = state[13]; state[13] = state[9]; state[9] = state[5]; state[5] = state[1]; state[1] = t;
  t = state[2]; state[2] = state[10]; state[10] = t; t = state[6]; state[6] = state[14]; state[14] = t;
  t = state[3]; state[3] = state[7]; state[7] = state[11]; state[11] = state[15]; state[15] = t;
  for (int i = 0; i < 16; i++) state[i] = aes_inv_sbox[state[i]];
  for (int i = 0; i < 16; i++) state[i] ^= ctx->round_keys[i];

  memcpy(out, state, 16);
}

/* Decrypt AES-128-CBC with PKCS#7 padding removal.
 * Decrypts in-place. Returns new length or -1 on error. */
static ssize_t aes128_cbc_decrypt(const uint8_t key[16], const uint8_t iv[16],
                                  uint8_t *data, size_t len) {
  if (len == 0) return 0;
  if (len % AES_BLOCK_SIZE != 0) return -1;

  aes128_ctx ctx;
  aes128_key_expand(&ctx, key);

  uint8_t prev_ct[AES_BLOCK_SIZE];
  memcpy(prev_ct, iv, AES_BLOCK_SIZE);

  for (size_t i = 0; i < len; i += AES_BLOCK_SIZE) {
    uint8_t ct_block[AES_BLOCK_SIZE];
    memcpy(ct_block, data + i, AES_BLOCK_SIZE);

    uint8_t pt_block[AES_BLOCK_SIZE];
    aes128_decrypt_block(&ctx, data + i, pt_block);

    for (int j = 0; j < AES_BLOCK_SIZE; j++)
      data[i + j] = pt_block[j] ^ prev_ct[j];

    memcpy(prev_ct, ct_block, AES_BLOCK_SIZE);
  }

  /* Remove PKCS#7 padding */
  uint8_t pad = data[len - 1];
  if (pad == 0 || pad > AES_BLOCK_SIZE) return (ssize_t)len; /* no valid padding, return as-is */
  for (size_t i = 0; i < pad; i++) {
    if (data[len - 1 - i] != pad) return (ssize_t)len; /* invalid padding */
  }
  return (ssize_t)(len - pad);
}

/* ========================================================================= */
/*  HTTP helper (fetch URL into memory buffer using libcurl)                 */
/* ========================================================================= */

typedef struct {
  uint8_t *data;
  size_t size;
  size_t capacity;
} mem_buf_s;

static size_t write_mem_cb(void *contents, size_t size, size_t nmemb, void *userp) {
  size_t total = size * nmemb;
  mem_buf_s *buf = (mem_buf_s *)userp;
  if (buf->size + total >= buf->capacity) {
    size_t new_cap = (buf->capacity + total) * 2;
    uint8_t *tmp = realloc(buf->data, new_cap);
    if (!tmp) return 0;
    buf->data = tmp;
    buf->capacity = new_cap;
  }
  memcpy(buf->data + buf->size, contents, total);
  buf->size += total;
  return total;
}

static void apply_curl_opts(CURL *curl, m3u8_params_s *params) {
  if (params->proxy && !params->no_proxy)
    curl_easy_setopt(curl, CURLOPT_PROXY, params->proxy);
  if (params->tunnel_proxy && !params->no_proxy) {
    curl_easy_setopt(curl, CURLOPT_PROXY, params->tunnel_proxy);
    curl_easy_setopt(curl, CURLOPT_HTTPPROXYTUNNEL, 1L);
  }
  if (params->no_proxy)
    curl_easy_setopt(curl, CURLOPT_NOPROXY, "*");
  if (params->user_agent && !params->no_user_agent)
    curl_easy_setopt(curl, CURLOPT_USERAGENT, params->user_agent);
  if (params->referer)
    curl_easy_setopt(curl, CURLOPT_REFERER, params->referer);
  if (params->tls_no_verify) {
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
  }
  if (params->forced_ip_protocol == 4)
    curl_easy_setopt(curl, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);
  else if (params->forced_ip_protocol == 6)
    curl_easy_setopt(curl, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V6);
  if (params->inline_cookies)
    curl_easy_setopt(curl, CURLOPT_COOKIE, params->inline_cookies);
  if (params->cookie_file)
    curl_easy_setopt(curl, CURLOPT_COOKIEFILE, params->cookie_file);

  if (params->custom_headers) {
    struct curl_slist *headers = NULL;
    for (int i = 0; params->custom_headers[i]; i++)
      headers = curl_slist_append(headers, params->custom_headers[i]);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
  }

  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
  curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 10L);
  curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);

#ifdef _WIN32
  curl_easy_setopt(curl, CURLOPT_SSL_OPTIONS, CURLSSLOPT_NATIVE_CA);
#endif
}

static int fetch_url(m3u8_params_s *params, const char *url, mem_buf_s *buf) {
  CURL *curl = curl_easy_init();
  if (!curl) return -1;

  buf->data = malloc(4096);
  buf->size = 0;
  buf->capacity = 4096;

  curl_easy_setopt(curl, CURLOPT_URL, url);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_mem_cb);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, buf);
  apply_curl_opts(curl, params);

  CURLcode res = curl_easy_perform(curl);
  long http_code = 0;
  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
  curl_easy_cleanup(curl);

  if (res != CURLE_OK || (http_code >= 400)) {
    free(buf->data);
    buf->data = NULL;
    buf->size = 0;
    return -1;
  }
  return 0;
}

/* ========================================================================= */
/*  URL resolution                                                           */
/* ========================================================================= */

static char *resolve_url(const char *base, const char *ref) {
  /* Absolute URL */
  if (strstr(ref, "://")) return strdup(ref);

  /* Protocol-relative */
  if (ref[0] == '/' && ref[1] == '/') {
    const char *colon = strstr(base, "://");
    size_t plen = colon ? (size_t)(colon - base) : 5;
    char *result = malloc(plen + strlen(ref) + 1);
    memcpy(result, base, plen);
    strcpy(result + plen, ref);
    return result;
  }

  /* Absolute path */
  if (ref[0] == '/') {
    const char *scheme_end = strstr(base, "://");
    if (!scheme_end) return strdup(ref);
    const char *host_start = scheme_end + 3;
    const char *host_end = strchr(host_start, '/');
    size_t prefix_len = host_end ? (size_t)(host_end - base) : strlen(base);
    char *result = malloc(prefix_len + strlen(ref) + 1);
    memcpy(result, base, prefix_len);
    strcpy(result + prefix_len, ref);
    return result;
  }

  /* Relative path — append to base directory */
  const char *last_slash = strrchr(base, '/');
  if (!last_slash) return strdup(ref);
  size_t dir_len = (size_t)(last_slash - base) + 1;
  char *result = malloc(dir_len + strlen(ref) + 1);
  memcpy(result, base, dir_len);
  strcpy(result + dir_len, ref);
  return result;
}

/* ========================================================================= */
/*  M3U8 parser                                                              */
/* ========================================================================= */

static int hex_to_bytes(const char *hex, uint8_t *out, size_t out_len) {
  if (hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) hex += 2;
  size_t hex_len = strlen(hex);
  if (hex_len != out_len * 2) return -1;
  for (size_t i = 0; i < out_len; i++) {
    unsigned int val;
    if (sscanf(hex + i*2, "%2x", &val) != 1) return -1;
    out[i] = (uint8_t)val;
  }
  return 0;
}

static char *parse_attr(const char *line, const char *attr) {
  const char *p = strstr(line, attr);
  if (!p) return NULL;
  p += strlen(attr);
  if (*p == '"') {
    p++;
    const char *end = strchr(p, '"');
    if (!end) return NULL;
    return strndup(p, (size_t)(end - p));
  }
  const char *end = p;
  while (*end && *end != ',' && *end != '\n' && *end != '\r') end++;
  return strndup(p, (size_t)(end - p));
}

static int parse_media_playlist(const char *data, size_t len, const char *base_url,
                                m3u8_playlist_s *playlist) {
  playlist->segments = calloc(M3U8_MAX_SEGMENTS, sizeof(m3u8_segment_s));
  playlist->segment_count = 0;
  playlist->total_duration = 0;
  playlist->media_sequence = 0;
  playlist->base_url = strdup(base_url);

  /* Current encryption state (persists across segments per HLS spec) */
  m3u8_key_s current_key = {0};
  double seg_duration = 0;

  const char *p = data;
  const char *end = data + len;

  while (p < end) {
    /* Find line end */
    const char *line_end = p;
    while (line_end < end && *line_end != '\n' && *line_end != '\r') line_end++;
    size_t line_len = (size_t)(line_end - p);

    if (line_len > 0) {
      /* Make a null-terminated copy */
      char *line = strndup(p, line_len);

      if (strncmp(line, "#EXT-X-MEDIA-SEQUENCE:", 22) == 0) {
        playlist->media_sequence = atoi(line + 22);
      }
      else if (strncmp(line, "#EXT-X-KEY:", 11) == 0) {
        char *method = parse_attr(line, "METHOD=");
        if (method) {
          if (strcmp(method, "NONE") == 0) {
            current_key.method = M3U8_ENC_NONE;
          }
          else if (strcmp(method, "AES-128") == 0) {
            current_key.method = M3U8_ENC_AES128;
            free(current_key.key_url);
            char *uri = parse_attr(line, "URI=");
            if (uri) {
              current_key.key_url = resolve_url(base_url, uri);
              free(uri);
            }
            current_key.key_loaded = false;

            char *iv_str = parse_attr(line, "IV=");
            if (iv_str) {
              hex_to_bytes(iv_str, current_key.iv, AES_BLOCK_SIZE);
              current_key.has_explicit_iv = true;
              free(iv_str);
            } else {
              current_key.has_explicit_iv = false;
            }
          }
          free(method);
        }
      }
      else if (strncmp(line, "#EXTINF:", 8) == 0) {
        seg_duration = atof(line + 8);
      }
      else if (line[0] != '#' && line_len > 0) {
        /* This is a segment URI */
        if (playlist->segment_count >= M3U8_MAX_SEGMENTS) {
          free(line);
          break;
        }
        m3u8_segment_s *seg = &playlist->segments[playlist->segment_count];
        seg->url = resolve_url(base_url, line);
        seg->duration = seg_duration;
        seg->key = current_key;
        if (current_key.key_url)
          seg->key.key_url = strdup(current_key.key_url);

        /* If no explicit IV, use media sequence number */
        if (current_key.method == M3U8_ENC_AES128 && !current_key.has_explicit_iv) {
          memset(seg->key.iv, 0, AES_BLOCK_SIZE);
          uint32_t seq = (uint32_t)(playlist->media_sequence + (int)playlist->segment_count);
          seg->key.iv[12] = (uint8_t)(seq >> 24);
          seg->key.iv[13] = (uint8_t)(seq >> 16);
          seg->key.iv[14] = (uint8_t)(seq >> 8);
          seg->key.iv[15] = (uint8_t)(seq);
        }

        playlist->total_duration += seg_duration;
        playlist->segment_count++;
        seg_duration = 0;
      }

      free(line);
    }

    /* Skip past line ending */
    p = line_end;
    while (p < end && (*p == '\n' || *p == '\r')) p++;
  }

  return (playlist->segment_count > 0) ? 0 : -1;
}

/* ========================================================================= */
/*  Segment download + progress                                              */
/* ========================================================================= */

typedef struct {
  size_t completed;
  size_t total;
  size_t total_bytes;
  double total_duration;
#ifdef _WIN32
  CRITICAL_SECTION lock;
#else
  pthread_mutex_t lock;
#endif
} m3u8_progress_s;

static void progress_init(m3u8_progress_s *p, size_t total, double duration) {
  p->completed = 0;
  p->total = total;
  p->total_bytes = 0;
  p->total_duration = duration;
#ifdef _WIN32
  InitializeCriticalSection(&p->lock);
#else
  pthread_mutex_init(&p->lock, NULL);
#endif
}

static void progress_update(m3u8_progress_s *p, size_t bytes) {
#ifdef _WIN32
  EnterCriticalSection(&p->lock);
#else
  pthread_mutex_lock(&p->lock);
#endif
  p->completed++;
  p->total_bytes += bytes;
  double pct = (double)p->completed * 100.0 / (double)p->total;
  int bar_width = 40;
  int filled = (int)(pct * bar_width / 100.0);
  if (filled > bar_width) filled = bar_width;

  fprintf(stderr, "\r [");
  if (p->completed == p->total) {
    fprintf(stderr, "\033[32m");
    for (int i = 0; i < bar_width; i++) fprintf(stderr, "=");
    fprintf(stderr, "\033[0m");
  } else {
    if (filled > 0) {
      fprintf(stderr, "\033[33m");
      for (int i = 0; i < filled - 1; i++) fprintf(stderr, "=");
      fprintf(stderr, ">");
      fprintf(stderr, "\033[0m");
    }
    fprintf(stderr, "\033[90m");
    for (int i = filled; i < bar_width; i++)
      fprintf(stderr, "%s", ((i - filled) % 3 == 2) ? " " : "-");
    fprintf(stderr, "\033[0m");
  }

  /* Format total bytes */
  double size = (double)p->total_bytes;
  const char *suffix = "B";
  if (size >= 1073741824.0) { size /= 1073741824.0; suffix = "GiB"; }
  else if (size >= 1048576.0) { size /= 1048576.0; suffix = "MiB"; }
  else if (size >= 1024.0) { size /= 1024.0; suffix = "KiB"; }

  if (p->completed == p->total) {
    fprintf(stderr, "] \033[32m%5.1f%%\033[0m | %zu/%zu segments | %.1f %s   ",
        pct, p->completed, p->total, size, suffix);
  } else {
    fprintf(stderr, "] \033[33m%5.1f%%\033[0m | %zu/%zu segments | %.1f %s   ",
        pct, p->completed, p->total, size, suffix);
  }
  fflush(stderr);

#ifdef _WIN32
  LeaveCriticalSection(&p->lock);
#else
  pthread_mutex_unlock(&p->lock);
#endif
}

static void progress_finish(m3u8_progress_s *p) {
  fprintf(stderr, "\n");
#ifdef _WIN32
  DeleteCriticalSection(&p->lock);
#else
  pthread_mutex_destroy(&p->lock);
#endif
}

/* Download a single segment, decrypt if needed, write to output file at correct position.
 * For simplicity, we download segments sequentially to a single output file. */
static int download_segment(m3u8_params_s *params, m3u8_segment_s *seg, FILE *out,
                            m3u8_progress_s *progress) {
  mem_buf_s buf = {0};
  if (fetch_url(params, seg->url, &buf) != 0) {
    err_msg("m3u8", "Failed to download segment: %s", seg->url);
    return -1;
  }

  /* Decrypt if AES-128 */
  size_t write_len = buf.size;
  if (seg->key.method == M3U8_ENC_AES128) {
    /* Fetch key if not already loaded */
    if (!seg->key.key_loaded && seg->key.key_url) {
      mem_buf_s key_buf = {0};
      if (fetch_url(params, seg->key.key_url, &key_buf) != 0 || key_buf.size != 16) {
        err_msg("m3u8", "Failed to fetch decryption key: %s", seg->key.key_url);
        free(buf.data);
        free(key_buf.data);
        return -1;
      }
      memcpy(seg->key.key_data, key_buf.data, 16);
      seg->key.key_loaded = true;
      free(key_buf.data);
    }

    ssize_t dec_len = aes128_cbc_decrypt(seg->key.key_data, seg->key.iv, buf.data, buf.size);
    if (dec_len < 0) {
      err_msg("m3u8", "Decryption failed for segment: %s", seg->url);
      free(buf.data);
      return -1;
    }
    write_len = (size_t)dec_len;
  }

  fwrite(buf.data, 1, write_len, out);
  progress_update(progress, write_len);

  free(buf.data);
  return 0;
}

/* ========================================================================= */
/*  Concurrent segment downloader                                            */
/* ========================================================================= */

typedef struct {
  m3u8_params_s *params;
  m3u8_segment_s *segments;
  size_t start_idx;
  size_t end_idx;         /* exclusive */
  FILE *tmp_file;         /* per-worker temp file */
  char *tmp_filename;
  m3u8_progress_s *progress;
  int result;
} worker_ctx_s;

static void *worker_thread(void *arg) {
  worker_ctx_s *ctx = (worker_ctx_s *)arg;
  ctx->result = 0;

  for (size_t i = ctx->start_idx; i < ctx->end_idx; i++) {
    if (download_segment(ctx->params, &ctx->segments[i], ctx->tmp_file, ctx->progress) != 0) {
      ctx->result = -1;
      break;
    }
  }
  return NULL;
}

/* ========================================================================= */
/*  Public API                                                               */
/* ========================================================================= */

int m3u8_download(m3u8_params_s *params) {
  curl_global_init(CURL_GLOBAL_ALL);

  if (params->show_details) {
    fprintf(stderr, "M3U8 URL: %s\n", params->url);
  }

  /* Fetch the playlist */
  mem_buf_s playlist_buf = {0};
  if (fetch_url(params, params->url, &playlist_buf) != 0) {
    fatal("m3u8", "Failed to fetch M3U8 playlist: %s", params->url);
    return -1;
  }

  /* Null-terminate for parsing */
  playlist_buf.data = realloc(playlist_buf.data, playlist_buf.size + 1);
  playlist_buf.data[playlist_buf.size] = '\0';

  /* Check if this is a master playlist (has #EXT-X-STREAM-INF) */
  if (strstr((char *)playlist_buf.data, "#EXT-X-STREAM-INF")) {
    /* Master playlist — find best bandwidth variant */
    const char *p = (char *)playlist_buf.data;
    const char *end = p + playlist_buf.size;
    char *best_url = NULL;
    long best_bw = 0;

    while (p < end) {
      const char *le = p;
      while (le < end && *le != '\n' && *le != '\r') le++;
      size_t ll = (size_t)(le - p);

      if (ll > 0 && strncmp(p, "#EXT-X-STREAM-INF:", 18) == 0) {
        char *line = strndup(p, ll);
        char *bw_str = parse_attr(line, "BANDWIDTH=");
        long bw = bw_str ? atol(bw_str) : 0;
        free(bw_str);
        free(line);

        /* Next non-empty, non-comment line is the URI */
        const char *np = le;
        while (np < end && (*np == '\n' || *np == '\r')) np++;
        const char *nle = np;
        while (nle < end && *nle != '\n' && *nle != '\r') nle++;

        if (bw > best_bw && nle > np) {
          best_bw = bw;
          free(best_url);
          char *uri = strndup(np, (size_t)(nle - np));
          best_url = resolve_url(params->url, uri);
          free(uri);
        }
      }

      p = le;
      while (p < end && (*p == '\n' || *p == '\r')) p++;
    }

    free(playlist_buf.data);

    if (!best_url) {
      fatal("m3u8", "No valid streams found in master playlist");
      return -1;
    }

    info_msg("m3u8", "Selected stream: bandwidth=%ld", best_bw);

    /* Fetch the actual media playlist */
    if (fetch_url(params, best_url, &playlist_buf) != 0) {
      fatal("m3u8", "Failed to fetch media playlist: %s", best_url);
      free(best_url);
      return -1;
    }
    playlist_buf.data = realloc(playlist_buf.data, playlist_buf.size + 1);
    playlist_buf.data[playlist_buf.size] = '\0';

    /* Update URL for relative resolution */
    free(params->url);
    params->url = best_url;
  }

  /* Parse media playlist */
  m3u8_playlist_s playlist = {0};
  if (parse_media_playlist((char *)playlist_buf.data, playlist_buf.size,
                           params->url, &playlist) != 0) {
    fatal("m3u8", "Failed to parse media playlist (no segments found)");
    free(playlist_buf.data);
    return -1;
  }
  free(playlist_buf.data);

  info_msg("m3u8", "Segments: %zu, Duration: %.1fs", playlist.segment_count, playlist.total_duration);

  /* Determine output filename */
  char *output = NULL;
  if (params->output_filename) {
    output = strdup(params->output_filename);
  } else {
    output = strdup("output.ts");
  }

  if (params->root_dir) {
    char *full = malloc(strlen(params->root_dir) + strlen(output) + 2);
    sprintf(full, "%s/%s", params->root_dir, output);
    free(output);
    output = full;
  }

  if (params->show_details) {
    fprintf(stderr, "Saving To: %s\n", output);
    fprintf(stderr, "Segments: %zu | Duration: %.1fs\n", playlist.segment_count, playlist.total_duration);
  }

  /* Pre-fetch encryption keys (one per unique key URL) */
  char *last_key_url = NULL;
  uint8_t cached_key[16] = {0};
  bool key_cached = false;

  for (size_t i = 0; i < playlist.segment_count; i++) {
    m3u8_segment_s *seg = &playlist.segments[i];
    if (seg->key.method == M3U8_ENC_AES128 && seg->key.key_url) {
      if (key_cached && last_key_url && strcmp(seg->key.key_url, last_key_url) == 0) {
        memcpy(seg->key.key_data, cached_key, 16);
        seg->key.key_loaded = true;
      } else {
        mem_buf_s key_buf = {0};
        if (fetch_url(params, seg->key.key_url, &key_buf) != 0 || key_buf.size != 16) {
          fatal("m3u8", "Failed to fetch decryption key: %s", seg->key.key_url);
          free(key_buf.data);
          free(output);
          return -1;
        }
        memcpy(seg->key.key_data, key_buf.data, 16);
        seg->key.key_loaded = true;
        memcpy(cached_key, key_buf.data, 16);
        free(last_key_url);
        last_key_url = strdup(seg->key.key_url);
        key_cached = true;
        free(key_buf.data);
        info_msg("m3u8", "Loaded decryption key from: %s", seg->key.key_url);
      }
    }
  }
  free(last_key_url);

  /* Download segments */
  m3u8_progress_s progress;
  progress_init(&progress, playlist.segment_count, playlist.total_duration);

  size_t conns = params->connections;
  if (conns < 1) conns = 1;
  if (conns > playlist.segment_count) conns = playlist.segment_count;

  if (conns == 1) {
    /* Single-threaded: download directly to output */
    FILE *out = fopen(output, "wb");
    if (!out) {
      fatal("m3u8", "Cannot open output file: %s: %s", output, strerror(errno));
      free(output);
      return -1;
    }
    for (size_t i = 0; i < playlist.segment_count; i++) {
      if (download_segment(params, &playlist.segments[i], out, &progress) != 0) {
        fclose(out);
        free(output);
        return -1;
      }
    }
    fclose(out);
  } else {
    /* Multi-threaded: each worker writes segments to a temp file, then we concatenate.
     * Segments must be in order, so we split ranges among workers. */
    size_t per_worker = playlist.segment_count / conns;
    size_t remainder = playlist.segment_count % conns;

    worker_ctx_s *workers = calloc(conns, sizeof(worker_ctx_s));
#ifdef _WIN32
    HANDLE *threads = calloc(conns, sizeof(HANDLE));
#else
    pthread_t *threads = calloc(conns, sizeof(pthread_t));
#endif
    size_t idx = 0;
    for (size_t w = 0; w < conns; w++) {
      size_t count = per_worker + (w < remainder ? 1 : 0);
      workers[w].params = params;
      workers[w].segments = playlist.segments;
      workers[w].start_idx = idx;
      workers[w].end_idx = idx + count;
      workers[w].progress = &progress;

      /* Create temp file */
      char tmpname[256];
      snprintf(tmpname, sizeof(tmpname), "%s.part%zu", output, w);
      workers[w].tmp_filename = strdup(tmpname);
      workers[w].tmp_file = fopen(tmpname, "wb");
      if (!workers[w].tmp_file) {
        fatal("m3u8", "Cannot create temp file: %s", tmpname);
        free(output);
        return -1;
      }

#ifdef _WIN32
      threads[w] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)worker_thread, &workers[w], 0, NULL);
#else
      pthread_create(&threads[w], NULL, worker_thread, &workers[w]);
#endif
      idx += count;
    }

    /* Wait for all workers */
    int fail = 0;
    for (size_t w = 0; w < conns; w++) {
#ifdef _WIN32
      WaitForSingleObject(threads[w], INFINITE);
      CloseHandle(threads[w]);
#else
      pthread_join(threads[w], NULL);
#endif
      fclose(workers[w].tmp_file);
      if (workers[w].result != 0) fail = 1;
    }

    if (fail) {
      for (size_t w = 0; w < conns; w++) {
        remove(workers[w].tmp_filename);
        free(workers[w].tmp_filename);
      }
      free(workers);
      free(threads);
      free(output);
      return -1;
    }

    /* Concatenate temp files into output */
    FILE *out = fopen(output, "wb");
    if (!out) {
      fatal("m3u8", "Cannot open output file: %s", output);
      free(output);
      return -1;
    }

    uint8_t copy_buf[65536];
    for (size_t w = 0; w < conns; w++) {
      FILE *tmp = fopen(workers[w].tmp_filename, "rb");
      if (tmp) {
        size_t n;
        while ((n = fread(copy_buf, 1, sizeof(copy_buf), tmp)) > 0)
          fwrite(copy_buf, 1, n, out);
        fclose(tmp);
      }
      remove(workers[w].tmp_filename);
      free(workers[w].tmp_filename);
    }
    fclose(out);
    free(workers);
    free(threads);
  }

  progress_finish(&progress);
  info_msg("m3u8", "Download complete: %s", output);

  /* Cleanup */
  for (size_t i = 0; i < playlist.segment_count; i++) {
    free(playlist.segments[i].url);
    free(playlist.segments[i].key.key_url);
  }
  free(playlist.segments);
  free(playlist.base_url);
  free(output);

  return 0;
}

/* vim: set filetype=c ts=2 sw=2 et spell foldmethod=syntax: */
