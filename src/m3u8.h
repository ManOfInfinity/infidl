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

#ifndef INFIDL_M3U8_H
#define INFIDL_M3U8_H
#else
#error redefining INFIDL_M3U8_H
#endif

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <curl/curl.h>

#define AES_BLOCK_SIZE 16
#define M3U8_MAX_SEGMENTS 65536

/* Encryption method */
typedef enum {
  M3U8_ENC_NONE = 0,
  M3U8_ENC_AES128
} m3u8_enc_method;

/* Encryption key for segments */
typedef struct {
  m3u8_enc_method method;
  char *key_url;
  uint8_t iv[AES_BLOCK_SIZE];
  bool has_explicit_iv;
  uint8_t key_data[AES_BLOCK_SIZE];
  bool key_loaded;
} m3u8_key_s;

/* A single segment */
typedef struct {
  char *url;
  double duration;
  m3u8_key_s key;
} m3u8_segment_s;

/* Parsed media playlist */
typedef struct {
  m3u8_segment_s *segments;
  size_t segment_count;
  double total_duration;
  int media_sequence;
  char *base_url;
} m3u8_playlist_s;

/* Params from CLI */
typedef struct {
  char *url;
  char *output_filename;
  char *root_dir;
  char *proxy;
  char *tunnel_proxy;
  bool no_proxy;
  char *user_agent;
  bool no_user_agent;
  char *referer;
  char **custom_headers;
  bool tls_no_verify;
  uint8_t forced_ip_protocol;
  size_t connections;
  bool show_details;
  char *inline_cookies;
  char *cookie_file;
  bool no_color;
} m3u8_params_s;

int m3u8_download(m3u8_params_s *params);

/* vim: set filetype=c ts=2 sw=2 et spell foldmethod=syntax: */
