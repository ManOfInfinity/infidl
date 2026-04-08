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

#ifndef INFIDL_SEGDL_H
#define INFIDL_SEGDL_H
#else
#error redefining INFIDL_SEGDL_H
#endif

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <curl/curl.h>

/* A single segment entry from the input file */
typedef struct {
  char *url;
  char *dir;   /* per-entry dir= override */
  char *out;   /* per-entry out= override */
} seg_entry_s;

/* Parsed input file */
typedef struct {
  seg_entry_s *entries;
  size_t count;
} seg_list_s;

/* Params from CLI */
typedef struct {
  char *input_file;   /* "-" for stdin */
  char *default_dir;  /* -d / -D */
  char *proxy;
  char *tunnel_proxy;
  bool no_proxy;
  char *user_agent;
  bool no_user_agent;
  char *referer;
  char **custom_headers;
  bool tls_no_verify;
  uint8_t forced_ip_protocol;
  size_t connections;  /* concurrent downloads */
  bool show_details;
  char *inline_cookies;
  char *cookie_file;
  size_t max_retries;
  size_t retry_wait;
} segdl_params_s;

int segdl_download(segdl_params_s *params);

/* vim: set filetype=c ts=2 sw=2 et spell foldmethod=syntax: */
