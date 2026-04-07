/*
    This file is a part of saldl.

    Copyright (C) 2026 ManOfInfinity <https://github.com/ManOfInfinity>
    https://github.com/ManOfInfinity/saldl

    saldl is free software: you can redistribute it and/or modify
    it under the terms of the Affero GNU General Public License as
    published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    Affero GNU General Public License for more details.

    You should have received a copy of the Affero GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef SALDL_SALDL_DEFAULTS_H
#define SALDL_SALDL_DEFAULTS_H
#else
#error redefining SALDL_SALDL_DEFAULTS_H
#endif

/* Project Info */
#define SALDL_NAME "saldl"
#define SALDL_WWW "https://github.com/ManOfInfinity/saldl"
#define SALDL_BUG "https://github.com/ManOfInfinity/saldl/issues"

/* Version is defined by the build system via git describe.
 * Falls back to this default if git is not available. */
#ifndef SALDL_VERSION
#define SALDL_VERSION "2.0"
#endif

/* Default Params */
#define SALDL_DEF_STATUS_REFRESH_INTERVAL 0.3

/* Default Params (configurable) */
#ifndef SALDL_DEF_CHUNK_SIZE
#define SALDL_DEF_CHUNK_SIZE 1*1024*1024 /* 1.00 MiB */
#endif

#ifndef SALDL_DEF_NUM_CONNECTIONS
#define SALDL_DEF_NUM_CONNECTIONS 6
#endif

/* Constants */
#define SALDL_STATUS_INITIAL_INTERVAL 0.5

/* vim: set filetype=c ts=2 sw=2 et spell foldmethod=syntax: */
