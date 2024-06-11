/*
 * NFSv4.1 client for Windows
 * Copyright (C) 2024 Roland Mainz <roland.mainz@nrubsig.org>
 *
 * Roland Mainz <roland.mainz@nrubsig.org>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * without any warranty; without even the implied warranty of merchantability
 * or fitness for a particular purpose.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 */

#ifndef __NFS41_DAEMON_ACCESSTOKEN_H__
#define __NFS41_DAEMON_ACCESSTOKEN_H__ 1

#include <Windows.h>
#include <stdbool.h>

bool get_token_user_name(HANDLE tok, char *out_buffer);
bool get_token_primarygroup_name(HANDLE tok, char *out_buffer);
bool get_token_authenticationid(HANDLE tok, LUID *out_authenticationid);
bool set_token_privilege(HANDLE tok, const char *seprivname, bool enable_priv);

#endif /* !__NFS41_DAEMON_ACCESSTOKEN_H__ */
