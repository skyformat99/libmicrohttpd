/*
  This file is part of libmicrohttpd
  Copyright (C) 2007-2017 Daniel Pittman and Christian Grothoff

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/

/**
 * @file microhttpd/tls_openssl.h
 * @brief OpenSSL-based TLS engine
 */

#ifndef TLS_OPENSSL_H
#define TLS_OPENSSL_H

#include <openssl/ssl.h>
#include <openssl/x509.h>

struct MHD_OpenSSL_Context
{
  /**
   * @brief OpenSSL context.
   */
  SSL_CTX *context;
};

struct MHD_OpenSSL_Session
{
  /**
   * @brief OpenSSL session.
   */
  SSL *session;
};

void
MHD_TLS_openssl_init (void);

void
MHD_TLS_openssl_deinit (void);

bool
MHD_TLS_openssl_init_context (struct MHD_TLS_Context *context);

void
MHD_TLS_openssl_deinit_context (struct MHD_TLS_Context * context);

bool
MHD_TLS_openssl_set_context_certificate_cb (struct MHD_TLS_Context *context,
                                            MHD_TLS_GetCertificateCallback cb);

bool
MHD_TLS_openssl_set_context_dh_params (struct MHD_TLS_Context *context,
                                       const char *params);

bool
MHD_TLS_openssl_set_context_certificate (struct MHD_TLS_Context *context,
                                         const char *certificate,
                                         const char *private_key,
                                         const char *password);
bool
MHD_TLS_openssl_set_context_trust_certificate (struct MHD_TLS_Context *context,
                                               const char *certificate);

bool
MHD_TLS_openssl_set_context_client_certificate_mode (struct MHD_TLS_Context *context,
                                                     enum MHD_TLS_ClientCertificateMode mode);

bool
MHD_TLS_openssl_set_context_cipher_priorities (struct MHD_TLS_Context *context,
                                               const char *priorities);

bool
MHD_TLS_openssl_init_session (struct MHD_TLS_Session * session,
                              MHD_TLS_ReadCallback read_cb,
                              MHD_TLS_WriteCallback write_cb,
                              void *cb_data);

void
MHD_TLS_openssl_deinit_session (struct MHD_TLS_Session * session);

ssize_t
MHD_TLS_openssl_session_handshake (struct MHD_TLS_Session * session);

ssize_t
MHD_TLS_openssl_session_close (struct MHD_TLS_Session * session);

bool
MHD_TLS_openssl_session_wants_read (struct MHD_TLS_Session *session);

bool
MHD_TLS_openssl_session_wants_write (struct MHD_TLS_Session *session);

size_t
MHD_TLS_openssl_session_read_pending (struct MHD_TLS_Session *session);

ssize_t
MHD_TLS_openssl_session_read (struct MHD_TLS_Session * session,
                              void *buf,
                              size_t size);

ssize_t
MHD_TLS_openssl_session_write (struct MHD_TLS_Session * session,
                               const void *buf,
                               size_t size);

#endif
