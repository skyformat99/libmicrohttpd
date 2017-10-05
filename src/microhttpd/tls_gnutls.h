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
 * @file microhttpd/tls_gnutls.h
 * @brief GnuTLS-based TLS engine
 */

#ifndef TLS_GNUTLS_H
#define TLS_GNUTLS_H

#include <gnutls/gnutls.h>
#if GNUTLS_VERSION_MAJOR >= 3
#include <gnutls/abstract.h>
#endif

struct MHD_GnuTLS_Context
{
  /**
   * @brief Desired cipher algorithms.
   */
  gnutls_priority_t priority_cache;

  /**
   * @brief Server x509 credentials.
   */
  gnutls_certificate_credentials_t x509_cred;

  /**
   * @brief Client certificate mode.
   */
  enum MHD_TLS_ClientCertificateMode client_cert_mode;
#if 0
#if GNUTLS_VERSION_MAJOR >= 3
  /**
   * @brief Function that can be used to obtain the certificate.
   *
   * Needed for SNI support.
   *
   * @see #MHD_OPTION_HTTPS_CERT_CALLBACK
   */
  gnutls_certificate_retrieve_function2 *cert_callback;
#endif

  /**
   * @brief Our Diffie-Hellman parameters.
   */
  gnutls_dh_params_t dh_params;
#endif
};

struct MHD_GnuTLS_Session
{
  /**
   * @brief GnuTLS session.
   */
  gnutls_session_t session;
};

void
MHD_TLS_gnutls_init (void);

void
MHD_TLS_gnutls_deinit (void);

bool
MHD_TLS_gnutls_init_context (struct MHD_TLS_Context *context);

void
MHD_TLS_gnutls_deinit_context (struct MHD_TLS_Context * context);

bool
MHD_TLS_gnutls_set_context_certificate_cb (struct MHD_TLS_Context *context,
                                           MHD_TLS_GetCertificate cb);

bool
MHD_TLS_gnutls_set_context_dh_params (struct MHD_TLS_Context *context,
                                      const char *params);

bool
MHD_TLS_gnutls_set_context_certificate (struct MHD_TLS_Context *context,
                                        const char *certificate,
                                        const char *private_key,
                                        const char *password);

bool
MHD_TLS_gnutls_set_context_trust_certificate (struct MHD_TLS_Context *context,
                                              const char *certificate);

bool
MHD_TLS_gnutls_set_context_client_certificate_mode (struct MHD_TLS_Context *context,
                                                    enum MHD_TLS_ClientCertificateMode mode);

bool
MHD_TLS_gnutls_set_context_cipher_priorities (struct MHD_TLS_Context *context,
                                              const char *priorities);

bool
MHD_TLS_gnutls_init_session (struct MHD_TLS_Session * session);

void
MHD_TLS_gnutls_deinit_session (struct MHD_TLS_Session * session);

ssize_t
MHD_TLS_gnutls_session_handshake (struct MHD_TLS_Session * session);

ssize_t
MHD_TLS_gnutls_session_close (struct MHD_TLS_Session * session);

bool
MHD_TLS_gnutls_session_wants_read (struct MHD_TLS_Session *session);

bool
MHD_TLS_gnutls_session_wants_write (struct MHD_TLS_Session *session);

size_t
MHD_TLS_gnutls_session_read_pending (struct MHD_TLS_Session *session);

ssize_t
MHD_TLS_gnutls_session_read (struct MHD_TLS_Session * session,
                             void *buf,
                             size_t size);

ssize_t
MHD_TLS_gnutls_session_write (struct MHD_TLS_Session * session,
                              const void *buf,
                              size_t size);

#endif
