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
 * @file microhttpd/tls.h
 * @brief TLS engine
 */

#ifndef TLS_H
#define TLS_H

/* must come first */
#include "mhd_options.h"

#ifdef HAVE_STDBOOL_H
#include <stdbool.h>
#endif

#include "platform.h"
#include "microhttpd.h"

#ifdef HTTPS_SUPPORT

struct MHD_TLS_Engine;
struct MHD_TLS_Context;
struct MHD_TLS_Session;

/**
 * @brief Callback to free opaque data.
 */
typedef void
(*MHD_TLS_FreeCallback)(void *data);

/**
 * @brief Callback to get a certificate.
 */
typedef int
(*MHD_TLS_GetCertificateCallback)();

/**
 * @brief Callback to read data from the transport layer.
 *
 * @return -1 on error and set errno, the number of bytes read on success.
 */
typedef ssize_t
(*MHD_TLS_ReadCallback) (void *context,
                         void *buf,
                         size_t size);

/**
 * @brief Callback to write data to the transport layer.
 *
 * @return -1 on error and set errno, the number of bytes written on success.
 */
typedef ssize_t
(*MHD_TLS_WriteCallback) (void *context,
                          const void *buf,
                          size_t size);

/**
 * @brief Client certificate mode.
 */
enum MHD_TLS_ClientCertificateMode
{
  /**
   * @brief Don't request a client certificate. This is the default.
   */
  MHD_TLS_CLIENT_CERTIFICATE_MODE_DISABLE = 0,

  /**
   * @brief Request a client certificate but don't require it.
   */
  MHD_TLS_CLIENT_CERTIFICATE_MODE_REQUEST = 1,

  /**
   * @brief Require a client certificate.
   */
  MHD_TLS_CLIENT_CERTIFICATE_MODE_REQUIRE = 2,

  /**
   * @brief Upper-bound value.
   */
  MHD_TLS_CLIENT_CERTIFICATE_MODE_MAX = MHD_TLS_CLIENT_CERTIFICATE_MODE_REQUIRE
};

/**
 * @name Special return values for session read/write functions.
 * @{
 */

/**
 * @brief An unknown error occured.
 */
#define MHD_TLS_IO_UNKNOWN_ERROR ((ssize_t)-1)

/**
 * @brief Invalid parameters.
 */
#define MHD_TLS_IO_INVALID_PARAMS ((ssize_t)-2)

/**
 * @brief Session was closed (closure alert occured).
 */
#define MHD_TLS_IO_SESSION_CLOSED ((ssize_t)-3)

/**
 * @brief Session wants to read more data.
 */
#define MHD_TLS_IO_WANTS_READ ((ssize_t)-4)

/**
 * @brief Session wants to write more data.
 */
#define MHD_TLS_IO_WANTS_WRITE ((ssize_t)-5)

/** @} */

#ifdef HAVE_OPENSSL
#include "tls_gnutls.h"
#endif

#ifdef HAVE_OPENSSL
#include "tls_openssl.h"
#endif

/**
 * @brief TLS engine structure.
 *
 * It contains a set of engine-specific functions.
 */
struct MHD_TLS_Engine
{
  /**
   * @brief Statically-allocated engine name.
   *
   * It's only used for debugging purposes.
   */
  const char *name;

  /**
   * @brief Engine type.
   */
  enum MHD_TLS_EngineType type;

  bool (*has_feature)(enum MHD_TLS_FEATURE feature);

  bool (*init_context) (struct MHD_TLS_Context *context);
  void (*deinit_context) (struct MHD_TLS_Context * context);

  bool (*set_context_certificate_cb) (struct MHD_TLS_Context *context,
                                      MHD_TLS_GetCertificateCallback cb);

  bool (*set_context_dh_params) (struct MHD_TLS_Context *context,
                                 const char *params);

  bool (*set_context_certificate) (struct MHD_TLS_Context *context,
                                   const char *certificate,
                                   const char *private_key,
                                   const char *password);

  bool (*set_context_trust_certificate) (struct MHD_TLS_Context *context,
                                         const char *certificate);

  bool (*set_context_client_certificate_mode) (struct MHD_TLS_Context *context,
                                               enum MHD_TLS_ClientCertificateMode mode);

  bool (*set_context_cipher_priorities) (struct MHD_TLS_Context *context,
                                         const char *priorities);

  bool (*init_session) (struct MHD_TLS_Session * session,
                        MHD_TLS_ReadCallback read_cb,
                        MHD_TLS_WriteCallback write_cb,
                        void *cb_data);
  void (*deinit_session) (struct MHD_TLS_Session * session);

  ssize_t (*session_handshake) (struct MHD_TLS_Session * session);
  ssize_t (*session_close) (struct MHD_TLS_Session * session);

  bool (*session_wants_read) (struct MHD_TLS_Session * session);
  bool (*session_wants_write) (struct MHD_TLS_Session * session);

  size_t (*session_read_pending) (struct MHD_TLS_Session *session);

  ssize_t (*session_read) (struct MHD_TLS_Session * session,
                           void *buf,
                           size_t size);
  ssize_t (*session_write) (struct MHD_TLS_Session * session,
                            const void *buf,
                            size_t size);
};

/**
 * @brief TLS context.
 *
 * It provides a logging function to keep this code insulated of the daemon
 * logging mechanism and ease testing.
 */
struct MHD_TLS_Context
{
  const struct MHD_TLS_Engine * engine;

  /* The following fields are set by @c MHD_TLS_set_context_logging_cb(). */

  /**
   * @brief Logging callback.
   */
  MHD_LogCallback log_cb;

  /**
   * @brief Opaque data for logging callback.
   */
  void *log_data;

  /**
   * @brief Function to free @c log_data.
   */
  MHD_TLS_FreeCallback free_log_data_cb;

  union
  {
#ifdef HAVE_GNUTLS
    struct MHD_GnuTLS_Context gnutls;
#endif
#ifdef HAVE_OPENSSL
    struct MHD_OpenSSL_Context openssl;
#endif
  } d;
};

struct MHD_TLS_Session
{
  struct MHD_TLS_Context * context;

  void * cb_data;
  MHD_TLS_FreeCallback free_cb_data_cb;

  union
  {
#ifdef HAVE_GNUTLS
    struct MHD_GnuTLS_Session gnutls;
#endif
#ifdef HAVE_OPENSSL
    struct MHD_OpenSSL_Session openssl;
#endif
  } d;
};

#ifdef HAVE_MESSAGES

void
MHD_TLS_LOG_CONTEXT (struct MHD_TLS_Context *context,
                     const char *format,
                     ...);

void
MHD_TLS_LOG_SESSION (struct MHD_TLS_Session *session,
                     const char *format,
                     ...);

#else /* !HAVE_MESSAGES */

#define MHD_TLS_LOG_CONTEXT(context, format, ...) do {} while(false)
#define MHD_TLS_LOG_SESSION(session, format, ...) do {} while(false)

#endif /* !HAVE_MESSAGES */

void
MHD_TLS_global_init (void);

void
MHD_TLS_global_deinit (void);

const struct MHD_TLS_Engine *
MHD_TLS_lookup_engine (enum MHD_TLS_EngineType type);

bool
MHD_TLS_engine_has_feature (const struct MHD_TLS_Engine *engine,
                            enum MHD_TLS_FEATURE feature);

struct MHD_TLS_Context *
MHD_TLS_create_context (const struct MHD_TLS_Engine *engine,
                        MHD_LogCallback cb,
                        void *data,
                        MHD_TLS_FreeCallback free_data_cb);

void
MHD_TLS_del_context (struct MHD_TLS_Context *context);


void
MHD_TLS_log_context (struct MHD_TLS_Context *context,
                     const char *format,
                     ...);

void
MHD_TLS_log_context_va (struct MHD_TLS_Context *context,
                        const char *format,
                        va_list args);

bool
MHD_TLS_set_context_certificate_cb (struct MHD_TLS_Context *context,
                                    MHD_TLS_GetCertificateCallback cb);

bool
MHD_TLS_set_context_dh_params (struct MHD_TLS_Context *context,
                               const char *params);

bool
MHD_TLS_set_context_certificate (struct MHD_TLS_Context *context,
                                 const char *certificate,
                                 const char *private_key,
                                 const char *password);

bool
MHD_TLS_set_context_trust_certificate (struct MHD_TLS_Context *context,
                                       const char *certificate);

bool
MHD_TLS_set_context_client_certificate_mode (struct MHD_TLS_Context *context,
                                             enum MHD_TLS_ClientCertificateMode mode);

bool
MHD_TLS_set_context_cipher_priorities (struct MHD_TLS_Context *context,
                                       const char *priorities);

struct MHD_TLS_Session *
MHD_TLS_create_session (struct MHD_TLS_Context * context,
                        MHD_TLS_ReadCallback read_cb,
                        MHD_TLS_WriteCallback write_cb,
                        void *cb_data,
                        MHD_TLS_FreeCallback free_data_cb);

void
MHD_TLS_del_session (struct MHD_TLS_Session *session);

ssize_t
MHD_TLS_session_handshake (struct MHD_TLS_Session * session);

ssize_t
MHD_TLS_session_close (struct MHD_TLS_Session * session);

bool
MHD_TLS_session_wants_read (struct MHD_TLS_Session *session);
bool
MHD_TLS_session_wants_write (struct MHD_TLS_Session *session);

size_t
MHD_TLS_session_read_pending (struct MHD_TLS_Session *session);

ssize_t MHD_TLS_session_read (struct MHD_TLS_Session * session,
                              void *buf,
                              size_t size);
ssize_t MHD_TLS_session_write (struct MHD_TLS_Session * session,
                               const void *buf,
                               size_t size);

#endif /* HTTPS_SUPPORT */

#endif
