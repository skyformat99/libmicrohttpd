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
 * @file tls.c
 * @brief TLS engine
 */

/* must come first */
#include "mhd_options.h"

#include <assert.h>

#include "internal.h"
#include "tls.h"
#include "mhd_compat.h"

#ifdef HAVE_GNUTLS
static bool gnutls_inited = false;
#endif

#ifdef HAVE_OPENSSL
static bool openssl_inited = false;
#endif

static const char *tls_engine_type_strings[MHD_TLS_ENGINE_TYPE_MAX] = {
  "GnuTLS",
  "OpenSSL"
};

#ifdef HAVE_MESSAGES

void
MHD_TLS_LOG_ENGINE (struct MHD_TLS_Engine *engine,
                    const char *format,
                    ...)
{
  va_list args;

  va_start (args,
            format);
  MHD_TLS_log_engine_va (engine,
                         format,
                         args);
  va_end (args);
}

void
MHD_TLS_LOG_CONTEXT (struct MHD_TLS_Context *context,
                     const char *format,
                     ...)
{
  va_list args;

  va_start (args,
            format);
  MHD_TLS_log_engine_va (context->engine,
                         format,
                         args);
  va_end (args);
}

void
MHD_TLS_LOG_SESSION (struct MHD_TLS_Session *session,
                     const char *format,
                     ...)
{
  va_list args;

  va_start (args,
            format);
  MHD_TLS_log_engine_va (session->context->engine,
                         format,
                         args);
  va_end (args);
}

#endif /* HAVE_MESSAGES */

void
MHD_TLS_global_init (void)
{
#ifdef HAVE_GNUTLS
  if (!gnutls_inited)
    {
      MHD_TLS_gnutls_init ();
      gnutls_inited = true;
    }
#endif /* HAVE_GNUTLS */

#ifdef HAVE_OPENSSL
  if (!openssl_inited)
    {
      MHD_TLS_openssl_init ();
      openssl_inited = true;
    }
#endif /* HAVE_OPENSSL */
}

void
MHD_TLS_global_deinit (void)
{
#ifdef HAVE_GNUTLS
  if (gnutls_inited)
    {
      MHD_TLS_gnutls_deinit ();
      gnutls_inited = false;
    }
#endif /* HAVE_GNUTLS */

#ifdef HAVE_OPENSSL
  if (openssl_inited)
    {
      MHD_TLS_openssl_deinit ();
      openssl_inited = false;
    }
#endif /* HAVE_OPENSSL */
}

bool
MHD_TLS_has_engine (enum MHD_TLS_EngineType type)
{
  switch (type)
    {
#ifdef HAVE_GNUTLS
    case MHD_TLS_ENGINE_TYPE_GNUTLS:
      return gnutls_inited;
#endif /* HAVE_GNUTLS */

#ifdef HAVE_OPENSSL
    case MHD_TLS_ENGINE_TYPE_OPENSSL:
      return openssl_inited;
#endif /* HAVE_OPENSSL */
    }

  return false;
}

struct MHD_TLS_Engine *
MHD_TLS_create_engine (void)
{
  struct MHD_TLS_Engine *engine;

  engine = MHD_calloc_ (1, sizeof (struct MHD_TLS_Engine));
  if (NULL == engine)
    return NULL;

  engine->name = "";
  engine->type = MHD_TLS_ENGINE_TYPE_NONE;

  return engine;
}

void
MHD_TLS_set_engine_logging_cb (struct MHD_TLS_Engine *engine,
                               MHD_LogCallback cb,
                               void *data,
                               MHD_TLS_FreeData free_data_cb)
{
  if (NULL == engine)
    return;

  if (NULL != engine->log_data &&
      NULL != engine->free_log_data_cb)
    {
      engine->free_log_data_cb (engine->log_data);
      engine->log_data = NULL;
      engine->free_log_data_cb = NULL;
    }

  if (NULL != cb)
    {
      engine->log_cb = cb;
      engine->log_data = data;
      engine->free_log_data_cb = free_data_cb;
    }
  else
    {
      engine->log_cb = NULL;
      assert (NULL == engine->log_data);
      assert (NULL == engine->free_log_data_cb);
    }
}

void
MHD_TLS_log_engine (struct MHD_TLS_Engine *engine,
                    const char *format,
                    ...)
{
  if (NULL == engine)
    return;

  if (engine->log_cb != NULL)
    {
      va_list args;

      va_start (args, format);
      engine->log_cb (engine->log_data, format, args);
      va_end (args);
    }
}

void
MHD_TLS_log_engine_va (struct MHD_TLS_Engine *engine,
                       const char *format,
                       va_list args)
{
  if (NULL == engine)
    return;

  if (engine->log_cb != NULL)
    {
      engine->log_cb (engine->log_data, format, args);
    }
}

bool
MHD_TLS_setup_engine (struct MHD_TLS_Engine * engine,
                      enum MHD_TLS_EngineType type)
{
  const char *name;

  if (NULL == engine)
    return false;

  if (type > MHD_TLS_ENGINE_TYPE_MAX)
    {
      MHD_TLS_LOG_ENGINE (engine,
                          _("Unknown TLS engine type %d\n"),
                          type);
      return false;
    }

  if (!MHD_TLS_has_engine (type))
    {
      MHD_TLS_LOG_ENGINE (engine,
                          _("TLS engine %s not available\n"),
                          tls_engine_type_strings[type]);
      return false;
    }

  if (MHD_TLS_ENGINE_TYPE_NONE != engine->type)
    {
      MHD_TLS_LOG_ENGINE (engine,
                          _("TLS engine already set up\n"));
      return false;
    }

  switch (type)
    {
    case MHD_TLS_ENGINE_TYPE_GNUTLS:
      engine->init_context = MHD_TLS_gnutls_init_context;
      engine->deinit_context = MHD_TLS_gnutls_deinit_context;
      engine->set_context_certificate_cb = MHD_TLS_gnutls_set_context_certificate_cb;
      engine->set_context_dh_params = MHD_TLS_gnutls_set_context_dh_params;
      engine->set_context_certificate = MHD_TLS_gnutls_set_context_certificate;
      engine->set_context_trust_certificate = MHD_TLS_gnutls_set_context_trust_certificate;
      engine->set_context_client_certificate_mode = MHD_TLS_gnutls_set_context_client_certificate_mode;
      engine->set_context_cipher_priorities = MHD_TLS_gnutls_set_context_cipher_priorities;
      engine->init_session = MHD_TLS_gnutls_init_session;
      engine->deinit_session = MHD_TLS_gnutls_deinit_session;
      engine->session_handshake = MHD_TLS_gnutls_session_handshake;
      engine->session_close = MHD_TLS_gnutls_session_close;
      engine->session_wants_read = MHD_TLS_gnutls_session_wants_read;
      engine->session_wants_write = MHD_TLS_gnutls_session_wants_write;
      engine->session_read_pending = MHD_TLS_gnutls_session_read_pending;
      engine->session_read = MHD_TLS_gnutls_session_read;
      engine->session_write = MHD_TLS_gnutls_session_write;
      break;

    case MHD_TLS_ENGINE_TYPE_OPENSSL:
      engine->init_context = MHD_TLS_openssl_init_context;
      engine->deinit_context = MHD_TLS_openssl_deinit_context;
      engine->set_context_certificate_cb = MHD_TLS_openssl_set_context_certificate_cb;
      engine->set_context_dh_params = MHD_TLS_openssl_set_context_dh_params;
      engine->set_context_certificate = MHD_TLS_openssl_set_context_certificate;
      engine->set_context_trust_certificate = MHD_TLS_openssl_set_context_trust_certificate;
      engine->set_context_client_certificate_mode = MHD_TLS_openssl_set_context_client_certificate_mode;
      engine->set_context_cipher_priorities = MHD_TLS_openssl_set_context_cipher_priorities;
      engine->init_session = MHD_TLS_openssl_init_session;
      engine->deinit_session = MHD_TLS_openssl_deinit_session;
      engine->session_handshake = MHD_TLS_openssl_session_handshake;
      engine->session_close = MHD_TLS_openssl_session_close;
      engine->session_wants_read = MHD_TLS_openssl_session_wants_read;
      engine->session_wants_write = MHD_TLS_openssl_session_wants_write;
      engine->session_read_pending = MHD_TLS_openssl_session_read_pending;
      engine->session_read = MHD_TLS_openssl_session_read;
      engine->session_write = MHD_TLS_openssl_session_write;
      break;

    default:
      assert (false);
      return false;
    }

  engine->name = tls_engine_type_strings[type];
  engine->type = type;

  return true;
}

void
MHD_TLS_del_engine (struct MHD_TLS_Engine *engine)
{
  if (NULL == engine)
    return;

  MHD_TLS_set_engine_logging_cb (engine,
                                 NULL,
                                 NULL,
                                 NULL);
  free (engine);
}

struct MHD_TLS_Context *
MHD_TLS_create_context (struct MHD_TLS_Engine *engine)
{
  struct MHD_TLS_Context *context;

  if (NULL == engine)
    return NULL;

  if (MHD_TLS_ENGINE_TYPE_NONE == engine->type)
    {
      MHD_TLS_LOG_ENGINE (engine,
                          _("TLS engine not set up\n"));
      return NULL;
    }

  context = MHD_calloc_ (1, sizeof (struct MHD_TLS_Context));
  if (NULL == context)
    {
      MHD_TLS_LOG_ENGINE (engine,
                          _("Cannot allocate TLS context\n"));
      return NULL;
    }

  context->engine = engine;

  if (!engine->init_context (context))
    {
      MHD_TLS_LOG_ENGINE (engine,
                          _("Engine %s failed to initialize TLS context\n"),
                          engine->name);
      free (context);
      return NULL;
    }

  return context;
}

void
MHD_TLS_del_context (struct MHD_TLS_Context *context)
{
  if (NULL == context)
    return;

  context->engine->deinit_context (context);
  free (context);
}

bool
MHD_TLS_own_context (struct MHD_TLS_Engine *engine,
                     struct MHD_TLS_Context *context)
{
  if (NULL == engine || NULL == context)
    return false;

  return (context->engine == engine);
}

bool
MHD_TLS_set_context_certificate_cb (struct MHD_TLS_Context *context,
                                    MHD_TLS_GetCertificate cb)
{
  if (NULL == context)
    return false;

  return context->engine->set_context_certificate_cb (context,
                                                      cb);
}

bool
MHD_TLS_set_context_dh_params (struct MHD_TLS_Context *context,
                               const char *params)
{
  if (NULL == context)
    return false;

  if (NULL == params)
    {
      MHD_TLS_LOG_CONTEXT (context,
                           _("Invalid DH parameters\n"));
      return false;
    }

  return context->engine->set_context_dh_params(context,
                                                params);
}

bool
MHD_TLS_set_context_certificate (struct MHD_TLS_Context *context,
                                 const char *certificate,
                                 const char *private_key,
                                 const char *password)
{
  if (NULL == context)
    return false;

  if (NULL == certificate)
    {
      MHD_TLS_LOG_CONTEXT (context,
                           _("Invalid certificate\n"));
      return false;
    }

  if (NULL == private_key)
    {
      MHD_TLS_LOG_CONTEXT (context,
                           _("Invalid private key\n"));
      return false;
    }

  return context->engine->set_context_certificate(context,
                                                  certificate,
                                                  private_key,
                                                  password);
}

bool
MHD_TLS_set_context_trust_certificate (struct MHD_TLS_Context *context,
                                       const char *certificate)
{
  if (NULL == context)
    return false;

  if (NULL == certificate)
    {
      MHD_TLS_LOG_CONTEXT (context,
                           _("Invalid certificate\n"));
      return false;
    }

  return context->engine->set_context_trust_certificate(context,
                                                        certificate);
}

bool
MHD_TLS_set_context_client_certificate_mode (struct MHD_TLS_Context *context,
                                             enum MHD_TLS_ClientCertificateMode mode)
{
  if (NULL == context)
    return false;

  if (mode > MHD_TLS_CLIENT_CERTIFICATE_MODE_MAX)
    {
      MHD_TLS_LOG_CONTEXT (context,
                           _("Invalid client certificate mode %u\n"),
                           mode);
      return false;
    }

  return context->engine->set_context_client_certificate_mode (context,
                                                               mode);
}

bool
MHD_TLS_set_context_cipher_priorities (struct MHD_TLS_Context *context,
                                       const char *priorities)
{
  if (NULL == context)
    return false;

  if (NULL == priorities)
    {
      MHD_TLS_LOG_CONTEXT (context,
                           _("Invalid priorities\n"));
      return false;
    }

  return context->engine->set_context_cipher_priorities(context,
                                                        priorities);
}

struct MHD_TLS_Session *
MHD_TLS_create_session (struct MHD_TLS_Context * context)
{
  struct MHD_TLS_Session *session;

  if (NULL == context)
    return NULL;

  session = MHD_calloc_ (1, sizeof (struct MHD_TLS_Session));
  if (NULL == session)
    {
      MHD_TLS_LOG_CONTEXT (context,
                           _("Cannot allocate TLS session\n"));
      return NULL;
    }

  session->context = context;

  if (!context->engine->init_session (session))
    {
      MHD_TLS_LOG_CONTEXT (context,
                           _("Engine %s failed to initialize TLS session\n"),
                           context->engine->name);
      free (session);
      return NULL;
    }

  return session;
}

void
MHD_TLS_del_session (struct MHD_TLS_Session *session)
{
  if (NULL == session)
    return;

  session->context->engine->deinit_session (session);
  free (session);
}

bool
MHD_TLS_own_session (struct MHD_TLS_Context *context,
                     struct MHD_TLS_Session *session)
{
  if (NULL == context || NULL == session)
    return false;

  return (session->context == context);
}

ssize_t
MHD_TLS_session_handshake (struct MHD_TLS_Session * session)
{
  if (NULL == session)
    return MHD_TLS_IO_INVALID_PARAMS;

  return session->context->engine->session_handshake (session);
}

ssize_t
MHD_TLS_session_close (struct MHD_TLS_Session * session)
{
  if (NULL == session)
    return MHD_TLS_IO_INVALID_PARAMS;

  return session->context->engine->session_close (session);
}


bool
MHD_TLS_session_wants_read (struct MHD_TLS_Session *session)
{
  if (NULL == session)
    return false;

  return session->context->engine->session_wants_read (session);
}

bool
MHD_TLS_session_wants_write (struct MHD_TLS_Session *session)
{
  if (NULL == session)
    return false;

  return session->context->engine->session_wants_write (session);
}

size_t
MHD_TLS_session_read_pending (struct MHD_TLS_Session *session)
{
  if (NULL == session)
    return 0;

  return session->context->engine->session_read_pending (session);
}

ssize_t
MHD_TLS_session_read (struct MHD_TLS_Session * session,
                      void *buf,
                      size_t size)
{
  if (NULL == session)
    return MHD_TLS_IO_INVALID_PARAMS;
  if (0 == size)
    return 0;
  if (NULL == buf)
    return MHD_TLS_IO_INVALID_PARAMS;

  if (size > SSIZE_MAX)
    size = SSIZE_MAX;

  return session->context->engine->session_read (session,
                                                 buf,
                                                 size);
}

ssize_t
MHD_TLS_session_write (struct MHD_TLS_Session * session,
                       const void *buf,
                       size_t size)
{
  if (NULL == session)
    return MHD_TLS_IO_INVALID_PARAMS;
  if (0 == size)
    return 0;
  if (NULL == buf)
    return MHD_TLS_IO_INVALID_PARAMS;

  if (size > SSIZE_MAX)
    size = SSIZE_MAX;

  return session->context->engine->session_write (session,
                                                  buf,
                                                  size);
}
