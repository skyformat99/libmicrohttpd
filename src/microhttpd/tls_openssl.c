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
 * @file tls_openssl.c
 * @brief OpenSSL-based TLS engine
 */

/* must come first */
#include "mhd_options.h"

#include <openssl/err.h>

#include "internal.h"
#include "tls.h"

#if defined(MHD_USE_POSIX_THREADS)

static pthread_mutex_t *locks;

static void
pthreads_locking_callback (int mode,
                           int type,
                           const char *file,
                           int line)
{
  if (mode & CRYPTO_LOCK)
    pthread_mutex_lock (&locks[type]);
  else
    pthread_mutex_unlock (&locks[type]);
}

static unsigned long
pthreads_thread_id (void)
{
  return (unsigned long)pthread_self ();
}

static void
threads_init (void)
{
  size_t i;

  locks = OPENSSL_malloc (CRYPTO_num_locks () * sizeof (pthread_mutex_t));
  if (NULL == locks)
    MHD_PANIC (_("Cannot allocate locks for OpenSSL\n"));

  for (i = 0; i < CRYPTO_num_locks (); i++)
    pthread_mutex_init (&locks[i], NULL);

  CRYPTO_set_id_callback (pthreads_thread_id);
  CRYPTO_set_locking_callback (pthreads_locking_callback);
}

static void
threads_deinit (void)
{
  size_t i;

  CRYPTO_set_locking_callback (NULL);
  CRYPTO_set_id_callback (NULL);
  for (i = 0; i < CRYPTO_num_locks (); i++)
    pthread_mutex_destroy (&locks[i]);
  OPENSSL_free (locks);
}

#elif defined(MHD_W32_MUTEX_)

static HANDLE *locks;

void
win32_locking_callback (int mode,
                        int type,
                        const char *file,
                        int line)
{
  if (mode & CRYPTO_LOCK)
    WaitForSingleObject (locks[type], INFINITE);
  else
    ReleaseMutex (locks[type]);
}

static unsigned long
win32_thread_id (void)
{
  return (unsigned long) GetCurrentThreadId ();
}

static void
threads_init (void)
{
  size_t i;

  locks = OPENSSL_malloc (CRYPTO_num_locks () * sizeof (HANDLE));
  if (NULL == locks)
    MHD_PANIC (_("Cannot allocate locks for OpenSSL\n"));

  for (i = 0; i < CRYPTO_num_locks (); i++)
    locks[i] = CreateMutex (NULL, FALSE, NULL);

  CRYPTO_set_id_callback (win32_thread_id);
  CRYPTO_set_locking_callback (win32_locking_callback);
}

static void
threads_deinit (void)
{
  size_t i;

  CRYPTO_set_locking_callback (NULL);
  CRYPTO_set_id_callback (NULL);
  for (i = 0; i < CRYPTO_num_locks (); i++)
    CloseHandle (locks[i]);
  OPENSSL_free (locks);
}

#endif

void
MHD_TLS_openssl_init (void)
{
  SSL_library_init ();
  SSL_load_error_strings (),
  threads_init ();
}

void
MHD_TLS_openssl_deinit (void)
{
  threads_deinit ();
  ERR_free_strings ();
  EVP_cleanup ();
}

bool
MHD_TLS_openssl_init_context (struct MHD_TLS_Context *context)
{
  context->d.openssl.context = SSL_CTX_new (SSLv23_server_method ());
  if (NULL == context->d.openssl.context)
    {
      MHD_TLS_LOG_CONTEXT (context, "Cannot allocate SSL context\n");
      return false;
    }

  return true;
}

void
MHD_TLS_openssl_deinit_context (struct MHD_TLS_Context * context)
{
  SSL_CTX_free (context->d.openssl.context);
}

bool
MHD_TLS_openssl_set_context_certificate_cb (struct MHD_TLS_Context *context,
                                            MHD_TLS_GetCertificate cb)
{
  SSL_CTX_set_cert_cb (context->d.openssl.context,
                       (int (*)(SSL *, void *))cb,
                       NULL);
  return true;
}

bool
MHD_TLS_openssl_set_context_dh_params (struct MHD_TLS_Context *context,
                                       const char *params)
{
  DH *dh = NULL;
  BIO *bio;

  bio = BIO_new_mem_buf (params, -1);
  if (NULL != bio)
    {
      dh = PEM_read_bio_DHparams (bio,
          NULL,
          0,
          NULL);
      BIO_free_all (bio);
    }
  if (NULL == dh)
    {
      MHD_TLS_LOG_CONTEXT (context,
                           _("Bad Diffie-Hellman parameters format\n"));
      return false;
    }
  if (!SSL_CTX_set_tmp_dh (context->d.openssl.context,
                           dh))
  {
    MHD_TLS_LOG_CONTEXT (context,
                         _("Cannot set Diffie-Hellman parameters\n"));
    DH_free (dh);
    return false;
  }
  DH_free (dh);

  return true;
}

bool
MHD_TLS_openssl_set_context_certificate (struct MHD_TLS_Context *context,
                                         const char *certificate,
                                         const char *private_key,
                                         const char *password)
{
  X509 *cert = NULL;
  EVP_PKEY *key = NULL;
  BIO *bio;

  bio = BIO_new_mem_buf (certificate, -1);
  if (NULL != bio)
    {
      cert = PEM_read_bio_X509 (bio,
                                NULL,
                                0,
                                NULL);
      BIO_free_all (bio);
    }
  if (NULL == cert)
    {
	    MHD_TLS_LOG_CONTEXT (context,
                           _("Bad server certificate format\n"));
      return false;
    }

  if (!SSL_CTX_use_certificate (context->d.openssl.context,
                                cert))
    {
	    MHD_TLS_LOG_CONTEXT (context,
                           _("Cannot set server certificate\n"));
      X509_free (cert);
      return false;
	}
  X509_free (cert);

  bio = BIO_new_mem_buf (private_key, -1);
  if (NULL != bio)
    {
      key = PEM_read_bio_PrivateKey (bio,
                                     NULL,
                                     NULL,
                                     (void *)password);
      BIO_free_all (bio);
    }
  if (NULL == key)
    {
	    MHD_TLS_LOG_CONTEXT (context,
                           _("Bad server key format or invalid password\n"));
      return false;
    }
  if (!SSL_CTX_use_PrivateKey (context->d.openssl.context,
                               key))
    {
      MHD_TLS_LOG_CONTEXT (context,
                           _("Cannot set server private key\n"));
      EVP_PKEY_free (key);
      return false;
    }
  EVP_PKEY_free (key);

  return true;
}

bool
MHD_TLS_openssl_set_context_trust_certificate (struct MHD_TLS_Context *context,
                                               const char *certificate)
{
  X509 *cert = NULL;
  BIO *bio;

  bio = BIO_new_mem_buf (certificate, -1);
  if (NULL != bio)
    {
      cert = PEM_read_bio_X509 (bio,
                                NULL,
                                0,
                                NULL);
      BIO_free_all (bio);
    }
  if (NULL == cert)
    {
      MHD_TLS_LOG_CONTEXT (context,
                           _("Bad trust certificate format\n"));
      return false;
    }

  if (!SSL_CTX_add_extra_chain_cert (context->d.openssl.context,
                                     cert))
    {
      MHD_TLS_LOG_CONTEXT (context,
                           _("Cannot set trust certificate\n"));
      X509_free (cert);
      return false;
    }
  X509_free (cert);

  return true;
}

bool
MHD_TLS_openssl_set_context_client_certificate_mode (struct MHD_TLS_Context *context,
                                                     enum MHD_TLS_ClientCertificateMode mode)
{
  int openssl_mode;

  switch (mode)
    {
    case MHD_TLS_CLIENT_CERTIFICATE_MODE_DISABLE:
      openssl_mode = SSL_VERIFY_NONE;
      break;
    case MHD_TLS_CLIENT_CERTIFICATE_MODE_REQUEST:
      openssl_mode = SSL_VERIFY_PEER;
      break;
    case MHD_TLS_CLIENT_CERTIFICATE_MODE_REQUIRE:
      openssl_mode = SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
      break;
    default:
      MHD_TLS_LOG_CONTEXT (context,
                           _("Unsupported client certificate mode %d\n"),
                           mode);
      return false;
    }

  SSL_CTX_set_verify (context->d.openssl.context,
                      openssl_mode,
                      NULL);

  return true;
}

bool
MHD_TLS_openssl_set_context_cipher_priorities (struct MHD_TLS_Context *context,
                                               const char *priorities)
{
  if (0 != SSL_CTX_set_cipher_list (context->d.openssl.context,
                                    priorities))
    {
      MHD_TLS_LOG_CONTEXT (context,
			                     _("Setting priorities to `%s' failed\n"),
                           priorities);
      return false;
    }

  return true;
}

bool
MHD_TLS_openssl_init_session (struct MHD_TLS_Session * session)
{
  session->d.openssl.session = SSL_new (session->context->d.openssl.context);
  if (NULL == session ->d.openssl.session)
    {
      MHD_TLS_LOG_SESSION(session, "Cannot allocate SSL session\n");
      return false;
    }

  return true;
}

void
MHD_TLS_openssl_deinit_session (struct MHD_TLS_Session * session)
{
  SSL_free (session->d.openssl.session);
}

ssize_t
MHD_TLS_openssl_session_handshake (struct MHD_TLS_Session * session)
{
  int result;

  result = SSL_accept (session->d.openssl.session);
  if (result == 1)
    return 0;

  switch (SSL_get_error (session->d.openssl.session, result))
    {
    case SSL_ERROR_WANT_READ:
      return MHD_TLS_IO_WANTS_READ;
    case SSL_ERROR_WANT_WRITE:
      return MHD_TLS_IO_WANTS_WRITE;
    default:
      MHD_TLS_LOG_SESSION (session,
                           _("Session handskake failed"));
      return MHD_TLS_IO_UNKNOWN_ERROR;
    }
}

ssize_t
MHD_TLS_openssl_session_close (struct MHD_TLS_Session * session)
{
  int result;

  result = SSL_shutdown (session->d.openssl.session);
  if (result == 1)
    return 0;

  switch (SSL_get_error (session->d.openssl.session, result))
    {
    case SSL_ERROR_WANT_READ:
      return MHD_TLS_IO_WANTS_READ;
    case SSL_ERROR_WANT_WRITE:
      return MHD_TLS_IO_WANTS_WRITE;
    default:
      MHD_TLS_LOG_SESSION (session,
                           _("Session close failed"));
      return MHD_TLS_IO_UNKNOWN_ERROR;
    }
}

bool
MHD_TLS_openssl_session_wants_read (struct MHD_TLS_Session *session)
{
  return SSL_want_read (session->d.openssl.session);
}

bool
MHD_TLS_openssl_session_wants_write (struct MHD_TLS_Session *session)
{
  return SSL_want_write (session->d.openssl.session);
}

size_t
MHD_TLS_openssl_session_read_pending (struct MHD_TLS_Session *session)
{
  return (size_t)SSL_pending (session->d.openssl.session);
}

ssize_t
MHD_TLS_openssl_session_read (struct MHD_TLS_Session * session,
                              void *buf,
                              size_t size)
{
  ssize_t result;

  if (size > INT_MAX)
    size = INT_MAX;

  result = SSL_read (session->d.openssl.session,
                     buf,
                     (int)size);
  if (result > 0)
    return result;

  switch (SSL_get_error (session->d.openssl.session, result))
    {
    case SSL_ERROR_WANT_READ:
      return MHD_TLS_IO_WANTS_READ;

    case SSL_ERROR_WANT_WRITE:
      return MHD_TLS_IO_WANTS_WRITE;

    case SSL_ERROR_ZERO_RETURN:
      return MHD_TLS_IO_SESSION_CLOSED;

    default:
      return MHD_TLS_IO_UNKNOWN_ERROR;
    }
}

ssize_t
MHD_TLS_openssl_session_write (struct MHD_TLS_Session * session,
                               const void *buf,
                               size_t size)
{
  ssize_t result;

  if (size > INT_MAX)
    size = INT_MAX;

  result = SSL_write (session->d.openssl.session,
                      buf,
                      (int)size);
  if (result > 0)
    return result;

  switch (SSL_get_error (session->d.openssl.session, result))
    {
    case SSL_ERROR_WANT_READ:
      return MHD_TLS_IO_WANTS_READ;

    case SSL_ERROR_WANT_WRITE:
      return MHD_TLS_IO_WANTS_WRITE;

    case SSL_ERROR_ZERO_RETURN:
      return MHD_TLS_IO_SESSION_CLOSED;

    default:
      return MHD_TLS_IO_UNKNOWN_ERROR;
    }
}
