/*
 * Written by Christian Heimes for the OpenSSL project.
 */
/* ====================================================================
 * Copyright (c) 1998-2016 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#include <stdio.h>
#include <openssl/crypto.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#define ROOT_CA "certs/trust-root.pem"
#define ROOT_CA_TRUST_CLIENT "certs/trust-root.trustclientauth.pem"
#define ROOT_CA_TRUST_SERVER "certs/trust-root.trustserverauth.pem"
#define ROOT_CA_TRUST_EMAIL "certs/trust-root.trustemailprotection.pem"
#define ROOT_CA_REJECT_SERVER "certs/trust-root.rejectserverauth.pem"
#define ROOT_CA_CONFLICT_SERVER "certs/trust-root.conflictserverauth.pem"

#define INTERMEDIATE_CA "certs/trust-intermediate.pem"

#define CLIENT_CERT "certs/trust-client.pem"
#define SERVER_CERT "certs/trust-server.pem"
#define EMAIL_CERT "certs/trust-smime.pem"

typedef struct {
    const char *ca_file;
    const char *leaf_file;
    int purpose;
    int trust;
    int ok;
    int verify_result;
    int error_depth;
} trust_test_case;

trust_test_case trust_tests[] = {
#define NO_ERROR 0
#define LEAF_ERROR 0
#define INTERMEDIATE_ERROR 1
#define ROOT_ERROR 2
#define ERR_CERT_UNTRUSTED X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT
    /* TLS server cert, signed by intermediate CA */
    {ROOT_CA, SERVER_CERT,
     X509_PURPOSE_SSL_SERVER, X509_TRUST_SSL_SERVER,
     1, X509_V_OK, NO_ERROR},
    {ROOT_CA, SERVER_CERT,
     X509_PURPOSE_SSL_CLIENT, X509_TRUST_SSL_SERVER,
     0, X509_V_ERR_INVALID_PURPOSE, LEAF_ERROR},
    {ROOT_CA_REJECT_SERVER, SERVER_CERT,
     X509_PURPOSE_SSL_SERVER, X509_TRUST_SSL_SERVER,
     0, X509_V_ERR_CERT_REJECTED, ROOT_ERROR},
    {ROOT_CA_TRUST_SERVER, SERVER_CERT,
     X509_PURPOSE_SSL_SERVER, X509_TRUST_SSL_SERVER,
     1, X509_V_OK, NO_ERROR},
    {ROOT_CA_CONFLICT_SERVER, SERVER_CERT,
     X509_PURPOSE_SSL_SERVER, X509_TRUST_SSL_SERVER,
     0, X509_V_ERR_CERT_REJECTED, ROOT_ERROR},
    {ROOT_CA_TRUST_CLIENT, SERVER_CERT,
     X509_PURPOSE_SSL_SERVER, X509_TRUST_SSL_SERVER,
     0, ERR_CERT_UNTRUSTED, ROOT_ERROR},

    /* TLS client cert, signed by intermediate CA */
    {ROOT_CA, CLIENT_CERT,
     X509_PURPOSE_SSL_CLIENT, X509_TRUST_SSL_CLIENT,
     1, X509_V_OK, NO_ERROR},
    {ROOT_CA, CLIENT_CERT,
     X509_PURPOSE_SSL_SERVER, X509_TRUST_SSL_CLIENT,
     0, X509_V_ERR_INVALID_PURPOSE, LEAF_ERROR},
    {ROOT_CA_TRUST_SERVER, CLIENT_CERT,
     X509_PURPOSE_SSL_CLIENT, X509_TRUST_SSL_CLIENT,
     0, ERR_CERT_UNTRUSTED, ROOT_ERROR},
    {ROOT_CA_TRUST_CLIENT, CLIENT_CERT,
     X509_PURPOSE_SSL_CLIENT, X509_TRUST_SSL_CLIENT,
     1, X509_V_OK, NO_ERROR},

    /* S/MIME cert, signed by intermediate CA */
    {ROOT_CA, EMAIL_CERT,
     X509_PURPOSE_SMIME_SIGN, X509_TRUST_EMAIL,
     0, X509_V_ERR_INVALID_PURPOSE, INTERMEDIATE_ERROR},
    {ROOT_CA, EMAIL_CERT,
     X509_PURPOSE_SMIME_ENCRYPT, X509_TRUST_EMAIL,
     0, X509_V_ERR_INVALID_PURPOSE, INTERMEDIATE_ERROR},
    {ROOT_CA, CLIENT_CERT,
     X509_PURPOSE_SMIME_SIGN, X509_TRUST_EMAIL,
     0, X509_V_ERR_INVALID_PURPOSE, LEAF_ERROR},
    {ROOT_CA, CLIENT_CERT,
     X509_PURPOSE_SMIME_ENCRYPT, X509_TRUST_EMAIL,
     0, X509_V_ERR_INVALID_PURPOSE, LEAF_ERROR},
    {ROOT_CA_TRUST_EMAIL, EMAIL_CERT,
     X509_PURPOSE_SMIME_ENCRYPT, X509_TRUST_EMAIL,
     0, X509_V_ERR_INVALID_PURPOSE, INTERMEDIATE_ERROR},
};

#define trust_tests_count (sizeof(trust_tests)/sizeof(trust_test_case))

static int test_verify_trust_case(int idx)
{
    int i;
    int ret = -1;
    int vflags = X509_V_FLAG_X509_STRICT;
    X509_STORE *store = NULL;
    X509_LOOKUP *lookup = NULL;
    X509_VERIFY_PARAM *vp = NULL;
    BIO *bio = NULL;
    STACK_OF(X509) *chain = NULL;
    X509 *leaf = NULL;
    X509 *cert = NULL;
    X509_STORE_CTX *sctx = NULL;
    trust_test_case *testcase = trust_tests + idx;

    /* store */
    store = X509_STORE_new();
    if (store == NULL)
        goto err;

    /* load root */
    lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
    if (lookup == NULL)
        goto err;
    if (!X509_LOOKUP_load_file(lookup, testcase->ca_file, X509_FILETYPE_PEM))
        goto err;

    /* set verify params */
    vp = X509_VERIFY_PARAM_new();
    if (vp == NULL)
        goto err;

    X509_VERIFY_PARAM_set_purpose(vp, testcase->purpose);
    X509_VERIFY_PARAM_set_trust(vp, testcase->trust);
    X509_STORE_set1_param(store, vp);
    X509_STORE_set_flags(store, vflags);

    /* untrusted intermediate CA certs */
    bio = BIO_new_file(INTERMEDIATE_CA, "r");
    if (bio == NULL)
        goto err;

    chain = sk_X509_new_null();
    if (chain == NULL)
        goto err;
    /* read one cert */
    cert = PEM_read_bio_X509(bio, NULL, 0, NULL);
    if (cert == NULL)
        goto err;
    if (!sk_X509_push(chain, cert)) {
        X509_free(cert);
        cert = NULL;
        goto err;
    }
    BIO_free(bio);

    /* load leaf cert */
    bio = BIO_new_file(testcase->leaf_file, "r");
    if (bio == NULL)
        goto err;

    leaf = PEM_read_bio_X509(bio, NULL, 0, NULL);
    if (leaf == NULL)
        goto err;

    /* verify context */
    sctx = X509_STORE_CTX_new();
    if (sctx == NULL)
        goto err;

    if (!X509_STORE_CTX_init(sctx, store, leaf, chain))
        goto err;

    i = X509_verify_cert(sctx);

    if ((i == testcase->ok)
        && (X509_STORE_CTX_get_error(sctx) == testcase->verify_result)
        && (X509_STORE_CTX_get_error_depth(sctx) == testcase->error_depth)
        ) {
        ret = 1;
    } else {
        fprintf(stderr, "Test verify trust case %i failed:\n", idx + 1);
        fprintf(stderr, "  root CA file: '%s'\n", testcase->ca_file);
        fprintf(stderr, "  cert file: '%s'\n", testcase->leaf_file);
        fprintf(stderr, "  purpose: '%i' trust: '%i'\n",
                testcase->purpose, testcase->trust);
        fprintf(stderr, "  X509_verify_cert(): %i (expected %i)\n",
                i, testcase->ok);
        fprintf(stderr, "  verify error: %i (expected %i)\n",
                X509_STORE_CTX_get_error(sctx), testcase->verify_result);
        fprintf(stderr, "  error depth: %i (expected %i)\n",
                X509_STORE_CTX_get_error_depth(sctx), testcase->error_depth);
        ERR_print_errors_fp(stderr);
        ret = 0;
    }

 err:
    if (ret != 1)
        ERR_print_errors_fp(stderr);
    if (store)
        X509_STORE_free(store);
    if (vp)
        X509_VERIFY_PARAM_free(vp);
    if (bio)
        BIO_free(bio);
    if (chain)
        sk_X509_pop_free(chain, X509_free);
    if (leaf)
        X509_free(leaf);
    if (sctx)
        X509_STORE_CTX_free(sctx);
    return ret;
}

static int test_verify_trust(void)
{
    int idx;
    int success = 0;
    int failed = 0;

    for (idx = 0; idx < trust_tests_count; idx++) {
        if (test_verify_trust_case(idx) == 1) {
            success++;
        } else {
            failed++;
        }
    }
    fprintf(stdout, "%i of %lu tests passed\n", success, trust_tests_count);
    if (failed)
        fprintf(stdout, "%i of %lu tests failed\n", failed, trust_tests_count);

    return (failed == 0);
}

int main(void)
{
    CRYPTO_malloc_debug_init();
    CRYPTO_set_mem_debug_options(V_CRYPTO_MDEBUG_ALL);
    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);

    ERR_load_crypto_strings();
    OpenSSL_add_all_digests();

    if (!test_verify_trust()) {
        fprintf(stderr, "Test verify trust failed\n");
        return 1;
    }

    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_remove_thread_state(NULL);
    ERR_free_strings();
    CRYPTO_mem_leaks_fp(stderr);

    printf("PASS\n");
    return 0;
}
