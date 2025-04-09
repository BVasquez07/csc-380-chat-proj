#include "auth.h"
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int sign_data(const char* priv_key_path, const unsigned char* data, size_t data_len, unsigned char** sig_out, size_t* sig_len) {
    FILE* fp = fopen(priv_key_path, "r");
    if (!fp) return -1;

    EVP_PKEY* pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!pkey) return -2;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        EVP_PKEY_free(pkey);
        return -3;
    }

    if (EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, pkey) <= 0) goto err;
    if (EVP_DigestSignUpdate(ctx, data, data_len) <= 0) goto err;

    size_t required = 0;
    if (EVP_DigestSignFinal(ctx, NULL, &required) <= 0) goto err;

    *sig_out = malloc(required);
    *sig_len = required;
    if (EVP_DigestSignFinal(ctx, *sig_out, sig_len) <= 0) goto err;

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return 0;

err:
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return -4;
}

int verify_signature(const char* pub_key_path, const unsigned char* data, size_t data_len, const unsigned char* sig, size_t sig_len) {
    char cwd[PATH_MAX];
    getcwd(cwd, sizeof(cwd));
    fprintf(stderr, "[DEBUG] CWD: %s\n", cwd);
    fprintf(stderr, "[DEBUG] Looking for: %s\n", pub_key_path);
    
    FILE* fp = fopen(pub_key_path, "r");
    if (!fp) return -1;

    EVP_PKEY* pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!pkey) return -2;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        EVP_PKEY_free(pkey);
        return -3;
    }

    int result = -4;
    if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pkey) > 0 &&
        EVP_DigestVerifyUpdate(ctx, data, data_len) > 0) {
        result = EVP_DigestVerifyFinal(ctx, sig, sig_len);
    }

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    return result; // 1 = success, 0 = fail, <0 = error
}