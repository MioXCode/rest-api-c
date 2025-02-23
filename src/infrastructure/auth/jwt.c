#include "jwt.h"
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define JWT_EXPIRES_IN 3600
#define BASE64_SIZE(x) (((x + 2) / 3) * 4 + 1)

static char *base64_encode(const unsigned char *input, int length)
{
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;
    char *result;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_write(bio, input, length);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);

    result = (char *)malloc(bufferPtr->length);
    memcpy(result, bufferPtr->data, bufferPtr->length - 1);
    result[bufferPtr->length - 1] = 0;

    BIO_free_all(bio);
    return result;
}

JWT *create_jwt(const char *user_id, const char *secret_key)
{
    JWT *jwt = malloc(sizeof(JWT));
    if (!jwt)
        return NULL;

    time_t now = time(NULL);
    jwt->exp = now + JWT_EXPIRES_IN;

    const char *header = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
    char *base64_header = base64_encode((unsigned char *)header, strlen(header));

    char payload[256];
    snprintf(payload, sizeof(payload),
             "{\"user_id\":\"%s\",\"exp\":%ld}",
             user_id, jwt->exp);
    char *base64_payload = base64_encode((unsigned char *)payload, strlen(payload));

    char signature_input[512];
    snprintf(signature_input, sizeof(signature_input),
             "%s.%s", base64_header, base64_payload);

    unsigned char *signature = malloc(EVP_MAX_MD_SIZE);
    unsigned int signature_len;

    HMAC(EVP_sha256(), secret_key, strlen(secret_key),
         (unsigned char *)signature_input, strlen(signature_input),
         signature, &signature_len);

    char *base64_signature = base64_encode(signature, signature_len);

    jwt->token = malloc(strlen(base64_header) + strlen(base64_payload) +
                        strlen(base64_signature) + 3);
    sprintf(jwt->token, "%s.%s.%s",
            base64_header, base64_payload, base64_signature);

    free(base64_header);
    free(base64_payload);
    free(base64_signature);
    free(signature);

    return jwt;
}

int verify_jwt(const char *token, const char *secret_key)
{
    if (!token || !secret_key)
        return 0;

    char *token_copy = strdup(token);
    char *header = strtok(token_copy, ".");
    char *payload = strtok(NULL, ".");
    char *signature = strtok(NULL, ".");

    if (!header || !payload || !signature)
    {
        free(token_copy);
        return 0;
    }

    char signature_input[512];
    snprintf(signature_input, sizeof(signature_input), "%s.%s", header, payload);

    unsigned char *computed_signature = malloc(EVP_MAX_MD_SIZE);
    unsigned int signature_len;

    HMAC(EVP_sha256(), secret_key, strlen(secret_key),
         (unsigned char *)signature_input, strlen(signature_input),
         computed_signature, &signature_len);

    char *base64_computed = base64_encode(computed_signature, signature_len);

    int result = (strcmp(base64_computed, signature) == 0);

    free(token_copy);
    free(computed_signature);
    free(base64_computed);

    return result;
}

void free_jwt(JWT *jwt)
{
    if (jwt)
    {
        if (jwt->token)
            free(jwt->token);
        free(jwt);
    }
}