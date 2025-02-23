#ifndef JWT_H
#define JWT_H

#include <time.h>

typedef struct {
    char *token;
    time_t exp;
} JWT;

JWT* create_jwt(const char *user_id, const char *secret_key);
int verify_jwt(const char *token, const char *secret_key);
void free_jwt(JWT *jwt);

#endif 