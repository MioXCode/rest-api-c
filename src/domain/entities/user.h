#ifndef USER_H
#define USER_H

#include <time.h>

typedef struct
{
    char id[37];
    char username[50];
    char password_hash[65];
    char email[100];
    time_t created_at;
} User;

#endif