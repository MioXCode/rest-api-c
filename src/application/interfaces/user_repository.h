#ifndef USER_REPOSITORY_H
#define USER_REPOSITORY_H

#include "../../domain/entities/user.h"

typedef struct
{
    User *(*find_by_id)(const char *id);
    User *(*find_by_username)(const char *username);
    int (*save)(User *user);
    int (*update)(User *user);
    int (*remove)(const char *id);
} UserRepository;

#endif