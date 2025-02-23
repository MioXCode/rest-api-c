#ifndef USER_SERVICE_H
#define USER_SERVICE_H

#include "../../domain/entities/user.h"
#include "../interfaces/user_repository.h"

typedef struct {
    UserRepository *repository;
} UserService;

UserService* create_user_service(UserRepository *repository);
User* authenticate_user(UserService *service, const char *username, const char *password);
User* register_user(UserService *service, const char *username, const char *password, const char *email);
void free_user_service(UserService *service);

#endif 