#ifndef AUTH_HANDLER_H
#define AUTH_HANDLER_H

#include <microhttpd.h>
#include "../../infrastructure/auth/jwt.h"

enum MHD_Result handle_login(struct MHD_Connection *connection,
                             const char *username,
                             const char *password);

enum MHD_Result handle_register(struct MHD_Connection *connection,
                                const char *username,
                                const char *password,
                                const char *email);

int verify_auth_token(struct MHD_Connection *connection);

#endif