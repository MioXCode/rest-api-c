#ifndef SERVER_H
#define SERVER_H

#include <microhttpd.h>

typedef struct
{
    unsigned int port;
    const char *host;
} ServerConfig;

int init_server(void);
void start_server(void);
void stop_server(void);

#endif