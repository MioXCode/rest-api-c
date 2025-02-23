#ifndef SERVER_H
#define SERVER_H

#include <microhttpd.h>

// Server configuration
typedef struct {
    unsigned int port;
    const char* host;
} ServerConfig;

// Server functions
int init_server(void);
void start_server(void);
void stop_server(void);

#endif 