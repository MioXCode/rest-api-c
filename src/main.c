#include "infrastructure/database/mysql.h"
#include "infrastructure/auth/jwt.h"
#include "interfaces/http/server.h"
#include <stdio.h>

int main() {
    // Initialize database connection
    DatabaseConfig config = {
        .host = "localhost",
        .user = "root",
        .password = "root",
        .database = "rest_api",
        .port = 3306,
        .unix_socket = NULL,
        .flags = 0
    };
    
    init_db_connection(config);
    MYSQL *conn = get_db_connection();
    if (!conn) {
        fprintf(stderr, "Failed to connect to database\n");
        return 1;
    }
    
    // Initialize server
    if (!init_server()) {
        db_disconnect(conn);
        return 1;
    }
    
    // Start server
    start_server();
    
    // Cleanup
    db_disconnect(conn);
    return 0;
}
