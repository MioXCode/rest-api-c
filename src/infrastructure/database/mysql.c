#include "mysql.h"
#include <stdio.h>
#include <stdlib.h>

static MYSQL *global_conn = NULL;

MYSQL* db_connect(DatabaseConfig config) {
    MYSQL *conn = mysql_init(NULL);
    
    if (conn == NULL) {
        fprintf(stderr, "mysql_init() failed\n");
        return NULL;
    }
    
    // Set additional options if needed
    unsigned int timeout = 10;
    mysql_options(conn, MYSQL_OPT_CONNECT_TIMEOUT, &timeout);
    
    // Enable auto-reconnect
    my_bool reconnect = 1;
    mysql_options(conn, MYSQL_OPT_RECONNECT, &reconnect);
    
    if (mysql_real_connect(conn, 
                          config.host, 
                          config.user, 
                          config.password, 
                          config.database, 
                          config.port, 
                          config.unix_socket, 
                          config.flags) == NULL) {
        fprintf(stderr, "Connection error: %s\n", mysql_error(conn));
        mysql_close(conn);
        return NULL;
    }
    
    // Set UTF8 character set
    if (mysql_set_character_set(conn, "utf8mb4")) {
        fprintf(stderr, "Failed to set character set: %s\n", mysql_error(conn));
        mysql_close(conn);
        return NULL;
    }
    
    return conn;
}

void init_db_connection(DatabaseConfig config) {
    if (global_conn != NULL) {
        db_disconnect(global_conn);
    }
    global_conn = db_connect(config);
}

MYSQL* get_db_connection(void) {
    return global_conn;
}

void db_disconnect(MYSQL *conn) {
    if (conn != NULL) {
        mysql_close(conn);
    }
}

int db_execute_query(MYSQL *conn, const char *query) {
    if (mysql_query(conn, query)) {
        fprintf(stderr, "Query error: %s\n", mysql_error(conn));
        return 0;
    }
    return 1;
}

MYSQL_RES* db_fetch_query(MYSQL *conn, const char *query) {
    if (mysql_query(conn, query)) {
        fprintf(stderr, "Query error: %s\n", mysql_error(conn));
        return NULL;
    }
    return mysql_store_result(conn);
}

int db_begin_transaction(MYSQL *conn) {
    return db_execute_query(conn, "START TRANSACTION");
}

int db_commit(MYSQL *conn) {
    return db_execute_query(conn, "COMMIT");
}

int db_rollback(MYSQL *conn) {
    return db_execute_query(conn, "ROLLBACK");
}

const char* db_get_error(MYSQL *conn) {
    return mysql_error(conn);
} 