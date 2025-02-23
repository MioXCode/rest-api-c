#ifndef MYSQL_H
#define MYSQL_H

#include <mariadb/mysql.h>
#include <time.h>

typedef struct {
    MYSQL *conn;
    const char *host;
    const char *user;
    const char *password;
    const char *database;
    int port;
    const char *unix_socket;  // untuk Unix socket connection
    unsigned long flags;      // connection flags
} DatabaseConfig;

// Database connection functions
MYSQL* db_connect(DatabaseConfig config);
void db_disconnect(MYSQL *conn);
int db_execute_query(MYSQL *conn, const char *query);
MYSQL_RES* db_fetch_query(MYSQL *conn, const char *query);

// Global connection access
MYSQL* get_db_connection(void);
void init_db_connection(DatabaseConfig config);

// Transaction handling
int db_begin_transaction(MYSQL *conn);
int db_commit(MYSQL *conn);
int db_rollback(MYSQL *conn);

// Error handling
const char* db_get_error(MYSQL *conn);

#endif 