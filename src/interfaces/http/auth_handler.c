#include "auth_handler.h"
#include "../../infrastructure/database/mysql.h"
#include <string.h>
#include <stdio.h>
#include <jansson.h>

#define SECRET_KEY "your-secret-key-here"

static struct MHD_Response *create_json_response(const char *json_str)
{
    return MHD_create_response_from_buffer(strlen(json_str),
                                           (void *)json_str,
                                           MHD_RESPMEM_MUST_COPY);
}

enum MHD_Result handle_login(struct MHD_Connection *connection,
                             const char *username,
                             const char *password)
{
    MYSQL *conn = get_db_connection();
    if (!conn)
    {
        const char *error = "{\"error\":\"Database connection error\"}";
        struct MHD_Response *response = create_json_response(error);
        enum MHD_Result ret = MHD_queue_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, response);
        MHD_destroy_response(response);
        return ret;
    }

    // Verify credentials from database
    char query[512];
    snprintf(query, sizeof(query),
             "SELECT id FROM users WHERE username='%s' AND password_hash='%s'",
             username, password); // Note: Use prepared statements in production!

    MYSQL_RES *result = db_fetch_query(conn, query);
    if (!result)
    {
        json_t *error = json_object();
        json_object_set_new(error, "error", json_string("Invalid credentials"));
        char *error_str = json_dumps(error, 0);

        struct MHD_Response *response = create_json_response(error_str);
        enum MHD_Result ret = MHD_queue_response(connection, MHD_HTTP_UNAUTHORIZED, response);

        json_decref(error);
        free(error_str);
        MHD_destroy_response(response);
        return ret;
    }

    MYSQL_ROW row = mysql_fetch_row(result);
    const char *user_id = row[0];

    // Create JWT
    JWT *jwt = create_jwt(user_id, SECRET_KEY);

    json_t *success = json_object();
    json_object_set_new(success, "token", json_string(jwt->token));
    char *success_str = json_dumps(success, 0);

    struct MHD_Response *response = create_json_response(success_str);
    enum MHD_Result ret = MHD_queue_response(connection, MHD_HTTP_OK, response);

    // Cleanup
    json_decref(success);
    free(success_str);
    free_jwt(jwt);
    mysql_free_result(result);
    MHD_destroy_response(response);

    return ret;
}

int verify_auth_token(struct MHD_Connection *connection)
{
    const char *auth_header = MHD_lookup_connection_value(connection,
                                                          MHD_HEADER_KIND,
                                                          "Authorization");

    if (!auth_header || strncmp(auth_header, "Bearer ", 7) != 0)
    {
        return 0;
    }

    const char *token = auth_header + 7;
    return verify_jwt(token, SECRET_KEY);
}

enum MHD_Result handle_register(struct MHD_Connection *connection,
                              const char *username,
                              const char *password,
                              const char *email)
{
    MYSQL *conn = get_db_connection();
    if (!conn)
    {
        const char *error = "{\"error\":\"Database connection error\"}";
        struct MHD_Response *response = create_json_response(error);
        enum MHD_Result ret = MHD_queue_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, response);
        MHD_destroy_response(response);
        return ret;
    }

    // Generate UUID for user
    char uuid[37];
    snprintf(uuid, sizeof(uuid), "%d", rand()); // In production, use proper UUID generation

    // Hash the password (in production, use proper password hashing)
    char query[1024];
    snprintf(query, sizeof(query),
             "INSERT INTO users (id, username, password_hash, email) "
             "VALUES ('%s', '%s', '%s', '%s')",
             uuid, username, password, email);

    if (!db_execute_query(conn, query))
    {
        const char *error = "{\"error\":\"Username or email already exists\"}";
        struct MHD_Response *response = create_json_response(error);
        enum MHD_Result ret = MHD_queue_response(connection, MHD_HTTP_CONFLICT, response);
        MHD_destroy_response(response);
        return ret;
    }

    json_t *success = json_object();
    json_object_set_new(success, "message", json_string("User registered successfully"));
    char *success_str = json_dumps(success, 0);

    struct MHD_Response *response = create_json_response(success_str);
    enum MHD_Result ret = MHD_queue_response(connection, MHD_HTTP_CREATED, response);

    json_decref(success);
    free(success_str);
    MHD_destroy_response(response);

    return ret;
}