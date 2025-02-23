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

    MYSQL_STMT *stmt = mysql_stmt_init(conn);
    if (!stmt)
    {
        const char *error = "{\"error\":\"Failed to initialize statement\"}";
        struct MHD_Response *response = create_json_response(error);
        enum MHD_Result ret = MHD_queue_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, response);
        MHD_destroy_response(response);
        return ret;
    }

    const char *query = "SELECT id FROM users WHERE username=? AND password_hash=?";
    if (mysql_stmt_prepare(stmt, query, strlen(query)))
    {
        const char *error = "{\"error\":\"Failed to prepare statement\"}";
        struct MHD_Response *response = create_json_response(error);
        enum MHD_Result ret = MHD_queue_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, response);
        mysql_stmt_close(stmt);
        MHD_destroy_response(response);
        return ret;
    }

    MYSQL_BIND bind[2];
    memset(bind, 0, sizeof(bind));

    bind[0].buffer_type = MYSQL_TYPE_STRING;
    bind[0].buffer = (void *)username;
    bind[0].buffer_length = strlen(username);

    bind[1].buffer_type = MYSQL_TYPE_STRING;
    bind[1].buffer = (void *)password;
    bind[1].buffer_length = strlen(password);

    if (mysql_stmt_bind_param(stmt, bind))
    {
        const char *error = "{\"error\":\"Failed to bind parameters\"}";
        struct MHD_Response *response = create_json_response(error);
        enum MHD_Result ret = MHD_queue_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, response);
        mysql_stmt_close(stmt);
        MHD_destroy_response(response);
        return ret;
    }

    if (mysql_stmt_execute(stmt))
    {
        const char *error = "{\"error\":\"Failed to execute statement\"}";
        struct MHD_Response *response = create_json_response(error);
        enum MHD_Result ret = MHD_queue_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, response);
        mysql_stmt_close(stmt);
        MHD_destroy_response(response);
        return ret;
    }

    MYSQL_BIND result_bind[1];
    char user_id[37];
    unsigned long length;
    memset(result_bind, 0, sizeof(result_bind));

    result_bind[0].buffer_type = MYSQL_TYPE_STRING;
    result_bind[0].buffer = user_id;
    result_bind[0].buffer_length = sizeof(user_id);
    result_bind[0].length = &length;

    if (mysql_stmt_bind_result(stmt, result_bind))
    {
        const char *error = "{\"error\":\"Failed to bind result\"}";
        struct MHD_Response *response = create_json_response(error);
        enum MHD_Result ret = MHD_queue_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, response);
        mysql_stmt_close(stmt);
        MHD_destroy_response(response);
        return ret;
    }

    if (mysql_stmt_fetch(stmt) != 0)
    {
        json_t *error = json_object();
        json_object_set_new(error, "error", json_string("Invalid credentials"));
        char *error_str = json_dumps(error, 0);

        struct MHD_Response *response = create_json_response(error_str);
        enum MHD_Result ret = MHD_queue_response(connection, MHD_HTTP_UNAUTHORIZED, response);

        json_decref(error);
        free(error_str);
        mysql_stmt_close(stmt);
        MHD_destroy_response(response);
        return ret;
    }

    JWT *jwt = create_jwt(user_id, SECRET_KEY);

    json_t *success = json_object();
    json_object_set_new(success, "token", json_string(jwt->token));
    char *success_str = json_dumps(success, 0);

    struct MHD_Response *response = create_json_response(success_str);
    enum MHD_Result ret = MHD_queue_response(connection, MHD_HTTP_OK, response);

    json_decref(success);
    free(success_str);
    free_jwt(jwt);
    mysql_stmt_close(stmt);
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

    char uuid[37];
    snprintf(uuid, sizeof(uuid), "%d", rand());

    MYSQL_STMT *stmt = mysql_stmt_init(conn);
    if (!stmt)
    {
        const char *error = "{\"error\":\"Failed to initialize statement\"}";
        struct MHD_Response *response = create_json_response(error);
        enum MHD_Result ret = MHD_queue_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, response);
        MHD_destroy_response(response);
        return ret;
    }

    const char *query = "INSERT INTO users (id, username, password_hash, email) VALUES (?, ?, ?, ?)";
    if (mysql_stmt_prepare(stmt, query, strlen(query)))
    {
        const char *error = "{\"error\":\"Failed to prepare statement\"}";
        struct MHD_Response *response = create_json_response(error);
        enum MHD_Result ret = MHD_queue_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, response);
        mysql_stmt_close(stmt);
        MHD_destroy_response(response);
        return ret;
    }

    MYSQL_BIND bind[4];
    memset(bind, 0, sizeof(bind));

    bind[0].buffer_type = MYSQL_TYPE_STRING;
    bind[0].buffer = uuid;
    bind[0].buffer_length = strlen(uuid);

    bind[1].buffer_type = MYSQL_TYPE_STRING;
    bind[1].buffer = (void *)username;
    bind[1].buffer_length = strlen(username);

    bind[2].buffer_type = MYSQL_TYPE_STRING;
    bind[2].buffer = (void *)password;
    bind[2].buffer_length = strlen(password);

    bind[3].buffer_type = MYSQL_TYPE_STRING;
    bind[3].buffer = (void *)email;
    bind[3].buffer_length = strlen(email);

    if (mysql_stmt_bind_param(stmt, bind))
    {
        const char *error = "{\"error\":\"Failed to bind parameters\"}";
        struct MHD_Response *response = create_json_response(error);
        enum MHD_Result ret = MHD_queue_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, response);
        mysql_stmt_close(stmt);
        MHD_destroy_response(response);
        return ret;
    }

    if (mysql_stmt_execute(stmt))
    {
        const char *error = "{\"error\":\"Username or email already exists\"}";
        struct MHD_Response *response = create_json_response(error);
        enum MHD_Result ret = MHD_queue_response(connection, MHD_HTTP_CONFLICT, response);
        mysql_stmt_close(stmt);
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
    mysql_stmt_close(stmt);
    MHD_destroy_response(response);

    return ret;
}