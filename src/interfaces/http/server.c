#include "server.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "auth_handler.h"
#include <jansson.h>

#define DEFAULT_PORT 8080

static struct MHD_Daemon *http_daemon = NULL;

struct connection_info_struct
{
    int connection_type;
    char *data;
    size_t data_size;
};

static enum MHD_Result handle_request(void *cls,
                                      struct MHD_Connection *connection,
                                      const char *url,
                                      const char *method,
                                      const char *version,
                                      const char *upload_data,
                                      size_t *upload_data_size,
                                      void **con_cls)
{
    (void)cls;
    (void)version;

    struct connection_info_struct *con_info = *con_cls;

    if (NULL == con_info)
    {
        con_info = malloc(sizeof(struct connection_info_struct));
        con_info->data = NULL;
        con_info->data_size = 0;
        *con_cls = con_info;
        return MHD_YES;
    }

    if (strcmp(method, "POST") == 0)
    {
        if (*upload_data_size != 0)
        {
            if (con_info->data == NULL)
            {
                con_info->data = malloc(*upload_data_size + 1);
                memcpy(con_info->data, upload_data, *upload_data_size);
                con_info->data[*upload_data_size] = '\0';
                con_info->data_size = *upload_data_size;
            }
            *upload_data_size = 0;
            return MHD_YES;
        }

        if (strcmp(url, "/login") == 0)
        {
            json_error_t error;
            json_t *root = json_loads(con_info->data, 0, &error);

            if (!root)
            {
                const char *error_msg = "{\"error\":\"Invalid JSON\"}";
                struct MHD_Response *response = MHD_create_response_from_buffer(
                    strlen(error_msg), (void *)error_msg, MHD_RESPMEM_PERSISTENT);
                enum MHD_Result ret = MHD_queue_response(connection, MHD_HTTP_BAD_REQUEST, response);
                MHD_destroy_response(response);
                return ret;
            }

            json_t *username_json = json_object_get(root, "username");
            json_t *password_json = json_object_get(root, "password");

            if (!json_is_string(username_json) || !json_is_string(password_json))
            {
                json_decref(root);
                const char *error_msg = "{\"error\":\"Missing username or password\"}";
                struct MHD_Response *response = MHD_create_response_from_buffer(
                    strlen(error_msg), (void *)error_msg, MHD_RESPMEM_PERSISTENT);
                enum MHD_Result ret = MHD_queue_response(connection, MHD_HTTP_BAD_REQUEST, response);
                MHD_destroy_response(response);
                return ret;
            }

            const char *username = json_string_value(username_json);
            const char *password = json_string_value(password_json);

            enum MHD_Result ret = handle_login(connection, username, password);
            json_decref(root);
            return ret;
        }

        if (strcmp(url, "/register") == 0)
        {
            json_error_t error;
            json_t *root = json_loads(con_info->data, 0, &error);

            if (!root)
            {
                const char *error_msg = "{\"error\":\"Invalid JSON\"}";
                struct MHD_Response *response = MHD_create_response_from_buffer(
                    strlen(error_msg), (void *)error_msg, MHD_RESPMEM_PERSISTENT);
                enum MHD_Result ret = MHD_queue_response(connection, MHD_HTTP_BAD_REQUEST, response);
                MHD_destroy_response(response);
                return ret;
            }

            json_t *username_json = json_object_get(root, "username");
            json_t *password_json = json_object_get(root, "password");
            json_t *email_json = json_object_get(root, "email");

            if (!json_is_string(username_json) ||
                !json_is_string(password_json) ||
                !json_is_string(email_json))
            {
                json_decref(root);
                const char *error_msg = "{\"error\":\"Missing required fields\"}";
                struct MHD_Response *response = MHD_create_response_from_buffer(
                    strlen(error_msg), (void *)error_msg, MHD_RESPMEM_PERSISTENT);
                enum MHD_Result ret = MHD_queue_response(connection, MHD_HTTP_BAD_REQUEST, response);
                MHD_destroy_response(response);
                return ret;
            }

            const char *username = json_string_value(username_json);
            const char *password = json_string_value(password_json);
            const char *email = json_string_value(email_json);

            enum MHD_Result ret = handle_register(connection, username, password, email);
            json_decref(root);
            return ret;
        }
    }

    if (strcmp(url, "/protected") == 0)
    {
        if (!verify_auth_token(connection))
        {
            const char *error = "{\"error\":\"Unauthorized\"}";
            struct MHD_Response *response = MHD_create_response_from_buffer(
                strlen(error), (void *)error, MHD_RESPMEM_PERSISTENT);
            enum MHD_Result ret = MHD_queue_response(connection,
                                                     MHD_HTTP_UNAUTHORIZED,
                                                     response);
            MHD_destroy_response(response);
            return ret;
        }

        const char *success = "{\"message\":\"Access granted\"}";
        struct MHD_Response *response = MHD_create_response_from_buffer(
            strlen(success), (void *)success, MHD_RESPMEM_PERSISTENT);
        enum MHD_Result ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
        MHD_destroy_response(response);
        return ret;
    }

    const char *page = "<html><body>Hello, World!</body></html>";
    struct MHD_Response *response;
    enum MHD_Result ret;

    response = MHD_create_response_from_buffer(strlen(page),
                                               (void *)page,
                                               MHD_RESPMEM_PERSISTENT);

    ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
    MHD_destroy_response(response);

    if (con_info)
    {
        if (con_info->data)
            free(con_info->data);
        free(con_info);
        *con_cls = NULL;
    }

    return ret;
}

int init_server(void)
{
    http_daemon = MHD_start_daemon(MHD_USE_AUTO | MHD_USE_INTERNAL_POLLING_THREAD,
                                   DEFAULT_PORT,
                                   NULL, NULL,
                                   (MHD_AccessHandlerCallback)&handle_request,
                                   NULL,
                                   MHD_OPTION_END);

    if (http_daemon == NULL)
    {
        fprintf(stderr, "Failed to start server\n");
        return 0;
    }

    printf("Server started on port %d\n", DEFAULT_PORT);
    return 1;
}

void start_server(void)
{

    while (1)
    {
        sleep(1);
    }
}

void stop_server(void)
{
    if (http_daemon != NULL)
    {
        MHD_stop_daemon(http_daemon);
        http_daemon = NULL;
    }
}