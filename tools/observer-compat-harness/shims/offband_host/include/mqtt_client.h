#ifndef _SHIM_MQTT_CLIENT_H
#define _SHIM_MQTT_CLIENT_H

#include "esp_err.h"
#include "esp_event.h"
#include <cstdbool>
#include <cstdint>

#ifndef ESP_IDF_VERSION_MAJOR
#define ESP_IDF_VERSION_MAJOR 5
#endif

typedef struct esp_mqtt_client* esp_mqtt_client_handle_t;

typedef enum {
    MQTT_EVENT_ANY = -1,
    MQTT_EVENT_ERROR = 0,
    MQTT_EVENT_CONNECTED,
    MQTT_EVENT_DISCONNECTED,
    MQTT_EVENT_SUBSCRIBED,
    MQTT_EVENT_UNSUBSCRIBED,
    MQTT_EVENT_PUBLISHED,
    MQTT_EVENT_DATA,
    MQTT_EVENT_BEFORE_CONNECT,
    MQTT_EVENT_DELETED,
} esp_mqtt_event_id_t;

typedef enum {
    MQTT_ERROR_TYPE_NONE = 0,
    MQTT_ERROR_TYPE_TCP_TRANSPORT,
    MQTT_ERROR_TYPE_CONNECTION_REFUSED,
} esp_mqtt_error_type_t;

typedef struct esp_mqtt_error_codes {
    esp_mqtt_error_type_t error_type;
    int esp_tls_last_esp_err;
    int esp_tls_stack_err;
    int esp_tls_cert_verify_flags;
    int esp_transport_sock_errno;
    int connect_return_code;
} esp_mqtt_error_codes_t;

typedef struct esp_mqtt_event_t {
    esp_mqtt_event_id_t event_id;
    esp_mqtt_client_handle_t client;
    void* user_context;
    const char* data;
    int data_len;
    const char* topic;
    int topic_len;
    int msg_id;
    const esp_mqtt_error_codes_t* error_handle;
} esp_mqtt_event_t;

typedef esp_mqtt_event_t* esp_mqtt_event_handle_t;

typedef struct esp_mqtt_client_config_t {
    struct {
        struct {
            const char* uri;
            const char* hostname;
            uint32_t port;
            const char* path;
        } address;
        struct {
            const char* certificate;
            bool skip_cert_common_name_check;
        } verification;
    } broker;
    struct {
        const char* username;
        struct {
            const char* password;
        } authentication;
    } credentials;
    struct {
        int keepalive;
        bool disable_auto_reconnect;
    } session;
} esp_mqtt_client_config_t;

#ifdef __cplusplus
extern "C" {
#endif

esp_mqtt_client_handle_t esp_mqtt_client_init(const esp_mqtt_client_config_t* config);
esp_err_t esp_mqtt_client_register_event(esp_mqtt_client_handle_t client,
                                         esp_mqtt_event_id_t event,
                                         esp_event_handler_t event_handler,
                                         void* event_handler_arg);
esp_err_t esp_mqtt_client_set_config(esp_mqtt_client_handle_t client,
                                     const esp_mqtt_client_config_t* config);
static inline esp_err_t esp_mqtt_set_config(esp_mqtt_client_handle_t client,
                                            const esp_mqtt_client_config_t* config) {
    return esp_mqtt_client_set_config(client, config);
}
esp_err_t esp_mqtt_client_start(esp_mqtt_client_handle_t client);
esp_err_t esp_mqtt_client_stop(esp_mqtt_client_handle_t client);
esp_err_t esp_mqtt_client_destroy(esp_mqtt_client_handle_t client);
int esp_mqtt_client_enqueue(esp_mqtt_client_handle_t client,
                            const char* topic,
                            const char* data,
                            int len,
                            int qos,
                            int retain,
                            bool store);
int esp_mqtt_client_get_outbox_size(esp_mqtt_client_handle_t client);

// Harness test helper: abruptly close underlying client without sending MQTT DISCONNECT
void shim_mqtt_force_drop_connection(esp_mqtt_client_handle_t client);

#ifdef __cplusplus
}
#endif

#endif
