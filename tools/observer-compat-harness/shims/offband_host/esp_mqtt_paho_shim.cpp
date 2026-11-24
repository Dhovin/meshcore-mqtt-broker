#include "Arduino.h"
#include "target.h"
#include "MeshLog.h"
#include "mqtt_client.h"

#include <MQTTAsync.h>

#include <atomic>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>

volatile bool g_meshLogEnabled = false;
EspClassStub ESP;
HardwareSerialStub Serial;
StubBoard board;

void mesh_log_line(uint8_t level, const char* fmt, ...) {
    (void)level;
    (void)fmt;
}

namespace {

std::string translate_uri(const std::string& raw, bool* out_is_ws, bool* out_is_tls) {
    *out_is_ws = false;
    *out_is_tls = false;
    if (raw.rfind("wss://", 0) == 0) {
        *out_is_ws = true;
        *out_is_tls = true;
        return raw;
    }
    if (raw.rfind("ws://", 0) == 0) {
        *out_is_ws = true;
        return raw;
    }
    if (raw.rfind("mqtts://", 0) == 0) {
        *out_is_tls = true;
        return std::string("ssl://") + raw.substr(8);
    }
    if (raw.rfind("ssl://", 0) == 0) {
        *out_is_tls = true;
        return raw;
    }
    if (raw.rfind("mqtt://", 0) == 0) {
        return std::string("tcp://") + raw.substr(7);
    }
    return raw;
}

}  // namespace

struct esp_mqtt_client {
    std::mutex mu;
    std::string uri;
    std::string ca_pem;
    std::string username;
    std::string password;
    int keepalive = 60;
    std::string client_id;

    esp_event_handler_t handler = nullptr;
    void* handler_arg = nullptr;

    MQTTAsync async = nullptr;
    std::atomic<bool> stopping{false};
    std::atomic<bool> started{false};
    std::atomic<int> inflight_bytes{0};
};

namespace {

void emit_event(esp_mqtt_client* c, esp_mqtt_event_id_t id, const esp_mqtt_error_codes_t* err = nullptr) {
    if (!c || !c->handler) return;
    esp_mqtt_event_t ev = {};
    ev.event_id = id;
    ev.client = c;
    ev.user_context = c->handler_arg;
    ev.error_handle = err;
    c->handler(c->handler_arg, "MQTT_EVENTS", static_cast<int32_t>(id), &ev);
}

void on_paho_connect_success(void* context, MQTTAsync_successData* response) {
    (void)response;
    auto* c = static_cast<esp_mqtt_client*>(context);
    if (!c || c->stopping.load()) return;
    emit_event(c, MQTT_EVENT_CONNECTED);
}

void on_paho_connect_failure(void* context, MQTTAsync_failureData* response) {
    auto* c = static_cast<esp_mqtt_client*>(context);
    if (!c || c->stopping.load()) return;
    esp_mqtt_error_codes_t err = {};
    int code = response ? response->code : -1;
    // Paho CONNACK return codes 1..5 are reported positively in response->code
    if (code > 0 && code <= 5) {
        err.error_type = MQTT_ERROR_TYPE_CONNECTION_REFUSED;
        err.connect_return_code = code;
    } else {
        err.error_type = MQTT_ERROR_TYPE_TCP_TRANSPORT;
        err.esp_transport_sock_errno = errno ? errno : 111;
    }
    emit_event(c, MQTT_EVENT_ERROR, &err);
    emit_event(c, MQTT_EVENT_DISCONNECTED);
}

void on_paho_connection_lost(void* context, char* cause) {
    (void)cause;
    auto* c = static_cast<esp_mqtt_client*>(context);
    if (!c || c->stopping.load()) return;
    emit_event(c, MQTT_EVENT_DISCONNECTED);
}

int on_paho_message_arrived(void* context, char* topicName, int topicLen, MQTTAsync_message* message) {
    (void)context; (void)topicLen;
    MQTTAsync_freeMessage(&message);
    MQTTAsync_free(topicName);
    return 1;
}

void on_paho_delivery_complete(void* context, MQTTAsync_token token) {
    (void)token;
    auto* c = static_cast<esp_mqtt_client*>(context);
    if (c) {
        c->inflight_bytes.store(0);
    }
}

void copy_cfg_unlocked(esp_mqtt_client* c, const esp_mqtt_client_config_t* cfg) {
    if (!cfg) return;
    if (cfg->broker.address.uri) {
        c->uri = cfg->broker.address.uri;
    }
    if (cfg->broker.verification.certificate) {
        c->ca_pem = cfg->broker.verification.certificate;
    }
    if (cfg->session.keepalive > 0) {
        c->keepalive = cfg->session.keepalive;
    }
    c->username = cfg->credentials.username ? cfg->credentials.username : "";
    c->password = cfg->credentials.authentication.password ? cfg->credentials.authentication.password : "";
}

}  // namespace

esp_mqtt_client_handle_t esp_mqtt_client_init(const esp_mqtt_client_config_t* config) {
    if (!config) return nullptr;
    auto* c = new esp_mqtt_client();
    copy_cfg_unlocked(c, config);
    const char* cid_env = std::getenv("OFFBAND_CLIENT_ID");
    if (cid_env && cid_env[0] != '\0') {
        c->client_id = cid_env;
    } else {
        c->client_id = std::string("ESP32_OFFBAND_") + std::to_string(millis() & 0xFFFF);
    }
    return c;
}

esp_err_t esp_mqtt_client_register_event(esp_mqtt_client_handle_t client,
                                         esp_mqtt_event_id_t event,
                                         esp_event_handler_t event_handler,
                                         void* event_handler_arg) {
    (void)event;
    if (!client) return ESP_FAIL;
    std::lock_guard<std::mutex> lk(client->mu);
    client->handler = event_handler;
    client->handler_arg = event_handler_arg;
    return ESP_OK;
}

esp_err_t esp_mqtt_client_set_config(esp_mqtt_client_handle_t client,
                                     const esp_mqtt_client_config_t* config) {
    if (!client || !config) return ESP_FAIL;
    std::lock_guard<std::mutex> lk(client->mu);
    copy_cfg_unlocked(client, config);
    return ESP_OK;
}

esp_err_t esp_mqtt_client_start(esp_mqtt_client_handle_t client) {
    if (!client) return ESP_FAIL;

    bool is_ws = false, is_tls = false;
    std::string paho_uri, cid, user, pass;
    int ka = 60;

    {
        std::lock_guard<std::mutex> lk(client->mu);
        client->stopping.store(false);
        if (client->async) {
            MQTTAsync_destroy(&client->async);
            client->async = nullptr;
        }
        paho_uri = translate_uri(client->uri, &is_ws, &is_tls);
        cid = client->client_id;
        user = client->username;
        pass = client->password;
        ka = client->keepalive;

        MQTTAsync_createOptions create_opts = MQTTAsync_createOptions_initializer;
        create_opts.sendWhileDisconnected = 1;
        create_opts.maxBufferedMessages = 100;

        int rc = MQTTAsync_createWithOptions(
            &client->async,
            paho_uri.c_str(),
            cid.c_str(),
            MQTTCLIENT_PERSISTENCE_NONE,
            nullptr,
            &create_opts);
        if (rc != MQTTASYNC_SUCCESS) {
            fprintf(stderr, "[esp_mqtt_shim] MQTTAsync_createWithOptions failed rc=%d uri=%s\n", rc, paho_uri.c_str());
            return ESP_FAIL;
        }

        MQTTAsync_setCallbacks(
            client->async,
            client,
            on_paho_connection_lost,
            on_paho_message_arrived,
            on_paho_delivery_complete);
    }

    emit_event(client, MQTT_EVENT_BEFORE_CONNECT);

    MQTTAsync_connectOptions conn_opts_tcp = MQTTAsync_connectOptions_initializer;
    MQTTAsync_connectOptions conn_opts_ws = MQTTAsync_connectOptions_initializer_ws;
    MQTTAsync_connectOptions* conn_opts = is_ws ? &conn_opts_ws : &conn_opts_tcp;
    conn_opts->keepAliveInterval = ka;
    conn_opts->cleansession = 1;
    conn_opts->automaticReconnect = 0;
    conn_opts->username = user.empty() ? nullptr : user.c_str();
    conn_opts->password = pass.empty() ? nullptr : pass.c_str();
    conn_opts->onSuccess = on_paho_connect_success;
    conn_opts->onFailure = on_paho_connect_failure;
    conn_opts->context = client;

    MQTTAsync_SSLOptions ssl_opts = MQTTAsync_SSLOptions_initializer;
    const char* ca_file_env = std::getenv("OFFBAND_CA_CERT_FILE");
    const char* insecure_env = std::getenv("OFFBAND_TLS_INSECURE");
    if (is_tls) {
        if (insecure_env && std::strcmp(insecure_env, "1") == 0) {
            ssl_opts.enableServerCertAuth = 0;
            ssl_opts.verify = 0;
        } else {
            ssl_opts.enableServerCertAuth = 1;
            ssl_opts.verify = 1;
            if (ca_file_env && ca_file_env[0] != '\0') {
                ssl_opts.trustStore = ca_file_env;
            }
        }
        conn_opts->ssl = &ssl_opts;
    }

    int rc = MQTTAsync_connect(client->async, conn_opts);
    if (rc != MQTTASYNC_SUCCESS) {
        fprintf(stderr, "[esp_mqtt_shim] MQTTAsync_connect failed rc=%d uri=%s\n", rc, paho_uri.c_str());
        return ESP_FAIL;
    }
    client->started.store(true);
    return ESP_OK;
}

esp_err_t esp_mqtt_client_stop(esp_mqtt_client_handle_t client) {
    if (!client) return ESP_FAIL;
    client->stopping.store(true);
    std::lock_guard<std::mutex> lk(client->mu);
    if (client->async) {
        MQTTAsync_disconnectOptions disc = MQTTAsync_disconnectOptions_initializer;
        disc.timeout = 500;
        MQTTAsync_disconnect(client->async, &disc);
    }
    client->started.store(false);
    return ESP_OK;
}

esp_err_t esp_mqtt_client_destroy(esp_mqtt_client_handle_t client) {
    if (!client) return ESP_OK;
    client->stopping.store(true);
    {
        std::lock_guard<std::mutex> lk(client->mu);
        if (client->async) {
            MQTTAsync_destroy(&client->async);
            client->async = nullptr;
        }
    }
    delete client;
    return ESP_OK;
}

int esp_mqtt_client_enqueue(esp_mqtt_client_handle_t client,
                            const char* topic,
                            const char* data,
                            int len,
                            int qos,
                            int retain,
                            bool store) {
    (void)store;
    if (!client || !topic || !data) return -1;
    std::lock_guard<std::mutex> lk(client->mu);
    if (!client->async || !MQTTAsync_isConnected(client->async)) {
        return -1;
    }

    MQTTAsync_message pubmsg = MQTTAsync_message_initializer;
    pubmsg.payload = const_cast<char*>(data);
    pubmsg.payloadlen = len;
    pubmsg.qos = qos;
    pubmsg.retained = retain ? 1 : 0;

    MQTTAsync_responseOptions opts = MQTTAsync_responseOptions_initializer;
    client->inflight_bytes.fetch_add(len);
    int rc = MQTTAsync_sendMessage(client->async, topic, &pubmsg, &opts);
    if (rc != MQTTASYNC_SUCCESS) {
        fprintf(stderr, "[esp_mqtt_shim] MQTTAsync_sendMessage failed rc=%d topic=%s\n", rc, topic);
        return -1;
    }
    return static_cast<int>(opts.token > 0 ? opts.token : 1);
}

int esp_mqtt_client_get_outbox_size(esp_mqtt_client_handle_t client) {
    if (!client) return 0;
    return client->inflight_bytes.load();
}

void shim_mqtt_force_drop_connection(esp_mqtt_client_handle_t client) {
    if (!client) return;
    std::lock_guard<std::mutex> lk(client->mu);
    if (client->async) {
        MQTTAsync_disconnectOptions disc = MQTTAsync_disconnectOptions_initializer;
        disc.timeout = 0;
        MQTTAsync_disconnect(client->async, &disc);
    }
}
