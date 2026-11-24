#include "Arduino.h"
#include "MqttBroker.h"
#include "MqttPayload.h"
#include "NeighborsReport.h"
#include "Identity.h"
#include "Packet.h"
#include "Utils.h"

extern "C" {
#include <ed_25519.h>
}

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

namespace {

class SimpleSeedRng : public mesh::RNG {
public:
    void random(uint8_t* dest, size_t sz) override {
        FILE* f = std::fopen("/dev/urandom", "rb");
        if (f) {
            size_t n = std::fread(dest, 1, sz, f);
            std::fclose(f);
            if (n == sz) return;
        }
        for (size_t i = 0; i < sz; ++i) {
            dest[i] = static_cast<uint8_t>((millis() + i * 31) & 0xFF);
        }
    }
};

bool wait_for_up(offband::MqttBroker& broker, uint32_t timeout_ms) {
    uint32_t start = millis();
    while (millis() - start < timeout_ms) {
        if (!broker.tryConnect(millis(), /*tls_budget_ok=*/true)) {
            // May already be Connecting/Backoff
        }
        broker.loop(millis());
        if (broker.runtime().state == offband::BrokerState::Up) {
            return true;
        }
        if (broker.runtime().state == offband::BrokerState::Failed) {
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    return broker.runtime().state == offband::BrokerState::Up;
}

}  // namespace

int main(int argc, char** argv) {
    std::string url;
    std::string audience = "audit.meshcore.local";
    std::string iata = "SEA";
    std::string transport_str = "wss";
    std::string auth_str = "jwt";
    std::string marker = "offband-marker";
    uint32_t refresh_sec = 60;
    bool test_slim_packet = true;
    bool test_raw = true;
    bool test_neighbors = true;
    bool test_jwt_refresh = false;
    uint32_t wait_past_expiry_sec = 0;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto next_val = [&](const char* flag) -> std::string {
            if (i + 1 >= argc) {
                std::fprintf(stderr, "Missing argument for %s\n", flag);
                std::exit(2);
            }
            return argv[++i];
        };
        if (a == "--url") url = next_val("--url");
        else if (a == "--audience") audience = next_val("--audience");
        else if (a == "--iata") iata = next_val("--iata");
        else if (a == "--transport") transport_str = next_val("--transport");
        else if (a == "--auth") auth_str = next_val("--auth");
        else if (a == "--marker") marker = next_val("--marker");
        else if (a == "--refresh-sec") refresh_sec = static_cast<uint32_t>(std::stoul(next_val("--refresh-sec")));
        else if (a == "--no-slim-packet") test_slim_packet = false;
        else if (a == "--no-raw") test_raw = false;
        else if (a == "--no-neighbors") test_neighbors = false;
        else if (a == "--test-jwt-refresh") test_jwt_refresh = true;
        else if (a == "--wait-sec") wait_past_expiry_sec = static_cast<uint32_t>(std::stoul(next_val("--wait-sec")));
    }

    if (url.empty()) {
        std::fprintf(stderr, "--url is required\n");
        return 2;
    }

    SimpleSeedRng rng;
    mesh::LocalIdentity identity(&rng);
    char pub_hex[65] = {0};
    mesh::Utils::toHex(pub_hex, identity.pub_key, PUB_KEY_SIZE);
    for (size_t i = 0; pub_hex[i]; ++i) {
        if (pub_hex[i] >= 'a' && pub_hex[i] <= 'f') pub_hex[i] -= 32;
    }

    offband::BrokerConfig cfg;
    cfg.enabled = true;
    std::snprintf(cfg.url, sizeof(cfg.url), "%s", url.c_str());
    if (transport_str == "tcp" || transport_str == "mqtt") cfg.transport = offband::BrokerTransport::Tcp;
    else if (transport_str == "tls" || transport_str == "mqtts") cfg.transport = offband::BrokerTransport::Tls;
    else cfg.transport = offband::BrokerTransport::Wss;

    if (auth_str == "jwt") cfg.auth_type = offband::BrokerAuthType::Jwt;
    else if (auth_str == "basic") cfg.auth_type = offband::BrokerAuthType::Basic;
    else cfg.auth_type = offband::BrokerAuthType::None;

    std::snprintf(cfg.jwt_audience, sizeof(cfg.jwt_audience), "%s", audience.c_str());
    cfg.jwt_refresh_sec = refresh_sec;
    std::snprintf(cfg.ca_cert_name, sizeof(cfg.ca_cert_name), "gts-r4");

    offband::MqttBroker broker;
    bool begin_ok = broker.begin(0, cfg, identity, /*may_alloc_client=*/true);
    if (!begin_ok) {
        std::printf("{\"observer\":\"offband\",\"pubkey\":\"%s\",\"begin_ok\":false,\"connected\":false,"
                    "\"error\":\"MqttBroker::begin returned false\"}\n", pub_hex);
        return 1;
    }

    bool connected = wait_for_up(broker, 10000);
    if (!connected) {
        std::printf("{\"observer\":\"offband\",\"pubkey\":\"%s\",\"begin_ok\":true,\"connected\":false,"
                    "\"state\":%d,\"error_class\":%d,\"error\":\"Failed to reach BrokerState::Up\"}\n",
                    pub_hex, static_cast<int>(broker.runtime().state),
                    static_cast<int>(broker.runtime().last_error_class));
        return 1;
    }

    offband::MqttPayloadCtx ctx{};
    broker.fillPayloadCtx(
        ctx,
        iata.c_str(),
        pub_hex,
        ("OffbandSim-" + marker).c_str(),
        "offband-sim/1.0",
        "v1.15.0-offband",
        "Heltec V4 Host"
    );

    // 1. Publish /status via unmodified buildStatusJson (retain=true, qos=0)
    offband::MqttStatusSnapshot snap{};
    snap.battery_mv = 4115;
    snap.uptime_secs = 42;
    snap.error_flags = 0;
    snap.queue_len = 0;
    snap.noise_floor = -111;
    snap.tx_air_secs = 5;
    snap.rx_air_secs = 120;
    snap.recv_errors = 0;
    snap.radio_freq = 910.525f;
    snap.radio_bw = 62.5f;
    snap.radio_sf = 7;
    snap.radio_cr = 5;
    snap.repeat_enabled = true;
    snap.loc_valid = false;

    char status_buf[1024];
    char topic[160];
    int status_len = offband::buildStatusJson(status_buf, sizeof(status_buf), snap, ctx, /*online=*/true);
    offband::formatTopic(topic, sizeof(topic), "status", ctx);
    bool status_enqueued = (status_len > 0) &&
        broker.publish(topic, reinterpret_cast<const uint8_t*>(status_buf), static_cast<size_t>(status_len), /*retain=*/true, /*qos=*/0);
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    // Build a realistic mesh::Packet carrying marker bytes
    mesh::Packet pkt;
    pkt.header = (PAYLOAD_TYPE_GRP_TXT << PH_TYPE_SHIFT) | ROUTE_TYPE_FLOOD;
    pkt.path_len = 0;
    std::string raw_body = std::string("\x11\x22\x33") + marker;
    pkt.payload_len = static_cast<uint16_t>(raw_body.size());
    std::memcpy(pkt.payload, raw_body.data(), raw_body.size());
    pkt._snr = 34;

    // 2. Publish slimmed /packets (#727 sec4: omits origin_id) via unmodified fillPacketRecord + buildPacketJsonFromRecord
    bool packet_enqueued = false;
    std::string packet_json_str;
    if (test_slim_packet) {
        offband::PacketRecord rec{};
        offband::fillPacketRecord(rec, pkt, -89, 8.5f, 1000, 120, static_cast<uint32_t>(std::time(nullptr)));
        char pkt_buf[1024];
        int pkt_len = offband::buildPacketJsonFromRecord(pkt_buf, sizeof(pkt_buf), rec, /*is_tx=*/false, ctx);
        offband::formatTopic(topic, sizeof(topic), "packets", ctx);
        if (pkt_len > 0) {
            packet_json_str.assign(pkt_buf, static_cast<size_t>(pkt_len));
            packet_enqueued = broker.publish(
                topic, reinterpret_cast<const uint8_t*>(pkt_buf), static_cast<size_t>(pkt_len), /*retain=*/false, /*qos=*/0);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(150));
    }

    // 3. Publish /raw via unmodified buildRawJson (includes origin_id)
    bool raw_enqueued = false;
    if (test_raw) {
        char raw_buf[1024];
        int raw_len = offband::buildRawJson(raw_buf, sizeof(raw_buf), pkt, /*is_tx=*/false, -89, 8.5f, ctx);
        offband::formatTopic(topic, sizeof(topic), "raw", ctx);
        if (raw_len > 0) {
            raw_enqueued = broker.publish(
                topic, reinterpret_cast<const uint8_t*>(raw_buf), static_cast<size_t>(raw_len), /*retain=*/false, /*qos=*/0);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(150));
    }

    // 4. Publish /neighbors via unmodified buildNeighborsJson (retain=true, qos=0 matching MqttBrokerPool)
    bool neighbors_enqueued = false;
    if (test_neighbors) {
        offband::ScopeResult sres{};
        std::memset(sres.row.pub_key, 0xAA, offband::kNeighborKeyLen);
        sres.row.snr = 34;
        sres.row.rssi = -85;
        sres.row.heard_timestamp = static_cast<uint32_t>(std::time(nullptr)) - 15;
        std::snprintf(sres.scopes, sizeof(sres.scopes), "sea-mesh");
        sres.status = offband::ScopeStatus::Responded;

        char nbr_ts[32];
        offband::formatReportTimestamp(static_cast<uint32_t>(std::time(nullptr)), nbr_ts, sizeof(nbr_ts));

        std::string origin_str = "OffbandSim-" + marker;
        offband::NeighborsReportInput nin{};
        nin.timestamp = nbr_ts;
        nin.origin = origin_str.c_str();
        nin.origin_id = pub_hex;
        nin.self_scopes = "sea-mesh";
        nin.default_scope = "*";
        nin.rows = &sres;
        nin.n_rows = 1;
        nin.total_neighbors = 1;
        nin.now = static_cast<uint32_t>(std::time(nullptr));
        nin.plausible = nullptr;

        char nbr_buf[4096];
        int nbr_len = offband::buildNeighborsJson(nbr_buf, sizeof(nbr_buf), nin);
        offband::formatTopic(topic, sizeof(topic), "neighbors", ctx);
        if (nbr_len > 0) {
            neighbors_enqueued = broker.publish(
                topic, reinterpret_cast<const uint8_t*>(nbr_buf), static_cast<size_t>(nbr_len), /*retain=*/true, /*qos=*/0);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    // Check whether socket is still Up after publishing slimmed /packets, /raw, /neighbors
    bool stayed_up_after_publishes = (broker.runtime().state == offband::BrokerState::Up);

    bool post_refresh_status_ok = false;
    if (test_jwt_refresh) {
        uint32_t sleep_s = wait_past_expiry_sec > 0 ? wait_past_expiry_sec : (refresh_sec + 5);
        for (uint32_t s = 0; s < sleep_s; ++s) {
            broker.loop(millis());
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        broker.loop(millis());
        if (broker.runtime().state == offband::BrokerState::Up) {
            offband::buildStatusJson(status_buf, sizeof(status_buf), snap, ctx, /*online=*/true);
            offband::formatTopic(topic, sizeof(topic), "status", ctx);
            post_refresh_status_ok = broker.publish(
                topic, reinterpret_cast<const uint8_t*>(status_buf), std::strlen(status_buf), /*retain=*/true, /*qos=*/0);
            std::this_thread::sleep_for(std::chrono::milliseconds(150));
        }
    }

    broker.releaseClient();

    std::printf(
        "{\"observer\":\"offband\",\"pubkey\":\"%s\",\"begin_ok\":true,\"connected\":true,"
        "\"status_enqueued\":%s,\"packet_enqueued\":%s,\"raw_enqueued\":%s,\"neighbors_enqueued\":%s,"
        "\"stayed_up_after_publishes\":%s,\"post_refresh_status_ok\":%s,\"status_timestamp\":\"\"}\n",
        pub_hex,
        status_enqueued ? "true" : "false",
        packet_enqueued ? "true" : "false",
        raw_enqueued ? "true" : "false",
        neighbors_enqueued ? "true" : "false",
        stayed_up_after_publishes ? "true" : "false",
        post_refresh_status_ok ? "true" : "false"
    );
    return 0;
}
