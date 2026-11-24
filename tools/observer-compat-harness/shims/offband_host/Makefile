OFFBAND_ROOT ?= /opt/observers/offband
CXX ?= g++
CC ?= gcc

CPPFLAGS := -DARDUINO=10819 -DESP_PLATFORM=1 -DWITH_MQTT_UPLINK=1 -DOFFBAND_OBSERVER=1 -DESP_IDF_VERSION_MAJOR=5 -DED25519_NO_SEED=1
INCLUDES := -Iinclude -I$(OFFBAND_ROOT)/src -I$(OFFBAND_ROOT)/src/helpers/wifi_observer -I$(OFFBAND_ROOT)/lib/ed25519
CXXFLAGS := -std=c++17 -O2 -Wall $(CPPFLAGS) $(INCLUDES)
CFLAGS := -O2 -DED25519_NO_SEED=1 -I$(OFFBAND_ROOT)/lib/ed25519
LDFLAGS := -lpaho-mqtt3as -lmbedcrypto -lmbedtls -lssl -lcrypto -lpthread

ED25519_SRCS := $(wildcard $(OFFBAND_ROOT)/lib/ed25519/*.c)
ED25519_OBJS := $(patsubst $(OFFBAND_ROOT)/lib/ed25519/%.c,build/ed25519_%.o,$(ED25519_SRCS))

OFFBAND_CPP_SRCS := \
	$(OFFBAND_ROOT)/src/Identity.cpp \
	$(OFFBAND_ROOT)/src/Packet.cpp \
	$(OFFBAND_ROOT)/src/Utils.cpp \
	$(OFFBAND_ROOT)/src/helpers/wifi_observer/JwtHelper.cpp \
	$(OFFBAND_ROOT)/src/helpers/wifi_observer/MqttAuth.cpp \
	$(OFFBAND_ROOT)/src/helpers/wifi_observer/MqttPayload.cpp \
	$(OFFBAND_ROOT)/src/helpers/wifi_observer/NeighborsReport.cpp \
	$(OFFBAND_ROOT)/src/helpers/wifi_observer/MqttBroker.cpp

OFFBAND_CPP_OBJS := $(patsubst $(OFFBAND_ROOT)/src/%.cpp,build/offband_%.o,$(OFFBAND_CPP_SRCS))

LOCAL_OBJS := build/esp_mqtt_paho_shim.o build/offband_driver.o

TARGET := offband_driver

.PHONY: all clean

all: $(TARGET)

build:
	mkdir -p build/helpers/wifi_observer

build/ed25519_%.o: $(OFFBAND_ROOT)/lib/ed25519/%.c | build
	$(CC) $(CFLAGS) -c $< -o $@

build/offband_helpers/wifi_observer/%.o: $(OFFBAND_ROOT)/src/helpers/wifi_observer/%.cpp | build
	mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -c $< -o $@

build/offband_%.o: $(OFFBAND_ROOT)/src/%.cpp | build
	mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -c $< -o $@

build/esp_mqtt_paho_shim.o: esp_mqtt_paho_shim.cpp | build
	$(CXX) $(CXXFLAGS) -c $< -o $@

build/offband_driver.o: offband_driver.cpp | build
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(TARGET): $(ED25519_OBJS) $(OFFBAND_CPP_OBJS) $(LOCAL_OBJS)
	$(CXX) $(CXXFLAGS) $^ $(LDFLAGS) -o $@

clean:
	rm -rf build $(TARGET)
