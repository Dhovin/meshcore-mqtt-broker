FROM python:3.12-bookworm

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    pkg-config \
    git \
    openssl \
    ca-certificates \
    libmbedtls-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Build Eclipse Paho MQTT C v1.3.13 with OpenSSL + WebSocket support (ws://, wss://, tcp://, ssl://)
RUN git clone --depth 1 --branch v1.3.13 https://github.com/eclipse-paho/paho.mqtt.c.git /tmp/paho.mqtt.c \
    && cmake -S /tmp/paho.mqtt.c -B /tmp/paho.mqtt.c/build \
        -DPAHO_WITH_SSL=ON \
        -DPAHO_BUILD_SHARED=ON \
        -DPAHO_BUILD_STATIC=OFF \
        -DPAHO_ENABLE_TESTING=OFF \
    && cmake --build /tmp/paho.mqtt.c/build -j"$(nproc)" \
    && cmake --install /tmp/paho.mqtt.c/build \
    && ldconfig \
    && rm -rf /tmp/paho.mqtt.c

# Install runtime dependencies for the Python upstream observers (unmodified)
RUN pip install --no-cache-dir \
    "paho-mqtt>=2.0.0" \
    "pyserial>=3.5" \
    "pyserial-asyncio>=0.6" \
    "pynacl>=1.5.0" \
    "ed25519_orlp" \
    "tomli" \
    "meshcore>=2.3.11" \
    "cryptography>=41.0.0" \
    "pyyaml>=6.0.0" \
    "openhop_core==1.1.3" \
    "psutil>=5.9.0" \
    "cachetools>=5.3.0" \
    "pycryptodome>=3.20.0" \
    "pycayennelpp>=1.0.0"

# Clone and pin exact upstream observer commits (NEVER modified)
RUN mkdir -p /opt/observers \
    && git init /opt/observers/agessaman \
    && git -C /opt/observers/agessaman remote add origin https://github.com/agessaman/meshcore-packet-capture.git \
    && git -C /opt/observers/agessaman fetch --depth 1 origin 122d959f047cb1750218abfadbab7e05bc6c9ba2 \
    && git -C /opt/observers/agessaman checkout --detach FETCH_HEAD \
    && git init /opt/observers/cisien \
    && git -C /opt/observers/cisien remote add origin https://github.com/Cisien/meshcoretomqtt.git \
    && git -C /opt/observers/cisien fetch --depth 1 origin 9b4e022e298020ef3359b36d8c364931de058af5 \
    && git -C /opt/observers/cisien checkout --detach FETCH_HEAD \
    && git init /opt/observers/offband \
    && git -C /opt/observers/offband remote add origin https://github.com/OffbandMesh/meshcore-firmware.git \
    && git -C /opt/observers/offband fetch --depth 1 origin 8be9a02003cfae4427cb349606938fa4fd2869bc \
    && git -C /opt/observers/offband checkout --detach FETCH_HEAD \
    && git init /opt/observers/openhop \
    && git -C /opt/observers/openhop remote add origin https://github.com/openhop-dev/openhop_repeater.git \
    && git -C /opt/observers/openhop fetch --depth 1 origin 13eb8b2ea8b1cdb4a07ed6e282dc99e3aa8a5a8b \
    && git -C /opt/observers/openhop checkout --detach FETCH_HEAD \
    && git init /opt/observers/meshcore-ha \
    && git -C /opt/observers/meshcore-ha remote add origin https://github.com/meshcore-dev/meshcore-ha.git \
    && git -C /opt/observers/meshcore-ha fetch --depth 1 origin 0d5855bfe5b1802fce0857e175674700179c33f1 \
    && git -C /opt/observers/meshcore-ha checkout --detach FETCH_HEAD

WORKDIR /harness
COPY . /harness/

# Compile unmodified OffbandMesh C++ sources against thin Linux/Paho-C shims
RUN make -C /harness/shims/offband_host

ENTRYPOINT ["python3", "/harness/run_audit.py"]
