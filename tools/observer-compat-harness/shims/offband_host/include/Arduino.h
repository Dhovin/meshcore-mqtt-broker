#ifndef _SHIM_ARDUINO_H
#define _SHIM_ARDUINO_H

#ifndef ARDUINO
#define ARDUINO 10819
#endif

#include <chrono>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

inline uint32_t millis() {
    static const auto start = std::chrono::steady_clock::now();
    auto now = std::chrono::steady_clock::now();
    return static_cast<uint32_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(now - start).count());
}

class String {
public:
    String() = default;
    String(const char* s) : s_(s ? s : "") {}
    String(const std::string& s) : s_(s) {}
    bool isEmpty() const { return s_.empty(); }
    const char* c_str() const { return s_.c_str(); }
    size_t length() const { return s_.size(); }
private:
    std::string s_;
};

class EspClassStub {
public:
    uint32_t getFreeHeap() const { return 256u * 1024u; }
};

class HardwareSerialStub {
public:
    void print(const char* s) { (void)s; }
    void println(const char* s = "") { (void)s; }
    void printf(const char* fmt, ...) { (void)fmt; }
    void flush() {}
};

extern EspClassStub ESP;
extern HardwareSerialStub Serial;

#endif
