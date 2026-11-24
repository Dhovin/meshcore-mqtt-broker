#ifndef _SHIM_STREAM_H
#define _SHIM_STREAM_H

#include <cstddef>
#include <cstdint>

class Stream {
public:
    virtual ~Stream() = default;
    virtual size_t readBytes(uint8_t* buf, size_t len) { (void)buf; (void)len; return 0; }
    virtual size_t write(const uint8_t* buf, size_t len) { (void)buf; (void)len; return 0; }
    virtual size_t write(uint8_t b) { (void)b; return 1; }
    virtual void print(const char* s) { (void)s; }
    virtual void print(char c) { (void)c; }
    virtual void print(int v) { (void)v; }
    virtual void println(const char* s = "") { (void)s; }
};

#endif
