#ifndef _SHIM_AES_H
#define _SHIM_AES_H

#include <cstddef>
#include <cstdint>
#include <cstring>

class AES128 {
public:
    void setKey(const uint8_t* key, size_t len) { (void)key; (void)len; }
    void decryptBlock(uint8_t* output, const uint8_t* input) { std::memcpy(output, input, 16); }
    void encryptBlock(uint8_t* output, const uint8_t* input) { std::memcpy(output, input, 16); }
};

#endif
