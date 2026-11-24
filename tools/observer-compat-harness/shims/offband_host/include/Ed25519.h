#ifndef _SHIM_ED25519_H
#define _SHIM_ED25519_H

#include <cstddef>
#include <cstdint>
#include <ed_25519.h>

class Ed25519 {
public:
    static bool verify(const uint8_t* signature, const uint8_t* publicKey,
                       const uint8_t* message, size_t len) {
        return ed25519_verify(signature, message, len, publicKey) != 0;
    }
};

#endif
