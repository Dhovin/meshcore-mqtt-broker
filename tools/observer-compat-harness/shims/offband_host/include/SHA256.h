#ifndef _SHIM_SHA256_H
#define _SHIM_SHA256_H

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <openssl/evp.h>

class SHA256 {
public:
    SHA256() { reset(); }
    ~SHA256() {
        if (ctx_) EVP_MD_CTX_free(ctx_);
    }

    void reset() {
        if (!ctx_) ctx_ = EVP_MD_CTX_new();
        EVP_DigestInit_ex(ctx_, EVP_sha256(), nullptr);
    }

    void update(const void* data, size_t len) {
        if (ctx_ && data && len > 0) {
            EVP_DigestUpdate(ctx_, data, len);
        }
    }

    void finalize(void* hash, size_t len) {
        if (!ctx_ || !hash || len == 0) return;
        unsigned char full[EVP_MAX_MD_SIZE];
        unsigned int md_len = 0;
        EVP_DigestFinal_ex(ctx_, full, &md_len);
        size_t copy_len = len < md_len ? len : md_len;
        std::memcpy(hash, full, copy_len);
    }

    void resetHMAC(const void* key, size_t keyLen) {
        uint8_t k_pad[64] = {0};
        deriveKeyBlock(key, keyLen, k_pad);
        for (size_t i = 0; i < 64; ++i) k_pad[i] ^= 0x36;
        reset();
        update(k_pad, 64);
    }

    void finalizeHMAC(const void* key, size_t keyLen, void* hash, size_t hashLen) {
        uint8_t inner[32] = {0};
        finalize(inner, sizeof(inner));
        uint8_t k_pad[64] = {0};
        deriveKeyBlock(key, keyLen, k_pad);
        for (size_t i = 0; i < 64; ++i) k_pad[i] ^= 0x5c;
        reset();
        update(k_pad, 64);
        update(inner, sizeof(inner));
        finalize(hash, hashLen);
    }

private:
    void deriveKeyBlock(const void* key, size_t keyLen, uint8_t out[64]) {
        std::memset(out, 0, 64);
        if (!key || keyLen == 0) return;
        if (keyLen > 64) {
            reset();
            update(key, keyLen);
            finalize(out, 32);
        } else {
            std::memcpy(out, key, keyLen);
        }
    }

    EVP_MD_CTX* ctx_ = nullptr;
};

#endif
