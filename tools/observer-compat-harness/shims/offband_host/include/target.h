#ifndef _SHIM_TARGET_H
#define _SHIM_TARGET_H

#include "MeshCore.h"

class StubBoard : public mesh::MainBoard {
public:
    uint16_t getBattMilliVolts() override { return 4100; }
    const char* getManufacturerName() const override { return "Heltec V4 Host"; }
    void reboot() override {}
    uint8_t getStartupReason() const override { return BD_STARTUP_NORMAL; }
};

extern StubBoard board;

#endif
