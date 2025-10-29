#pragma once

namespace lowlevel {
        struct QuarantineItem {
            const char* hash;
            const char* location;
            const char* reason;
        };
}
using ScanCallback = void(*)(const lowlevel::QuarantineItem&);

namespace scannow {
    class ScanNow {
    public:
        ScanNow();
        ~ScanNow();
        bool Initialize();
        void scan(ScanCallback callback);

        ScanNow(const ScanNow&) = delete;
        ScanNow& operator=(const ScanNow&) = delete;

    private:
        struct Impl;
        struct Impl* impl;
    };
}