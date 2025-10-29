#include "scanner/scanner.h"
#include <memory>
#include <string>
#include <windows.h>
#include "systems/SystemScanner.h"



struct scannow::ScanNow::Impl {
    std::shared_ptr<lowlevel::SystemScanner> scanner;
};


scannow::ScanNow::ScanNow() : impl(nullptr) {}
scannow::ScanNow::~ScanNow() { delete impl; }

bool scannow::ScanNow::Initialize() {    
    if (impl) return true;
    try {
        impl = new Impl();
        impl->scanner = std::make_shared<lowlevel::SystemScanner>();
        return true;
    }
    catch (...) {
        return false;
    }    
    return true;
}

void scannow::ScanNow::scan(ScanCallback callback) {
    if (!impl) return;
    lowlevel::QuarantineItem item;
    item.location = "example/location/test.exe";
    impl->scanner->StartSystemScan();
    callback(item);
}


