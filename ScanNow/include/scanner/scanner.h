#pragma once
#include <functional>
#include <string>


using ScanCallback = std::function<void(const std::string& filePath)>;


namespace scannow {
	
	
	void scan(ScanCallback callback);
	void stopScan();
	void addExclusionZone();
	
}