#pragma once
#include <functional>
#include <string>


//namespace lowlevel {
//	class QuarantineItem {};
//}

using ScanCallback = std::function<void(const std::string& filePath)>;


namespace scannow {
	
	
	void scan(ScanCallback callback);
	void stopScan();
	void addExclusionZone();
	
}