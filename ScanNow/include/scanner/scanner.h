#pragma once
#include <functional>
#include <string>
#include <memory>

namespace lowlevel {
	class QuarantineItem {
	public:
		std::string hash;
		std::string location;
		std::string reason;
	};
	class SystemScanner;
}

using ScanCallback = std::function<void(const lowlevel::QuarantineItem& filePath)>;


namespace scannow {
	
	class ScanNow
	{
	public:
		ScanNow();
		~ScanNow();
		void scan(ScanCallback callback);
		void stopScan();
		void addExclusionZone();

	private:
		std::unique_ptr<lowlevel::SystemScanner> m_Scanner;	
	};
	
}