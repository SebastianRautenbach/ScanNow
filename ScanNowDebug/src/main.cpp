#include <iostream>
#include "scanner.h"

namespace lowlevel
{
	class QuarantineItem {
	public:
		std::string hash;
		std::string location;
		std::string reason;
	};
}


void function_callback(const lowlevel::QuarantineItem& filePath) {
	std::cout << filePath.location << "\n";
}


int main() {
	scannow::scan(function_callback);
	scannow::stopScan();
	return 0;
}