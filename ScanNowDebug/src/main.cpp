#include <iostream>
#include "scanner.h"
#include <iostream>

void function_callback(const lowlevel::QuarantineItem& filePath) {
	std::cout << filePath.location << "\n";
}


int main() {
	scannow::ScanNow scnner;
	scnner.scan(function_callback);
	
	
	while (true) { // insure that the scanner does not get deleted!
		std::cin.get();
	}
	
	return 0;
}