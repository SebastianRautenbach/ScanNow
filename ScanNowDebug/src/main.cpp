#include <iostream>
#include "scanner.h"


void function_callback(const std::string& filePath) {
	std::cout << filePath << "\n";
}


int main() {
	scannow::scan(function_callback);
	scannow::stopScan();
	return 0;
}