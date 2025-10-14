#include <iostream>
#include "scanner.h"


void function_callback(std::string path) {
	std::cout << path << "\n";
}


int main() {
	scannow::scan(function_callback);

	return 0;
}