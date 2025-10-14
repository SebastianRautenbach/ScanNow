#include "scanner/scanner.h"
#include <iostream>

void scannow::scan(ScanCallback callback)
{
	callback("examples admkasmdlas;md");
}

void scannow::stopScan()
{
	std::cout << "stop scan\n";
}

void scannow::addExclusionZone()
{
	std::cout << "Add exclusion zone\n";
}
