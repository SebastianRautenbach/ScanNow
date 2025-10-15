#include "scanner/scanner.h"
#include <iostream>
#include "models/QuarantineItem.h"

void scannow::scan(ScanCallback callback)
{
	lowlevel::QuarantineItem example;
	//callback(example);
}

void scannow::stopScan()
{
	std::cout << "stop scan\n";
}

void scannow::addExclusionZone()
{
	std::cout << "Add exclusion zone\n";
}
