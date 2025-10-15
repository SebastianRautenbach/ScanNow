#include "scanner/scanner.h"
#include <iostream>
#include "models/QuarantineItem.h"
#include "systems/SystemScanner.h"

scannow::ScanNow::ScanNow()
{
	m_Scanner = std::make_unique<lowlevel::SystemScanner>();
}

void scannow::ScanNow::scan(ScanCallback callback)
{
	m_Scanner->StartSystemScan();
	lowlevel::QuarantineItem example;
	example.location = "example/location/test.exe";
	callback(example);
}

void scannow::ScanNow::stopScan()
{
	std::cout << "stop scan\n";
}

void scannow::ScanNow::addExclusionZone()
{
	std::cout << "Add exclusion zone\n";
}
