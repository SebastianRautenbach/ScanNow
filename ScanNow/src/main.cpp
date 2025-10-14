#include "persistance/FileHashMem.h"
#include "controllers/DatabaseClient.h"
#include "systems/FileScanner.h"
#include <Windows.h>

using namespace lowlevel;

int WINAPI WinMain(HINSTANCE, HINSTANCE, PSTR, int) {
	auto dc = std::make_shared<DatabaseClient>();
	auto fhm = std::make_shared<FileHashMem>(dc);
	auto fs = std::make_shared<FileScanner>(fhm);

	fs->scan("C:/Users/karat/Desktop/exclude/RenderEngine.exe");
	fs->scan("C:/Users/karat/Desktop/exclude/eicar.com");
}