#pragma once
#include "thirdparty/sqlite3.h"
#include <string>

class DatabaseClient {
public:


	DatabaseClient();

	int createDBFromCSV(const char* csv_path);
	int openDB(const char* db_name);
	sqlite3* getDB() { return db; }

private:
	sqlite3* db = nullptr;
	const char* db_name = "hashes.db";
};