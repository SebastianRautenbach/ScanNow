#pragma once


class sqlite3;

namespace lowlevel {
	class DatabaseClient {
	public:

		DatabaseClient();

		int createDBFromCSV(const char* csv_path);
		int openDB(const char* db_name);
		sqlite3* getDB() { return m_db; }

	private:
		sqlite3* m_db = nullptr;
		const char* m_dbName = "hashes.db";
	};
}
