#include "controllers/DatabaseClient.h"
#include <fstream>
#include <sstream>
#include <iostream>
#include <vector>
#include <string>
#include "thirdparty/sqlite3.h"
#include <string>


lowlevel::DatabaseClient::DatabaseClient()
{
	createDBFromCSV("resources/full.csv");
}

int lowlevel::DatabaseClient::createDBFromCSV(const char* csv_path)
{
    if (openDB(m_dbName) == 0) return 1; 

    char* errMsg = nullptr;

    const char* create_table_sql =
        "CREATE TABLE IF NOT EXISTS malhashes ("
        "first_seen_utc TEXT, "
        "sha256_hash TEXT, "
        "md5_hash TEXT, "
        "sha1_hash TEXT, "
        "reporter TEXT, "
        "file_name TEXT, "
        "file_type_guess TEXT, "
        "mime_type TEXT, "
        "signature TEXT, "
        "clamav TEXT, "
        "vtpercent TEXT, "
        "imphash TEXT, "
        "ssdeep TEXT, "
        "tlsh TEXT"
        ");";

    if (sqlite3_exec(m_db, create_table_sql, nullptr, nullptr, &errMsg) != SQLITE_OK) {
        std::cerr << "Failed to create table: " << errMsg << std::endl;
        sqlite3_free(errMsg);
        sqlite3_close(m_db);
        return 1;
    }

    const char* insert_sql =
        "INSERT INTO malhashes (first_seen_utc, sha256_hash, md5_hash, sha1_hash, reporter, "
        "file_name, file_type_guess, mime_type, signature, clamav, vtpercent, imphash, ssdeep, tlsh) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(m_db, insert_sql, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(m_db) << std::endl;
        sqlite3_close(m_db);
        return 1;
    }

    std::ifstream file(csv_path);
    if (!file.is_open()) {
        std::cerr << "Failed to open CSV file: " << csv_path << std::endl;
        sqlite3_finalize(stmt);
        sqlite3_close(m_db);
        return 1;
    }

    std::string line;
    bool skip_header = true;

    sqlite3_exec(m_db, "BEGIN TRANSACTION;", nullptr, nullptr, nullptr);

    while (std::getline(file, line)) {
        if (skip_header) { skip_header = false; continue; }
        if (line.empty()) continue;

        std::stringstream ss(line);
        std::string field;
        std::vector<std::string> columns;

        while (std::getline(ss, field, ',')) {              
            columns.push_back(field);
        }

        if (columns.size() != 14) {
            std::cerr << "Skipping malformed row: " << line << std::endl;
            continue;
        }

        for (int i = 0; i < 14; ++i) {
            sqlite3_bind_text(stmt, i + 1, columns[i].c_str(), -1, SQLITE_TRANSIENT);
        }

        if (sqlite3_step(stmt) != SQLITE_DONE) {
            std::cerr << "Insert failed: " << sqlite3_errmsg(m_db) << std::endl;
        }

        sqlite3_reset(stmt);
        sqlite3_clear_bindings(stmt);
    }

    sqlite3_exec(m_db, "COMMIT;", nullptr, nullptr, nullptr);
    sqlite3_finalize(stmt);
    file.close();


    return 0;
}

int lowlevel::DatabaseClient::openDB(const char* m_dbName)
{
    if (sqlite3_open(m_dbName, &m_db) != SQLITE_OK) {
        std::cerr << "Failed to open database: " << sqlite3_errmsg(m_db) << std::endl;
        return 1;
    }
    return 0;
}
