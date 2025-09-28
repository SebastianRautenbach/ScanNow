#include <string>
#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <unordered_map>
#include "picosha2.h"
#include "thirdparty/sqlite3.h"
#include <filesystem>

sqlite3* db = nullptr;



std::unordered_map<std::string, std::string> temp_hashes;


int openDB(const char* db_name) {
    if (sqlite3_open(db_name, &db) != SQLITE_OK) {
        std::cerr << "Failed to open database: " << sqlite3_errmsg(db) << std::endl;
        return 1;
    }
    return 0;
}

int createDBfromCSV() {
    const char* db_name = "hashes.db";
    const char* csv_path = "resources/full.csv";

    if (openDB(db_name) != 0) return 1;

    char* errMsg = nullptr;

    const char* create_table_sql =
        "CREATE TABLE IF NOT EXISTS hashes ("
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

    if (sqlite3_exec(db, create_table_sql, nullptr, nullptr, &errMsg) != SQLITE_OK) {
        std::cerr << "Failed to create table: " << errMsg << std::endl;
        sqlite3_free(errMsg);
        sqlite3_close(db);
        return 1;
    }

    const char* insert_sql =
        "INSERT INTO hashes (first_seen_utc, sha256_hash, md5_hash, sha1_hash, reporter, "
        "file_name, file_type_guess, mime_type, signature, clamav, vtpercent, imphash, ssdeep, tlsh) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, insert_sql, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_close(db);
        return 1;
    }

    std::ifstream file(csv_path);
    if (!file.is_open()) {
        std::cerr << "Failed to open CSV file: " << csv_path << std::endl;
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return 1;
    }

    std::string line;
    bool skip_header = true;

    sqlite3_exec(db, "BEGIN TRANSACTION;", nullptr, nullptr, nullptr);

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
            std::cerr << "Insert failed: " << sqlite3_errmsg(db) << std::endl;
        }

        sqlite3_reset(stmt);
        sqlite3_clear_bindings(stmt);
    }

    sqlite3_exec(db, "COMMIT;", nullptr, nullptr, nullptr);
    sqlite3_finalize(stmt);
    file.close();

 
    return 0;
}

std::string getFileHash(const char* fileName) {
    std::ifstream file(fileName, std::ios_base::binary);
    if (file.is_open()) {
        std::stringstream buffer;
        buffer << file.rdbuf();
        std::string original = buffer.str();
        std::vector<unsigned char> hash(picosha2::k_digest_size);
        picosha2::hash256(original.begin(), original.end(), hash.begin(), hash.end());
        std::cout << picosha2::bytes_to_hex_string(hash.begin(), hash.end());
        return picosha2::bytes_to_hex_string(hash.begin(), hash.end());
    }
    throw std::runtime_error("Error: Could not open file.");
}

bool doesHashMatchBadHash(const std::string& hash) {
    return temp_hashes.count(hash);
}

void loadHashesIntoMemory() {
    const char* query = "SELECT * FROM hashes;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, query, -1, &stmt, nullptr) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const unsigned char* hash256_text = sqlite3_column_text(stmt, 1);
            const unsigned char* file_name_text = sqlite3_column_text(stmt, 5);
            const unsigned char* mime_type_text = sqlite3_column_text(stmt, 7);
            const unsigned char* signature_text = sqlite3_column_text(stmt, 8);
            
            if (hash256_text && file_name_text && mime_type_text && signature_text) {
                
                hash_def temp;
                
                temp.sha256_hash = reinterpret_cast<const char*>(hash256_text);
                temp.file_name = reinterpret_cast<const char*>(file_name_text);
                temp.mime_type = reinterpret_cast<const char*>(mime_type_text);
                temp.signature = reinterpret_cast<const char*>(signature_text);
                
                temp_hashes[temp.sha256_hash] = temp;
            }                            
        }
    }
    sqlite3_finalize(stmt);
}

int main() {

    const char* db_name = "hashes.db";
    bool db_exists = std::filesystem::exists(db_name);
    

    if (!db_exists) {
        std::cout << "Database does not exist, creating from CSV...\n";
        if (createDBfromCSV() != 0) {
            return 1;
        }
    }
    else {
        std::cout << "Database already exists, opening...\n";
        if (openDB(db_name) != 0) {
            return 1;
        }
    }


    
    loadHashesIntoMemory();


    std::string input;
    std::cin >> input;
    
    try {
        std::string fileHash = getFileHash(input.c_str());
        if (doesHashMatchBadHash(fileHash)) {
            std::cout << "File hash found in DB!\n";
        }
        else {
            std::cout << "File hash not found in DB.\n";
        }
    }
    catch (const std::exception& e) {
        std::cerr << e.what() << "\n";
    }

    sqlite3_close(db);
    return 0;
}
