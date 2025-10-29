#include "persistance/FileHashMem.h"
#include "controllers/DatabaseClient.h"
#include "thirdparty/sqlite3.h"

lowlevel::FileHashMem::FileHashMem(std::shared_ptr<DatabaseClient> db)
    :dbClient(db)
{
    loadHashesIntoMemory();
}

void lowlevel::FileHashMem::loadHashesIntoMemory()
{
    // Malicious file insertion
    const char* query = "SELECT * FROM malhashes;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(dbClient->getDB(), query, -1, &stmt, nullptr) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const unsigned char* hash256_text = sqlite3_column_text(stmt, 1);
            if (hash256_text) {                
                mal_hashes[reinterpret_cast<const char*>(hash256_text)] = reinterpret_cast<const char*>(hash256_text);
            }
        }
    }
    sqlite3_finalize(stmt);

    // Benine file insertion
    query = "SELECT * FROM benhashes;";
    stmt = nullptr;
    if (sqlite3_prepare_v2(dbClient->getDB(), query, -1, &stmt, nullptr) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const unsigned char* hash256_text = sqlite3_column_text(stmt, 1);
            if (hash256_text) {
                ben_hashes[reinterpret_cast<const char*>(hash256_text)] = reinterpret_cast<const char*>(hash256_text);
            }
        }
    }
    sqlite3_finalize(stmt);

}
