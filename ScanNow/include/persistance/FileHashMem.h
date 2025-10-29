#pragma once
#include <unordered_map>
#include <string>
#include <memory>


namespace lowlevel {

	class DatabaseClient;

	class FileHashMem {
	public:


		FileHashMem(std::shared_ptr<DatabaseClient> db);
		void loadHashesIntoMemory();

		std::unordered_map<std::string, std::string>& getMaliciousHashes() { return mal_hashes; }
		std::unordered_map<std::string, std::string>& getBenineHashes() { return ben_hashes; }

	private:	
		std::unordered_map<std::string, std::string> mal_hashes, ben_hashes;
		std::shared_ptr<DatabaseClient> dbClient;
	};
}
