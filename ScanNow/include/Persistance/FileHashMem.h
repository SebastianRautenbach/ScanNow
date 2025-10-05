#pragma once
#include <unordered_set>
#include <string>
#include <memory>
#include "controllers/DatabaseClient.h"

namespace lowlevel {
	class FileHashMem {
	public:


		FileHashMem(std::shared_ptr<DatabaseClient> db);
		void loadHashesIntoMemory();

		std::unordered_set<std::string>& getMaliciousHashes() { return mal_hashes; }
		std::unordered_set<std::string>& getBenineHashes() { return ben_hashes; }

	private:	
		std::unordered_set<std::string> mal_hashes, ben_hashes;
		std::shared_ptr<DatabaseClient> dbClient;
	};
}
