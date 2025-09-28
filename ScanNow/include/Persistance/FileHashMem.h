#pragma once
#include <unordered_map>
#include <string>


namespace lowlevel {
	class FileHashMem {
	public:
		std::unordered_map<std::string, std::string> temp_hashes;
	private:
	};
}
