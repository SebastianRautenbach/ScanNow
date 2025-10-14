#pragma once
#include <string>
#include <memory>
#include <array>
#include "picosha2.h"

namespace lowlevel {

	class FileHashMem;	

	class SignatureScanner {
	public:


		/*
			Check file hash againts database of known bad hashes			
			returns true if match.
		*/

		bool scan(const std::string& fileData, const std::shared_ptr<FileHashMem> hashMem);

		/*
			Generate file to hash
		*/

		inline std::string generateFileHash(const std::string& fileData, std::array<unsigned char, picosha2::k_digest_size>& hashBuffer);

		/*
			Compare generated file hash to known bad hashes
		*/

		inline bool compare(const std::string& hash, const std::shared_ptr<FileHashMem> hashMem);

	private:
	};
}