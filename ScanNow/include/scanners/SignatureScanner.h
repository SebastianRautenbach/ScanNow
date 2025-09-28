#pragma once
#include "picosha2.h"
#include <string>


namespace lowlevel {

	class FileHashMem;


	class SignatureScanner {
	public:


		/*
			Check file hash againts database of known bad hashes			
			returns true if match.
		*/

		bool scan(std::string& fileData, std::shared_ptr<FileHashMem> hashMem);

		/*
			Generate file to hash
		*/

		std::string generateFileHash(std::string& fileData);

		/*
			Compare generated file hash to known bad hashes
		*/

		bool compare(std::string& hash, std::shared_ptr<FileHashMem> hashMem);

	private:
	};
}