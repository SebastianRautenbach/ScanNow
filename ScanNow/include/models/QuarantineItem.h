#pragma once
#include <string>


namespace lowlevel {
	class QuarantineItem {
	public:
		std::string hash;
		std::string location;
		std::string reason;		
	private:
	};
}