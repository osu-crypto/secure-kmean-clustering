#pragma once
#include <string>

#include "cryptoTools/Common/Defines.h"

void InitDebugPrinting(std::string file = SOLUTION_DIR"/unitTest.txt");
 
extern std::string testData;

class UnitTestFail : public std::exception 
{
	std::string mWhat;
public:
	explicit UnitTestFail(std::string reason)
		:std::exception(),
		mWhat(reason)
	{}

	explicit UnitTestFail()
		:std::exception(),
		mWhat("unitTestFailed exception")
	{ 
	}

	virtual  const char* what() const throw()
	{
		return mWhat.c_str();
	}
};
