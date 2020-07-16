#include "Common.h"
#include <fstream>
#include <cassert>
#include "cryptoTools/Common/Log.h"

using namespace osuCrypto;

static std::fstream* file = nullptr;
std::string testData("../..");

void InitDebugPrinting(std::string filePath)
{
	std::cout  << "changing sink" << std::endl;

	if (file == nullptr)
	{
		file = new std::fstream;
	}
	else
	{
		file->close();
	}

	file->open(filePath, std::ios::trunc | std::ofstream::out);
	if (!file->is_open())
		throw std::runtime_error("");


	//time_t now = time(0);

	//Log::SetSink(*file);

    std::cout.rdbuf(file->rdbuf());
    std::cerr.rdbuf(file->rdbuf());
	
	//std::cout  << "Test - " << ctime(&now) << std::endl;
}
