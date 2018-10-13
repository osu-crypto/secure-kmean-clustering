#include "Tests.h"
#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Network/Endpoint.h>
#include <cryptoTools/Network/IOService.h>
#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Common/Log.h>
#include "Common.h"
#include <thread>
#include <vector>
#include <cryptoTools/Common/Timer.h>
#include <algorithm>
#include <unordered_set>
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/BitVector.h"
#include <ivory/Runtime/Public/PublicInt.h>
#include <fstream>
#include <string>
#include <iostream>
#include <boost/algorithm/string.hpp>
#include <boost/tokenizer.hpp>
#include "DataShare.h"
#include <libOTe/Base/naor-pinkas.h>

#ifdef GetMessage
#undef GetMessage
#endif

#ifdef  _MSC_VER
#pragma warning(disable: 4800)
#pragma warning(disable:4996)
#endif //  _MSC_VER

using namespace std;
using namespace osuCrypto;


i64 signExtend1(i64 v, u64 b, bool print = false)
{
	i64 loc = (i64(1) << (b - 1));
	i64 sign = v & loc;

	if (sign)
	{
		i64 mask = i64(-1) << (b);
		auto ret = v | mask;
		if (print)
		{

			std::cout << "sign: " << BitVector((u8*)&sign, 64) << std::endl;;
			std::cout << "mask: " << BitVector((u8*)&mask, 64) << std::endl;;
			std::cout << "v   : " << BitVector((u8*)&v, 64) << std::endl;;
			std::cout << "ret : " << BitVector((u8*)&ret, 64) << std::endl;;

		}
		return ret;
	}
	else
	{
		i64 mask = (i64(1) << b) - 1;
		auto ret = v & mask;
		if (print)
		{

			std::cout << "sign: " << BitVector((u8*)&loc, 64) << std::endl;;
			std::cout << "mask: " << BitVector((u8*)&mask, 64) << std::endl;;
			std::cout << "v   : " << BitVector((u8*)&v, 64) << std::endl;;
			std::cout << "ret : " << BitVector((u8*)&ret, 64) << std::endl;;

		}
		return ret;
	}
}


struct Zn
{
	u64 mVal = 0;
	u8 mD, mM;
	Zn(u8 m, u8 d) {
		mM = m;
		mD = d;
	}
	Zn(i64 v, u8 m, u8 d)
	{
		mM = m;
		mD = d;
		*this = v;
	}

	Zn& operator=(i64 v) {
		mVal = v;// % mod(); 
		return *this;
	}
	Zn& operator=(const Zn& v) {
		return *this = v.mVal;
	}
	Zn operator+(const Zn v) {
		if (mD != v.mD)
			throw std::runtime_error(LOCATION);
		auto vv = mVal + v.mVal;
		return Zn(vv, mM, mD);
	}
	Zn operator-(const Zn v) {
		if (mD != v.mD)
			throw std::runtime_error(LOCATION);
		auto vv = mVal - v.mVal;
		Zn r(vv, mM, mD);
		return r;
	}
	Zn operator-() {
		auto vv = -i64(mVal);
		Zn r(vv, mM, mD);
		return r;
	}

	Zn operator+(const i64 v) {
		auto vv = mVal + v;
		return Zn(vv, mM, mD);
	}
	Zn operator-(const i64 v) {
		auto vv = mVal - v;
		return Zn(vv, mM, mD);
	}
	Zn operator*(const Zn v) {
		if (mD != v.mD)
			throw std::runtime_error(LOCATION);
		auto vv = mVal * v.mVal;
		return Zn(vv, mM, mD);
	}

	Zn operator>>(i64 s) {
		auto vv = signExtend1(mVal >> s, 64 - s);
		return Zn(vv, mM, mD - s);
	}

	i64 val()
	{

		return signExtend1(mVal, mM);
	}

	double get()
	{
		return double(i64(val())) / (1ull << mD);
	}


	BitVector getBinary()
	{
		return BitVector((u8*)&mVal, mM);
	}

	i64 mod()
	{
		return 1ll << mM;
	}
};





namespace osuCrypto
{
	void simple_test() {

		auto k = 8;
		auto d = 1;
		auto s = 8;

		PRNG prng(ZeroBlock);
		Zn a(k, d);
		a = prng.get<i32>();

		std::cout << "  " << a.getBinary() << std::endl;
		std::cout << "  " << a.get() << std::endl;
		//std::cout << "  " << a.mVal<< std::endl;



	}

	void AdaptiveMUL_Zn_test() {
		PRNG prng(ZeroBlock);
		auto bitLen = 5;
		auto radix = 2;
		u32 radixM = pow(radix, (int)bitLen);
		auto d = 0;
		auto s = 8;
		
		

		

		


		std::vector<u32>  baseRecv(128);
		std::vector<std::array<u32, 2>>  baseSend(128);
		BitVector baseChoice(128);
		baseChoice.randomize(prng);

		for (size_t itrial = 0; itrial < 100; itrial++)
		{

			Zn numA(bitLen, d), numB(bitLen, d);

			numA = prng.get<i32>()% radixM;
			numB = prng.get<i32>()% radixM;// prng.get<i32>();;
			auto bitsA = numA.getBinary();
			//auto bitsB = numA.getBinary();

			std::cout << numA.get() << " " << numB.get() << "  " << bitsA << std::endl;

		u32 sA=0, sB=0;
		for (u64 i = 0; i < bitsA.size(); i++)
		{

			baseSend[i][0] = (prng.get<u32>()+ radixM) % radixM;
			baseSend[i][1] = (u32)(numB.mVal*pow(2, i) + baseSend[i][0]) % radixM;
			baseRecv[i] = baseSend[i][bitsA[i]];
			auto mi = (u32)((u32)numB.mVal*bitsA[i] * pow(2, i) + baseSend[i][0] ) % radixM;
			std::cout << "  " << bitsA[i] << "  " << baseRecv[i] << "  " << baseSend[i][0] << "  " << baseSend[i][1] << std::endl;
			std::cout << "mi  " << mi << "\n";
			//std::cout << "mi  " << (u32)numB.mVal << "\n";
			sA += baseRecv[i];
			sB += baseSend[i][0];

			
		}
		sB = (0 - sB) % radixM;
		u32 sum = (sA + sB) % radixM;
		u32 sum2= (numA.mVal*numB.mVal) % radixM;


		if (sum != sum2)
		{
			std::cout << "  " << sum << std::endl;
			std::cout << "  " << sum2 << std::endl;
			throw std::exception();
		}


		}


	}


	BitVector getBinary(i32 value, i32 bitLen)
	{
		return BitVector((u8*)&value, bitLen);
	}

	void AdaptiveMUL_test() {
		PRNG prng(ZeroBlock);
		auto bitLen = 5;
		auto radix = 2;
		u32 radixM = pow(radix, (int)bitLen);
		
		std::vector<u32>  baseRecv(128);
		std::vector<std::array<u32, 2>>  baseSend(128);
		BitVector baseChoice(128);
		baseChoice.randomize(prng);

		for (size_t itrial = 0; itrial < 100; itrial++)
		{
			i32	 numA = prng.get<i32>() % radixM;
			i32 numB = prng.get<i32>() % radixM;// prng.get<i32>();;
			auto bitsA = getBinary(numA,bitLen);
			std::cout << numA << " " << numB << "  " << bitsA << std::endl;

			u32 sA = 0, sB = 0;
			for (u64 i = 0; i < bitsA.size(); i++)
			{

				baseSend[i][0] = (prng.get<u32>() + radixM) % radixM;
				baseSend[i][1] = (u32)(numB*pow(2, i) + baseSend[i][0]) % radixM;
				baseRecv[i] = baseSend[i][bitsA[i]];
				auto mi = (u32)((u32)numB*bitsA[i] * pow(2, i) + baseSend[i][0]) % radixM;
				std::cout << "  " << bitsA[i] << "  " << baseRecv[i] << "  " << baseSend[i][0] << "  " << baseSend[i][1] << std::endl;
				std::cout << "mi  " << mi << "\n";
				//std::cout << "mi  " << (u32)numB.mVal << "\n";
				sA += baseRecv[i];
				sB += baseSend[i][0];


			}
			sB = (0 - sB) % radixM;
			u32 sum = (sA + sB) % radixM;
			u32 sum2 = (numA*numB) % radixM;


			if (sum != sum2)
			{
				std::cout << "  " << sum << std::endl;
				std::cout << "  " << sum2 << std::endl;
				throw std::exception();
			}


		}


	}

	void loadTxtFile(const std::string & fileName,int mDimension, std::vector<std::vector<i64>>& inputA, std::vector<std::vector<i64>>& inputB)
	{
		std::ifstream inFile;
		inFile.open(fileName, std::ios::in);

		if (inFile.is_open() == false)
		{
			std::cout << "failed to open:\n     " << fileName << std::endl;
			throw std::runtime_error(LOCATION);
		}

		std::string line;

		while (getline(inFile, line))
		{
			boost::tokenizer<boost::char_separator<char>> tokens(line, boost::char_separator<char>());
			std::vector<std::string> results(tokens.begin(), tokens.end());
			
			/*std::cout << line << "\n";
			for (size_t i = 0; i < results.size(); i++)
				std::cout << results[i] << " ";*/


			std::vector<i64> idata(mDimension);

			if(mDimension!= results.size())
			{
				std::cout << "mDimension!= results.size()"  << results.size() << std::endl;
				throw std::runtime_error(LOCATION);
			}

			for (size_t i = 0; i < results.size(); i++)
				idata[i]=stoi(results[i]);
		
			auto isA = rand() % 2;
			if (isA)
				inputA.push_back(idata);
			else
				inputB.push_back(idata);
		}
	}

	void readData_test() {
		int mDimension = 2;
		std::vector<std::vector<i64>> inputA, inputB;
		loadTxtFile("I:/kmean-impl/dataset/s1.txt", mDimension, inputA, inputB);

		std::cout << inputA.size() << " \t " << inputB.size() <<"\n";

		for (size_t i = 0; i < inputA.size(); i++)
		{
			for (int j = 0; j < inputA[i].size(); j++)
				std::cout << inputA[i][j] << " ";

			std::cout << "\n ";
		}
	}

	void ClusteringTest()
	{
		IOService ios;
		Session ep01(ios, "127.0.0.1", SessionMode::Server);
		Session ep10(ios, "127.0.0.1", SessionMode::Client);
		Channel chl01 = ep01.addChannel();
		Channel chl10 = ep10.addChannel();


		int mDimension = 2;
		std::vector<std::vector<i64>> inputA, inputB;
		loadTxtFile("I:/kmean-impl/dataset/s1.txt", mDimension, inputA, inputB);

		DataShare p0, p1;
		std::vector<std::array<block, 2>> sendMsg(128);

		std::thread thrd = std::thread([&]() {
			p0.init(0, chl01, toBlock(34265), inputA);
			NaorPinkas baseOTs;
			baseOTs.send(p0.sendBaseMsg, p0.mPrng, chl01, 1);

		});
		
		p1.init(0, chl10, toBlock(34265), inputB);

		NaorPinkas baseOTs;
		baseOTs.receive(p1.mBaseChoices, p1.recvBaseMsg, p1.mPrng, chl10, 1);

		thrd.join();


	}



}