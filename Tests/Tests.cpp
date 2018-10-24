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
#include <ivory/Circuit/CircuitLibrary.h>
#include <ivory/Runtime/sInt.h>
#include <ivory/Runtime/Party.h>
#include <ivory/Runtime/ShGc/ShGcInt.h>
#ifdef GetMessage
#undef GetMessage
#endif

#ifdef  _MSC_VER
#pragma warning(disable: 4800)
#pragma warning(disable:4996)
#endif //  _MSC_VER

using namespace std;
using namespace osuCrypto;
#include <ivory/Runtime/ShGc/ShGcRuntime.h>


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
				std::cout << "inDimension!= results.size()"  << results.size() << std::endl;
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
		Timer timer;
		IOService ios;
		Session ep01(ios, "127.0.0.1", SessionMode::Server);
		Session ep10(ios, "127.0.0.1", SessionMode::Client);
		Channel chl01 = ep01.addChannel();
		Channel chl10 = ep10.addChannel();

		int securityParams = 128;
		int inDimension = 1;
		int inExMod = 20;
		u64 inNumCluster = 15;


		int inMod = pow(2, inExMod);
		std::vector<std::vector<Word>> inputA, inputB;
		//loadTxtFile("I:/kmean-impl/dataset/s1.txt", inDimension, inputA, inputB);
		
		PRNG prng(ZeroBlock);
		u64 numberTest = 5;
		inputA.resize(numberTest);
		inputB.resize(numberTest);
		for (int i = 0; i < numberTest; i++)
		{
			inputA[i].resize(inDimension);
			inputB[i].resize(inDimension);
			for (size_t j = 0; j < inDimension; j++)
			{
				inputA[i][j] = prng.get<Word>() % inMod;
				inputB[i][j] = prng.get<Word>() % inMod;

				std::cout << inputA[i][j] << "\t" << inputB[i][j] << " p\n";
			}
		}

		u64 inTotalPoint = inputA.size() + inputB.size();
		//=======================offline===============================
		DataShare p0, p1;

		timer.setTimePoint("starts");
		std::thread thrd = std::thread([&]() {
			p0.init(0, chl01, toBlock(34265), securityParams, inTotalPoint
				, inNumCluster, 0, inNumCluster/2, inputA, inExMod,inDimension);

			NaorPinkas baseOTs;
			baseOTs.send(p0.mSendBaseMsg, p0.mPrng, p0.mChl, 1); //first OT for D_B
			p0.recv.setBaseOts(p0.mSendBaseMsg);


			baseOTs.receive(p0.mBaseChoices, p0.mRecvBaseMsg, p0.mPrng, p0.mChl, 1); //second OT for D_A
			p0.sender.setBaseOts(p0.mRecvBaseMsg, p0.mBaseChoices); //set base OT


		});
		

		p1.init(1, chl10, toBlock(34265), securityParams, inTotalPoint
			, inNumCluster, inNumCluster / 2, inNumCluster, inputB, inExMod, inDimension);
		
		NaorPinkas baseOTs;
		baseOTs.receive(p1.mBaseChoices, p1.mRecvBaseMsg, p1.mPrng, p1.mChl, 1); //first OT for D_B
		p1.sender.setBaseOts(p1.mRecvBaseMsg, p1.mBaseChoices); //set base OT


		baseOTs.send(p1.mSendBaseMsg, p1.mPrng, p1.mChl, 1); //second OT for D_A
		p1.recv.setBaseOts(p1.mSendBaseMsg);



		thrd.join();

		timer.setTimePoint("offlineDone");
		//=======================online (sharing)===============================

		thrd = std::thread([&]() {
			
			p0.sendShareInput(0,0, inNumCluster / 2);
			p0.recvShareInput(p0.mPoint.size(), inNumCluster / 2, inNumCluster);

		});

		p1.recvShareInput(0,0, inNumCluster / 2);
		p1.sendShareInput(p1.mTheirNumPoints, inNumCluster / 2, inNumCluster);


		thrd.join();
		timer.setTimePoint("sharingInputsDone");

#if 1
		//check share
		for (u64 i = 0; i <  p0.mPoint.size(); i++)
		{
			for (u64 j = 0; j < inDimension; j++)
			{
				if ((p0.mSharePoint[i][j].mArithShare + p1.mSharePoint[i][j].mArithShare) % inMod != p0.mPoint[i][j])
				{

					std::cout <<  "(p0.mSharePoint[i][j].mArithShare + p1.mSharePoint[i][j].mArithShare) % inMod != 0\n";
					std::cout << i <<"-" <<j<<": " << p0.mSharePoint[i][j].mArithShare << " vs " << p1.mSharePoint[i][j].mArithShare << "\n";
					throw std::exception();
				}
			}
		}

		for (u64 i = p0.mPoint.size(); i < inTotalPoint; i++)
		{
			for (u64 j = 0; j < inDimension; j++)
			{
				if ((p0.mSharePoint[i][j].mArithShare + p1.mSharePoint[i][j].mArithShare) % inMod != p1.mPoint[i- p0.mPoint.size()][j])
				{

					std::cout << "(p0.mSharePoint[i][j].mArithShare + p1.mSharePoint[i][j].mArithShare) % inMod != 0\n";
					std::cout << i << "-" << j << ": " << p0.mSharePoint[i][j].mArithShare << " vs " << p1.mSharePoint[i][j].mArithShare << "\n";
					throw std::exception();
				}
			}
		}

		for (u64 i = 0; i < inNumCluster/2; i++)
		{
			for (u64 j = 0; j < inDimension; j++)
			{
				if ((p0.mShareCluster[i][j] + p1.mShareCluster[i][j]) % inMod != p0.mCluster[i][j])
				{

					std::cout << "(p0.mShareCluster[i][j].mArithShare + p1.mShareCluster[i][j].mArithShare) % inMod != p0.mCluster[i][j])\n";
					std::cout << i << "-" << j << ": " << p0.mShareCluster[i][j] << " vs " << p1.mShareCluster[i][j] << "\n";
					throw std::exception();
				}
			}
		}


		for (u64 i = inNumCluster / 2; i<inNumCluster; i++)
		{
			for (u64 j = 0; j < inDimension; j++)
			{
				if ((p0.mShareCluster[i][j]+ p1.mShareCluster[i][j]) % inMod != p1.mCluster[i][j])
				{

					std::cout << "(p0.mShareCluster[i][j].mArithShare + p1.mShareCluster[i][j].mArithShare) % inMod != p0.mCluster[i][j])\n";
					std::cout << i << "-" << j << ": " << p0.mShareCluster[i][j] << " vs " << p1.mShareCluster[i][j] << "\n";
					throw std::exception();
				}
			}
		}

		
#endif

		//=======================online OT (setting up keys for adaptive ED)===============================

		thrd = std::thread([&]() {

			//1st OT
			p0.appendAllChoice();
			p0.recv.receive(p0.mChoiceAllBitSharePoints, p0.mRecvAllOtKeys, p0.mPrng, p0.mChl);

			//other OT direction
			p0.sender.send(p0.mSendAllOtKeys, p0.mPrng, p0.mChl);

			p0.setAESkeys();

		});
		//1st OT
		p1.sender.send(p1.mSendAllOtKeys, p1.mPrng, p1.mChl);

		//other OT direction
		p1.appendAllChoice();
		p1.recv.receive(p1.mChoiceAllBitSharePoints, p1.mRecvAllOtKeys, p1.mPrng, p1.mChl);

		p1.setAESkeys();

		thrd.join();


		//=======================online MUL===============================
		
		thrd = std::thread([&]() {
			//(c^A[k][d]*c^B[k][d])
			p0.mProdCluster = p0.amortMULrecv(p0.mShareCluster); //compute C^Ak*C^Bk

			//(p^A[i][d]*(p^B[i][d]-c^B[k][d]) => A receiver
			for (u64 i = 0; i < p0.mTotalNumPoints; i++)
				for (u64 d = 0; d < p0.mDimension; d++)
					p0.mProdPointPPC[i][d] = p0.amortAdaptMULrecv(i, d, p0.mNumCluster); //for each point to all clusters

			//(p^B[i][d]*c^A[k][d]) => A is sender
			for (u64 d = 0; d < p0.mDimension; d++)
				for (u64 k = 0; k < p0.mNumCluster; k++)
					memcpy((u8*)&p0.prodTempC[d][k], (u8*)&p0.mShareCluster[k][d], p0.mLenModinByte); //c^A[k][d]

			for (u64 i = 0; i < p0.mTotalNumPoints; i++)
				for (u64 d = 0; d < p0.mDimension; d++)
					p0.mProdPointPC[i][d] = p0.amortAdaptMULsend(i, d, p0.prodTempC[d]); //for each point to all clusters

		});

			
		p1.mProdCluster = p1.amortMULsend(p1.mShareCluster);//(c^A[k][d]*c^B[k][d])

		//(p^A[i][d]*(p^B[i][d]-c^B[k][d])
		for (u64 i = 0; i < p1.mTotalNumPoints; i++)
			for (u64 d = 0; d < p1.mDimension; d++)
			{
				//prodTempPC=pid-ckl
				for (u64 k = 0; k < p1.mNumCluster; k++)
					p1.prodTempPC[i][d][k] = (p1.mSharePoint[i][d].mArithShare - p1.mShareCluster[k][d]) % p1.mMod;
				
				p1.mProdPointPPC[i][d] = p1.amortAdaptMULsend(i, d, p1.prodTempPC[i][d]);

			}

		//(p^B[i][d]*c^A[k][d]) => B is recv
		for (u64 i = 0; i < p1.mTotalNumPoints; i++)
			for (u64 d = 0; d < p1.mDimension; d++)
				p1.mProdPointPC[i][d] = p1.amortAdaptMULrecv(i, d, p1.mNumCluster); //for each point to all clusters
	
		thrd.join();

#if 1
		std::cout << "--------c^A[k][d]*c^B[k][d]------\n";

		for (u64 k = 0; k < p0.mNumCluster; k++)
			for (u64 d = 0; d < p0.mDimension; d++)
			{
				Word sum1 = (p0.mProdCluster[k][d] + p1.mProdCluster[k][d]) % p1.mMod;
				Word sum2 = (p0.mShareCluster[k][d] * p1.mShareCluster[k][d]) % p1.mMod;
				if (sum1 != sum2)
				{
					std::cout << p0.mProdCluster[k][d] << " + " << p1.mProdCluster[k][d] << " = " << sum1 << "\n";
					std::cout << p0.mShareCluster[k][d] << " * " << p1.mShareCluster[k][d] << " = " << sum2 << "\n";
					throw std::exception();
				}
			}

		std::cout << "--------(p^A[i][d]*(p^B[i][d]-c^B[k][d])------\n";

		

		for (u64 i = 0; i < p1.mTotalNumPoints; i++)
			for (u64 d = 0; d < p0.mDimension; d++)
				for (u64 k = 0; k < p0.mNumCluster; k++)
				{
					Word sum1 = (p0.mProdPointPPC[i][d][k] + p1.mProdPointPPC[i][d][k]) % p1.mMod;
					Word sum2 = (p0.mSharePoint[i][d].mArithShare * p1.prodTempPC[i][d][k]) % p1.mMod;
					if (sum1 != sum2)
					{
						std::cout << i << " - " << d << "\t" << p1.mTotalNumPoints << " sss\n";
						std::cout << p0.mProdPointPPC[i][d][k] << " + " << p1.mProdPointPPC[i][d][k] << " = " << sum1 << "\n";
						std::cout << p1.prodTempPC[i][d][k] << " * " << p0.mSharePoint[i][d].mArithShare << " = " << sum2 << "\n";
						throw std::exception();
					}
				}

		std::cout << "--------(p^B[i][d]*c^A[k][d])------\n";

		for (u64 i = 0; i < p1.mTotalNumPoints; i++)
			for (u64 d = 0; d < p0.mDimension; d++)
				for (u64 k = 0; k < p0.mNumCluster; k++)
				{
					Word sum1 = (p0.mProdPointPC[i][d][k] + p1.mProdPointPC[i][d][k]) % p1.mMod;
					Word sum2 = (p1.mSharePoint[i][d].mArithShare * p0.prodTempC[d][k]) % p1.mMod;
					if (sum1 != sum2)
					{
						std::cout << i << " - " << d << "\t" << p1.mTotalNumPoints << " sss\n";
						std::cout << p0.mProdPointPC[i][d][k] << " + " << p1.mProdPointPC[i][d][k] << " = " << sum1 << "\n";
						std::cout << p0.prodTempC[d][k] << " * " << p1.mSharePoint[i][d].mArithShare << " = " << sum2 << "\n";
						throw std::exception();
					}
				}

#endif
		//=======================online locally compute ED===============================
		thrd = std::thread([&]() {
			p0.computeDist();
		});
		p1.computeDist();

#if 1
		std::vector<std::vector<Word>> points(p0.mTotalNumPoints);
		std::vector<std::vector<Word>> clusters(p0.mNumCluster);
		for (u64 i = 0; i < p0.mTotalNumPoints; i++) //original points
		{
			points[i].resize(p0.mDimension);
			for (u64 d = 0; d < p0.mDimension; d++)
				points[i][d] = (Word)(p0.mSharePoint[i][d].mArithShare + p1.mSharePoint[i][d].mArithShare) % p0.mMod;
		}
		
		
		for (u64 k = 0; k < p0.mNumCluster; k++) //original cluster
		{
				clusters[k].resize(p0.mDimension);
				for (u64 d = 0; d < p0.mDimension; d++)
					clusters[k][d] = (Word)(p0.mShareCluster[k][d] + p1.mShareCluster[k][d]) % p0.mMod;
		}

		for (u64 i = 0; i < p0.mTotalNumPoints; i++) //original points
			for (u64 k = 0; k < p0.mNumCluster; k++) //original cluster
			{
				i64 expectedDist = 0;
				for (u64 d = 0; d < p0.mDimension; d++)
				{
					Word diff = (points[i][d] - clusters[k][d]) % p0.mMod;
					expectedDist = (expectedDist + (i64)pow(diff, 2)) % (i64)pow(p0.mMod, 1);
				}
				i64 ourDist = (p0.mDist[i][k]+ p1.mDist[i][k]) % (i64)pow(p0.mMod, 1);

				if (expectedDist != ourDist)
				{
					std::cout << i << "-" << k << ": ";
					std::cout << p0.mDist[i][k] << " + " << p1.mDist[i][k] << " = " << ourDist << " vs ";
					std::cout << expectedDist << "\n";

					for (u64 d = 0; d < p0.mDimension; d++)
					{
						std::cout << points[i][d] << " vs " << (p0.mSharePoint[i][d].mArithShare + p1.mSharePoint[i][d].mArithShare)% p0.mMod << "= " << p0.mSharePoint[i][d].mArithShare << " + " << p1.mSharePoint[i][d].mArithShare << " p \n";
						std::cout << clusters[k][d] << "= " <<p0.mShareCluster[k][d] << " + " << p1.mShareCluster[k][d] << " c \n";
						Word diff2p0 = (p0.mSharePoint[i][d].mArithShare - p0.mShareCluster[k][d]) % p0.mMod;
						Word diff2p1 = (p1.mSharePoint[i][d].mArithShare - p1.mShareCluster[k][d]) % p0.mMod;
						
						Word secondtermp0 = (p0.mProdPointPPC[i][d][k] - p0.mProdPointPC[i][d][k] + p0.mProdCluster[k][d]) % p0.mMod;
						Word secondtermp1 = (p1.mProdPointPPC[i][d][k] - p1.mProdPointPC[i][d][k] + p1.mProdCluster[k][d]) % p0.mMod;

						std::cout << diff2p0 << " * " << diff2p1 << " = " << (diff2p0*diff2p1) % (p0.mMod) << " \n";
						std::cout << secondtermp1 << " + " << secondtermp0 << " = " << (secondtermp1+secondtermp0)%(p0.mMod) << " \n";



					/*	Word distP0 = (Word)(pow(diff2p0, 2) + 2 * secondtermp0) % (i64)pow(p0.mMod, 2);
						Word distP1 = (Word)(pow(diff2p1, 2) + 2 * secondtermp1) % (i64)pow(p0.mMod, 2);

						std::cout << diff2p0 << " vs " << secondtermp0 << ": " << distP0 << " p0\n";
						std::cout << diff2p1 << " vs " << secondtermp1 << ": " << distP1 << " p1\n";*/




						

					}



					throw std::exception();
				}
			}

		std::cout << " ------ED done-------\n";


#endif

		thrd.join();
		timer.setTimePoint("OTkeysDone");

		p0.Print();
		p1.Print();


		


	}



	void MulTest()
	{
		Timer timer;
		IOService ios;
		Session ep01(ios, "127.0.0.1", SessionMode::Server);
		Session ep10(ios, "127.0.0.1", SessionMode::Client);
		Channel chl01 = ep01.addChannel();
		Channel chl10 = ep10.addChannel();

		int securityParams = 128;
		int inDimension = 2;
		int inExMod = 20;
		u64 inNumCluster = 15;


		int inMod = pow(2, inExMod);
		std::vector<std::vector<Word>> inputA, inputB;
		//loadTxtFile("I:/kmean-impl/dataset/s1.txt", inDimension, inputA, inputB);

		PRNG prng(ZeroBlock);
		u64 numberTest = 12;
		inputA.resize(numberTest);
		inputB.resize(numberTest);
		for (int i = 0; i < numberTest; i++)
		{
			inputA[i].resize(inDimension);
			inputB[i].resize(inDimension);
			for (size_t j = 0; j < inDimension; j++)
			{
				inputA[i][j] = prng.get<Word>() % inMod;
				inputB[i][j] = prng.get<Word>() % inMod;
			}
		}

		u64 inTotalPoint = inputA.size() + inputB.size();
		//=======================offline===============================
		DataShare p0, p1;

		timer.setTimePoint("starts");
		std::thread thrd = std::thread([&]() {
			p0.init(0, chl01, toBlock(34265), securityParams, inTotalPoint
				, inNumCluster, 0, inNumCluster / 2, inputA, inExMod, inDimension);

			NaorPinkas baseOTs;
			baseOTs.send(p0.mSendBaseMsg, p0.mPrng, p0.mChl, 1); //first OT for D_B
			p0.recv.setBaseOts(p0.mSendBaseMsg);


			baseOTs.receive(p0.mBaseChoices, p0.mRecvBaseMsg, p0.mPrng, p0.mChl, 1); //second OT for D_A
			p0.sender.setBaseOts(p0.mRecvBaseMsg, p0.mBaseChoices); //set base OT


		});


		p1.init(1, chl10, toBlock(34265), securityParams, inTotalPoint
			, inNumCluster, inNumCluster / 2, inNumCluster, inputB, inExMod, inDimension);

		NaorPinkas baseOTs;
		baseOTs.receive(p1.mBaseChoices, p1.mRecvBaseMsg, p1.mPrng, p1.mChl, 1); //first OT for D_B
		p1.sender.setBaseOts(p1.mRecvBaseMsg, p1.mBaseChoices); //set base OT


		baseOTs.send(p1.mSendBaseMsg, p1.mPrng, p1.mChl, 1); //second OT for D_A
		p1.recv.setBaseOts(p1.mSendBaseMsg);



		thrd.join();

		timer.setTimePoint("offlineDone");
		//=======================online (sharing)===============================

		thrd = std::thread([&]() {

			p0.sendShareInput(0, 0, inNumCluster / 2);
			p0.recvShareInput(p0.mPoint.size(), inNumCluster / 2, inNumCluster);

		});

		p1.recvShareInput(0, 0, inNumCluster / 2);
		p1.sendShareInput(p1.mTheirNumPoints, inNumCluster / 2, inNumCluster);


		thrd.join();
		timer.setTimePoint("sharingInputsDone");

#if 1
		//check share
		for (u64 i = 0; i < p0.mPoint.size(); i++)
		{
			for (u64 j = 0; j < inDimension; j++)
			{
				if ((p0.mSharePoint[i][j].mArithShare + p1.mSharePoint[i][j].mArithShare) % inMod != p0.mPoint[i][j])
				{

					std::cout << "(p0.mSharePoint[i][j].mArithShare + p1.mSharePoint[i][j].mArithShare) % inMod != 0\n";
					std::cout << i << "-" << j << ": " << p0.mSharePoint[i][j].mArithShare << " vs " << p1.mSharePoint[i][j].mArithShare << "\n";
					throw std::exception();
				}
			}
		}

		for (u64 i = p0.mPoint.size(); i < inTotalPoint; i++)
		{
			for (u64 j = 0; j < inDimension; j++)
			{
				if ((p0.mSharePoint[i][j].mArithShare + p1.mSharePoint[i][j].mArithShare) % inMod != p1.mPoint[i - p0.mPoint.size()][j])
				{

					std::cout << "(p0.mSharePoint[i][j].mArithShare + p1.mSharePoint[i][j].mArithShare) % inMod != 0\n";
					std::cout << i << "-" << j << ": " << p0.mSharePoint[i][j].mArithShare << " vs " << p1.mSharePoint[i][j].mArithShare << "\n";
					throw std::exception();
				}
			}
		}

		for (u64 i = 0; i < inNumCluster / 2; i++)
		{
			for (u64 j = 0; j < inDimension; j++)
			{
				if ((p0.mShareCluster[i][j] + p1.mShareCluster[i][j]) % inMod != p0.mCluster[i][j])
				{

					std::cout << "(p0.mShareCluster[i][j].mArithShare + p1.mShareCluster[i][j].mArithShare) % inMod != p0.mCluster[i][j])\n";
					std::cout << i << "-" << j << ": " << p0.mShareCluster[i][j] << " vs " << p1.mShareCluster[i][j] << "\n";
					throw std::exception();
				}
			}
		}


		for (u64 i = inNumCluster / 2; i<inNumCluster; i++)
		{
			for (u64 j = 0; j < inDimension; j++)
			{
				if ((p0.mShareCluster[i][j] + p1.mShareCluster[i][j]) % inMod != p1.mCluster[i][j])
				{

					std::cout << "(p0.mShareCluster[i][j].mArithShare + p1.mShareCluster[i][j].mArithShare) % inMod != p0.mCluster[i][j])\n";
					std::cout << i << "-" << j << ": " << p0.mShareCluster[i][j] << " vs " << p1.mShareCluster[i][j] << "\n";
					throw std::exception();
				}
			}
		}


#endif

		//=======================online OT (setting up keys for adaptive ED)===============================

		thrd = std::thread([&]() {

			//1st OT
			p0.appendAllChoice();
			p0.recv.receive(p0.mChoiceAllBitSharePoints, p0.mRecvAllOtKeys, p0.mPrng, p0.mChl);
			
			//other OT direction
			p0.sender.send(p0.mSendAllOtKeys, p0.mPrng, p0.mChl);

			p0.setAESkeys();

		});
		//1st OT
		p1.sender.send(p1.mSendAllOtKeys, p1.mPrng, p1.mChl);

		//other OT direction
		p1.appendAllChoice();
		p1.recv.receive(p1.mChoiceAllBitSharePoints, p1.mRecvAllOtKeys, p1.mPrng, p1.mChl);
		
		p1.setAESkeys();
		
		thrd.join();

		std::cout << p0.mChoiceAllBitSharePoints << " mChoiceAllBitSharePoints \n";
		std::cout << p1.mChoiceAllBitSharePoints << " mChoiceAllBitSharePoints \n";
		std::cout << p0.mSendAllOtKeys.size() << " = " << p0.mChoiceAllBitSharePoints.size()<<" ====\n";


		for (u64 i = 0; i < p0.mSendAllOtKeys.size(); i++)
		{
			std::cout << p1.mSendAllOtKeys[i][0]
				<< " vs " << p1.mSendAllOtKeys[i][1] << "\t";

			std::cout << p0.mRecvAllOtKeys[i] << " vs "
				<< p0.mChoiceAllBitSharePoints[i]<< "\n";
		}

		int idx = 0;
		for (u64 i = 0; i < p0.mTotalNumPoints; i++)
			for (u64 j = 0; j < p0.mDimension; j++)
			{
				for (u64 l = 0; l < p0.mLenMod; l++)
				{
				/*	std::cout << p0.mSharePoint[i][j].sendOtKeys[l][0]
						<< " vs " << p0.mSharePoint[i][j].sendOtKeys[l][1] << " tt\n";

					std::cout << p1.mSharePoint[i][j].recvOtKeys[l] 
						<< " tt\n";*/

					std::cout << p1.mSharePoint[i][j].sendOtKeys[l][0]
						<< " vs " << p1.mSharePoint[i][j].sendOtKeys[l][1] << " ttt\n";

					std::cout << p0.mSharePoint[i][j].recvOtKeys[l] << " vs " 
					<<	p0.mSharePoint[i][j].mBitShare[l] <<" ttt\n";

					idx++;
				}
				std::cout <<  "============\n";
			}
		//=======================online ED===============================
#if 1
		std::vector<Word> m0, mi;
		std::vector<Word> b;// (p0.mTotalNumPoints*p0.mNumCluster*p0.mDimension);

		int idxPoint = 12;
		int idxDim = 0;
		thrd = std::thread([&]() {

			
			//mi = p0.amortAdaptMULrecv(idxPoint, idxDim, p0.mNumCluster);
			mi = p0.amortAdaptMULrecv(idxPoint, idxDim, p0.mNumCluster);

			//p0.mProdCluster = p0.amortMULrecv(p0.mShareCluster);
		});

		
		for (u64 k = 0; k < p1.mNumCluster; k++)
		{
			auto a = (p1.mSharePoint[idxPoint][idxDim].mArithShare - p1.mShareCluster[k][idxDim]) % p1.mMod;
			std::cout << "a= " << a << "\n";
			b.push_back(a);

		}
		m0 = p1.amortAdaptMULsend(idxPoint, idxDim, b);

	//	p1.mProdCluster = p1.amortMULsend(p1.mShareCluster);


		thrd.join();

		for (u64 k = 0; k < p0.mNumCluster; k++)
		{
			std::cout << m0[k] << " + " << mi[k] << " = " << (m0[k] + mi[k]) % p1.mMod << "\n";
			std::cout << b[k] << " * " << p0.mSharePoint[idxPoint][idxDim].mArithShare << " = " << (b[k] * p0.mSharePoint[idxPoint][idxDim].mArithShare) % p1.mMod << "\n";
		}

	/*	std::cout << "--------------\n";
		for (u64 k = 0; k < p0.mNumCluster; k++)
		{
			for (u64 d = 0; d < p0.mDimension; d++)
			{
				std::cout << p0.mProdCluster[k][d] << " + " << p1.mProdCluster[k][d] << " = " << (p1.mProdCluster[k][d] + p0.mProdCluster[k][d]) % p0.mMod << "\n";
				std::cout << p0.mShareCluster[k][d] << " * " << p1.mShareCluster[k][d] << " = " << (p1.mShareCluster[k][d] * p0.mShareCluster[k][d]) % p1.mMod << "\n";

			}
		}*/


		timer.setTimePoint("OTkeysDone");

		p0.Print();
		p1.Print();


#endif


	}

	void testDecAES()
	{
		PRNG prng(ZeroBlock);
		block* plaintexts = new block[10];
		block* plaintexts1=new block[10];
		block key = prng.get<block>();
		AES encAES(key);
		AESDec decAES(key);
		
		for (size_t i = 0; i < 10; i++)
		{
			plaintexts[i] = prng.get<block>();
		}

		block* cipher = new block[10];
		encAES.ecbEncBlocks(plaintexts, 10, cipher);
		decAES.ecbDecBlocks(cipher, 10, plaintexts1);

		for (size_t i = 0; i < 10; i++)
		{
			//if(!memcmp((u8*)&plaintexts[i], (u8*)&plaintexts1[i], sizeof(block)));
			{
				std::cout << plaintexts[i] << " vs " << plaintexts1[i] << " \n";
				//throw std::exception();
			}
		}
	}



	void programLessThan(std::array<Party, 2> parties, std::vector<i64>& myInput, BitVector& myOutput, u64 bitCount)
	{

		// choose how large the arithmetic should be.
		bitCount = 16;

		for (u64 i = 0; i < myInput.size(); i++)
		{
			auto input0 = parties[0].isLocalParty() ?
				parties[0].input<sInt>(myInput[i], bitCount) :
				parties[0].input<sInt>(bitCount);

			auto input1 = parties[1].isLocalParty() ?
				parties[1].input<sInt>(myInput[i], bitCount) :
				parties[1].input<sInt>(bitCount);
		
			auto lt = input0 < input1;

			auto invert=~lt;

			 parties[0].reveal(lt);
			 parties[0].reveal(invert);
			parties[1].getRuntime().processesQueue();

			ShGcInt * v = static_cast<ShGcInt*>(lt.mData.get());
			myOutput[2*i] = PermuteBit((*v->mLabels)[0]);
			ShGcInt * v1 = static_cast<ShGcInt*>(invert.mData.get());
			myOutput[2*i + 1] = PermuteBit((*v1->mLabels)[0]);
			
			if (parties[0].isLocalParty())
			{
				ostreamLock(std::cout) << i << ": slt= " << int(myOutput[2*i]) << int(myOutput[2*i + 1]) << "    A\n";// << (*v1->mLabels)[0] << std::endl;
				std::cout << i << ": lt= " << lt.getValue() << " vs " << invert.getValue() <<  " \n--------------\n";

			}

			if (parties[1].isLocalParty())
			{
				//std::cout << i << ": lt= " << lt.getValue() << " vs " << invert.getValue() << std::endl;
				ostreamLock(std::cout) << i << ": slt= " << int(myOutput[2*i]) << int(myOutput[2*i + 1]) << "    B\n";// << (*v1->mLabels)[0] << std::endl;
			}


		}
					
		
	}

	void testMinDist()
	{
		Timer timer;
		IOService ios;
		Session ep01(ios, "127.0.0.1", SessionMode::Server);
		Session ep10(ios, "127.0.0.1", SessionMode::Client);
		Channel chl01 = ep01.addChannel();
		Channel chl10 = ep10.addChannel();

		CircuitLibrary lib;

		int securityParams = 128;
		int inDimension = 1;
		int inExMod = 20;
		u64 inNumCluster = 15;
		int inMod = pow(2, inExMod);
		PRNG prng(ZeroBlock);
		u64 numberTest = 6;

		std::vector<Word> inputA(numberTest), inputB(numberTest);
		BitVector vecMinA(numberTest), vecMinB(numberTest);


		for (int i = 0; i < numberTest; i++)
		{
				u64 num = rand() % 10;
				inputA[i] = prng.get<Word>() % inMod;
				inputB[i] =(num- inputA[i]) % inMod;
				std::cout << num <<":" << inputA[i] << " + " << inputB[i] <<" = " << (inputA[i] + inputB[i]) % inMod << " p\n";
		}

		
		bool debug = false;

		//TODO: case for odd #cluster
			std::thread thrd = std::thread([&]() { //party 1

				std::vector<i64> Diffs;
				for (u64 i = 0; i < inputA.size()-1; i+=2)
					Diffs.push_back(inputA[i] - inputA[i+1]);


				std::cout << IoStream::lock;
				for (u64 i = 0; i < Diffs.size(); i++)
					std::cout <<Diffs[i]  << "   A\n";
				std::cout << IoStream::unlock;

				//chl01.waitForConnection();

				// set up the runtime, see above for details
				ShGcRuntime rt0;
				rt0.mDebugFlag = debug;
				rt0.init(chl01, prng.get<block>(), ShGcRuntime::Garbler, 0);

				// instantiate the parties
				std::array<Party, 2> parties{
					Party(rt0, 0),
					Party(rt0, 1)
				};

				programLessThan(parties, Diffs, vecMinA,inExMod+1);
				//ostreamLock(std::cout) << "0share lt    " << int(shareLT) <<  std::endl;


			});

			std::vector<i64> Diffs;
			for (u64 i = 0; i < inputB.size() - 1; i += 2)
			{
				Diffs.push_back( inputB[i + 1]- inputB[i]);
			}


			std::cout << IoStream::lock;
			for (u64 i = 0; i < Diffs.size(); i++)
				std::cout << Diffs[i] << "   B\n";
			std::cout << IoStream::unlock;


			//chl10.waitForConnection();


			// set up the runtime, see above for details
			ShGcRuntime rt1;
			rt1.mDebugFlag = debug;
			rt1.init(chl10, prng.get<block>(), ShGcRuntime::Evaluator, 1);

			// instantiate the parties
			std::array<Party, 2> parties{
				Party(rt1, 0),
				Party(rt1, 1)
			};

			 programLessThan(parties, Diffs, vecMinB, inExMod+1);

			//party 2


			thrd.join();

			ostreamLock(std::cout) << vecMinA << " bitv A\n";
			ostreamLock(std::cout) << vecMinB << " bitv B";

		//if ((bool)cc != c)
		//{
		//	//std::cout << "i " << i << std::endl;
		//	std::cout << " a : " << inputs[0] << "  " << a << std::endl;
		//	std::cout << "<b : " << inputs[1] << "  " << b << std::endl;
		//	std::cout << "exp: " << c << std::endl;
		//	std::cout << "act: " << output[0] << "   " << cc << std::endl;


		//	cir = lib.int_int_subtract(inExMod, inExMod, std::max(inExMod, inExMod));
		//	output.clear();
		//	output.emplace_back(std::max(inExMod, inExMod));

		//	cir->evaluate(inputs, output);

		//	std::cout << "act: " << output[0] << "   " << cc << std::endl;


		//	//throw UnitTestFail();
		//}



	}


}