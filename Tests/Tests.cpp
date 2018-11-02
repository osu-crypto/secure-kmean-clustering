#include "Tests.h"
#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Network/Endpoint.h>
#include <cryptoTools/Network/IOService.h>
#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Matrix.h>
#include <cryptoTools/Common/MatrixView.h>
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




	void programLessThan22(std::array<Party, 2> parties, i64 myInput1, i64 myInput2, u64 bitCount, int expLt)
	{

		auto input01 = parties[0].isLocalParty() ?  //x1
			parties[0].input<sInt>(myInput1, bitCount) :
			parties[0].input<sInt>(bitCount);

		auto input11 = parties[1].isLocalParty() ? //x2
			parties[1].input<sInt>(myInput1, bitCount) :
			parties[1].input<sInt>(bitCount);

		auto input02 = parties[0].isLocalParty() ? //y1
			parties[0].input<sInt>(myInput2, bitCount) :
			parties[0].input<sInt>(bitCount);

		auto input12 = parties[1].isLocalParty() ? //y2
			parties[1].input<sInt>(myInput2, bitCount) :
			parties[1].input<sInt>(bitCount);

		auto input0 = input01 + input11;
		auto input1 = input02 + input12;


		auto lt = input0 < input1;
		auto minus = input0 - input1;

		parties[0].reveal(input0);
		parties[0].reveal(input1);
		parties[0].reveal(lt);
		parties[0].reveal(minus);
		parties[1].getRuntime().processesQueue();

#if 1
		if (parties[0].isLocalParty())
		{

			auto ltVal = lt.getValue();

			bool passed = expLt == ltVal;
			std::cout << "eval:\n"
				<< "    x  = " << input0.getValue() << "\n"
				<< "    y  = " << input1.getValue() << "\n"
				<< "    lt = " << ltVal << "\n"
				<< " minus = " << minus.getValue() << "\n --------------" << std::endl;
			if (passed)
				std::cout << Color::Green << "    Passed " << ColorDefault << std::endl;
			else
				std::cout << Color::Red << "    Failed " << ColorDefault << std::endl;

		}

		if (parties[1].isLocalParty())
		{
			//std::cout << i << ": lt= " << lt.getValue() << " vs " << invert.getValue() << std::endl;
			//ostreamLock(std::cout) << i << ": slt= " << int(myOutput[2 * i]) << int(myOutput[2 * i + 1]) << "    B\n";// << (*v1->mLabels)[0] << std::endl;
		}
#endif



	}





	void programLessThan223(std::array<Party, 2> parties, i64 myInput1, u64 bitCount, int expLt)
	{

		auto input01 = parties[0].isLocalParty() ?  //x1
			parties[0].input<sInt>(myInput1, bitCount) :
			parties[0].input<sInt>(bitCount);

		auto input11 = parties[1].isLocalParty() ? //x2
			parties[1].input<sInt>(myInput1, bitCount) :
			parties[1].input<sInt>(bitCount);

		auto lt = input01 < input11;
		auto minus = input01 - input11;

		parties[0].reveal(lt);
		parties[0].reveal(minus);
		parties[1].getRuntime().processesQueue();

#if 1
		if (parties[0].isLocalParty())
		{

			auto ltVal = lt.getValue();

			bool passed = expLt == ltVal;
			std::cout << "eval:\n"
				<< "    lt = " << ltVal << "\n"
				<< " minus = " << minus.getValue() << "\n --------------" << std::endl;
			if (passed)
				std::cout << Color::Green << "    Passed " << ColorDefault << std::endl;
			else
				std::cout << Color::Red << "    Failed " << ColorDefault << std::endl;

		}

		if (parties[1].isLocalParty())
		{
			//std::cout << i << ": lt= " << lt.getValue() << " vs " << invert.getValue() << std::endl;
			//ostreamLock(std::cout) << i << ": slt= " << int(myOutput[2 * i]) << int(myOutput[2 * i + 1]) << "    B\n";// << (*v1->mLabels)[0] << std::endl;
		}
#endif



	}



	template<typename T>
	T signExtend(T v, u64 b, bool print = false)
	{
		if (b > sizeof(T) * 8)
			throw RTE_LOC;

		if (b == sizeof(T) * 8)
			return v;

		T loc = (T(1) << (b - 1));
		T sign = v & loc;

		if (sign)
		{
			T mask = T(-1) << (b);
			auto ret = v | mask;
			if (print)
			{

				std::cout << "sign: " << BitVector((u8*)&sign, sizeof(T) * 8) << std::endl;;
				std::cout << "mask: " << BitVector((u8*)&mask, sizeof(T) * 8) << std::endl;;
				std::cout << "v   : " << BitVector((u8*)&v, sizeof(T) * 8) << std::endl;;
				std::cout << "ret : " << BitVector((u8*)&ret, sizeof(T) * 8) << std::endl;;

			}
			return ret;
		}
		else
		{
			T mask = (T(1) << b) - 1;
			auto ret = v & mask;
			if (print)
			{

				std::cout << "sign: " << BitVector((u8*)&loc, sizeof(T) * 8) << std::endl;;
				std::cout << "mask: " << BitVector((u8*)&mask, sizeof(T) * 8) << std::endl;;
				std::cout << "v   : " << BitVector((u8*)&v, sizeof(T) * 8) << std::endl;;
				std::cout << "ret : " << BitVector((u8*)&ret, sizeof(T) * 8) << std::endl;;

			}
			return ret;
		}
	}



	void testCircuit()
	{
		Timer timer;
		IOService ios;
		Session ep01(ios, "127.0.0.1", SessionMode::Server);
		Session ep10(ios, "127.0.0.1", SessionMode::Client);
		Channel chl01 = ep01.addChannel();
		Channel chl10 = ep10.addChannel();

		int securityParams = 128;
		int inDimension = 1;
		int bitCount = 20;

		using Word = i32;
		PRNG prng(ZeroBlock);
		u64 numberTest = 10;



		ShGcRuntime rt0, rt1;
		std::array<Party, 2> parties0{
			Party(rt0, 0),
			Party(rt0, 1)
		};

		std::array<Party, 2> parties1{
			Party(rt1, 0),
			Party(rt1, 1)
		};

		std::thread thrd = std::thread([&]() {
			rt0.init(chl01, prng.get<block>(), ShGcRuntime::Evaluator, 1);;
		});
		rt1.init(chl10, prng.get<block>(), ShGcRuntime::Garbler, 0);

		thrd.join();

		std::vector<Word> xx(numberTest), x1(numberTest), x2(numberTest);
		std::vector<Word> yy(numberTest), y1(numberTest), y2(numberTest);
		for (i64 i = 0; i < numberTest; i++)
		{
			//xx[i] = 1000 + i;//p0.mPrng.get<Word>() % inMod;
			xx[i] = signExtend(prng.get<Word>(), bitCount);
			x1[i] = signExtend(prng.get<Word>(), bitCount);
			x2[i] = signExtend(xx[i] - x1[i], bitCount);

			yy[i] = signExtend(2000 + i, bitCount); // p0.mPrng.get<Word>() % inMod;
			y1[i] = signExtend(prng.get<Word>(), bitCount);
			y2[i] = signExtend(yy[i] - y1[i], bitCount);

		}

		for (i64 i = 0; i < numberTest; i++)
		{

			auto exp = int(xx[i] < yy[i]);

			std::cout << "trial: " << i << "\n"
				<< "  x   = " << xx[i] << " = ( " << x1[i] << ", " << x2[i] << ")  " << (x1[i] + x2[i]) << "\n"
				<< "  y   = " << yy[i] << " = ( " << y1[i] << ", " << y2[i] << ")  " << (y1[i] + y2[i]) << "\n"
				<< "  exp = " << exp << std::endl;

			thrd = std::thread([&]() {
				programLessThan22(parties0, x1[i], y1[i], bitCount, exp);
			});

			programLessThan22(parties1, x2[i], y2[i], bitCount, exp);

			thrd.join();

		}


		std::cout << " ==================\n";

		for (i64 i = 0; i < numberTest; i++)
		{
			Word diff1 = signExtend(x1[i] - y1[i], bitCount);
			Word diff2= signExtend(y2[i] - x2[i], bitCount);
			auto exp = int(xx[i] < yy[i]);

			std::cout << "trial: " << i << "\n"
				<< "  x   = " << xx[i] << " = ( " << x1[i] << ", " << x2[i] << ")  " << (x1[i] + x2[i]) << "\n"
				<< "  y   = " << yy[i] << " = ( " << y1[i] << ", " << y2[i] << ")  " << (y1[i] + y2[i]) << "\n"
				<< "  exp = " << exp << std::endl;

			thrd = std::thread([&]() {
				programLessThan223(parties0, diff1, bitCount, exp);
			});

			programLessThan223(parties1, diff2, bitCount, exp);

			thrd.join();

		}

		//	std::cout << "================programDiv==================\n";
		//
		//	for (i64 i = 0; i < numberTest; i++)
		//	{
		//		std::cout << xx[i] << "/" << yy[i] << " = " << (xx[i] / yy[i]) << "  Expected\n";
		//	}
		//
		//	thrd = std::thread([&]() {
		//		for (i64 i = 0; i < numberTest; i++)
		//			programDiv(parties0, x1[i], y1[i], inExMod);
		//	});
		//
		//	for (i64 i = 0; i < numberTest; i++)
		//		programDiv(parties1, x2[i], y2[i], inExMod);
		//
		//	thrd.join();
	}




	void programLessThan22_o(std::array<Party, 2> parties, i64 myInput1, i64 myInput2, u64 bitCount)
	{

			auto input01 = parties[0].isLocalParty() ?  //x1
				parties[0].input<sInt>(myInput1, bitCount) :
				parties[0].input<sInt>(bitCount);

			auto input11 = parties[1].isLocalParty() ? //x2
				parties[1].input<sInt>(myInput1, bitCount) :
				parties[1].input<sInt>(bitCount);

			auto input02 = parties[0].isLocalParty() ? //y1
				parties[0].input<sInt>(myInput2, bitCount) :
				parties[0].input<sInt>(bitCount);

			auto input12 = parties[1].isLocalParty() ? //y2
				parties[1].input<sInt>(myInput2, bitCount) :
				parties[1].input<sInt>(bitCount);

			auto input0 = input01 + input11;
			auto input1 = input02 + input12;

			

			auto lt = input0 < input1; 
			parties[0].reveal(input0);
			parties[0].reveal(input1);
			parties[0].reveal(lt);
			parties[1].getRuntime().processesQueue();

#if 1
			if (parties[0].isLocalParty())
			{
				std::cout << IoStream::lock;
				std::cout << input0.getValue() << " < " << input1.getValue() << ": " << lt.getValue() << " --------------\n";
				std::cout << IoStream::unlock;

			}

			if (parties[1].isLocalParty())
			{
				//std::cout << i << ": lt= " << lt.getValue() << " vs " << invert.getValue() << std::endl;
				//ostreamLock(std::cout) << i << ": slt= " << int(myOutput[2 * i]) << int(myOutput[2 * i + 1]) << "    B\n";// << (*v1->mLabels)[0] << std::endl;
			}
#endif



	}


	void programDiv_o(std::array<Party, 2> parties, i64 myInput1, i64 myInput2, u64 bitCount)
	{

		auto input01 = parties[0].isLocalParty() ?  //x1
			parties[0].input<sInt>(myInput1, bitCount) :
			parties[0].input<sInt>(bitCount);

		auto input11 = parties[1].isLocalParty() ? //x2
			parties[1].input<sInt>(myInput1, bitCount) :
			parties[1].input<sInt>(bitCount);

		auto input02 = parties[0].isLocalParty() ? //y1
			parties[0].input<sInt>(myInput2, bitCount) :
			parties[0].input<sInt>(bitCount);

		auto input12 = parties[1].isLocalParty() ? //y2
			parties[1].input<sInt>(myInput2, bitCount) :
			parties[1].input<sInt>(bitCount);

		auto input0 = input01 + input11;
		auto input1 = input02 + input12;



		auto div = input0 / input1;
		parties[0].reveal(input0);
		parties[0].reveal(input1);
		parties[0].reveal(div);
		parties[1].getRuntime().processesQueue();

#if 1
		if (parties[0].isLocalParty())
		{
			std::cout << IoStream::lock;
			std::cout << input0.getValue() << "/" << input1.getValue() << "=" << div.getValue() << " --------------\n";
			std::cout << IoStream::unlock;

		}

		if (parties[1].isLocalParty())
		{
			//std::cout << i << ": lt= " << lt.getValue() << " vs " << invert.getValue() << std::endl;
			//ostreamLock(std::cout) << i << ": slt= " << int(myOutput[2 * i]) << int(myOutput[2 * i + 1]) << "    B\n";// << (*v1->mLabels)[0] << std::endl;
		}
#endif



	}




	void programLessThan3(std::array<Party, 2> parties, std::vector<i64>& myInput1, std::vector<i64>& myInput2, BitVector& myOutput, u64 bitCount)
	{

		myOutput.resize(2 * myInput1.size());

		for (u64 i = 0; i < myInput1.size(); i++)
		{
			auto input01 = parties[0].isLocalParty() ?
				parties[0].input<sInt>(myInput1[i], bitCount) :
				parties[0].input<sInt>(bitCount);

			auto input11 = parties[1].isLocalParty() ?
				parties[1].input<sInt>(myInput1[i], bitCount) :
				parties[1].input<sInt>(bitCount);

			auto input02 = parties[0].isLocalParty() ?
				parties[0].input<sInt>(myInput2[i], bitCount) :
				parties[0].input<sInt>(bitCount);

			auto input12 = parties[1].isLocalParty() ?
				parties[1].input<sInt>(myInput2[i], bitCount) :
				parties[1].input<sInt>(bitCount);

			auto input0 = input01 + input11;
			auto input1 = input02 + input12;

			auto lt = (input01 + input11) < (input02 + input12); //NOTE: YES is 1, NO is 0

			auto invert = ~lt;

			parties[0].reveal(input0);
			parties[0].reveal(input1);
			parties[0].reveal(lt);
			parties[0].reveal(invert);
			parties[1].getRuntime().processesQueue();

			ShGcInt * v = static_cast<ShGcInt*>(lt.mData.get());
			ShGcInt * v1 = static_cast<ShGcInt*>(invert.mData.get());
			myOutput[2 * i] = PermuteBit((*v->mLabels)[0]);//YES=10, NO=01
			myOutput[2 * i + 1] = PermuteBit((*v1->mLabels)[0]); //YES=10, NO=01

		

#if 1
			if (parties[0].isLocalParty())
			{
				std::cout << IoStream::lock;
				std::cout << i << ": slt= " << int(myOutput[2 * i]) << int(myOutput[2 * i + 1]) << "    A\n";// << (*v1->mLabels)[0] << std::endl;
				std::cout << i << ": final= " << lt.getValue() << " vs " << invert.getValue() << " \n--------------\n";
				std::cout << i << ": output= " << input0.getValue() << " vs " << input1.getValue() << " \n--------------\n";
				std::cout << IoStream::unlock;

			/*	if (input0.getValue() < input1.getValue())
					myOutput[2 * i] = 1;
				else
					myOutput[2 * i] = 0;*/

				//myOutput[2 * i + 1] = !myOutput[2 * i];
			}

			if (parties[1].isLocalParty())
			{
				//std::cout << i << ": lt= " << lt.getValue() << " vs " << invert.getValue() << std::endl;
				ostreamLock(std::cout) << i << ": slt= " << int(myOutput[2 * i]) << int(myOutput[2 * i + 1]) << "    B\n";// << (*v1->mLabels)[0] << std::endl;
			
				

			//	myOutput[2 * i + 1] = !myOutput[2 * i];
			
			}
#endif

		}


	}



	void programLessThan(std::array<Party, 2> parties, std::vector<i64>& myInput, BitVector& myOutput, u64 bitCount)
	{

		myOutput.resize(2 * myInput.size());

		for (u64 i = 0; i < myInput.size(); i++)
		{
			auto input0 = parties[0].isLocalParty() ?
				parties[0].input<sInt>(myInput[i], bitCount) :
				parties[0].input<sInt>(bitCount);

			auto input1 = parties[1].isLocalParty() ?
				parties[1].input<sInt>(myInput[i], bitCount) :
				parties[1].input<sInt>(bitCount);

			auto lt = input0 < input1; //NOTE: YES is 0, NO is 1

			auto invert = ~lt;

			parties[0].reveal(lt);
			parties[0].reveal(invert);
			parties[1].getRuntime().processesQueue();

			ShGcInt * v = static_cast<ShGcInt*>(lt.mData.get());
			ShGcInt * v1 = static_cast<ShGcInt*>(invert.mData.get());
			myOutput[2 * i] = PermuteBit((*v1->mLabels)[0]); //YES=10, NO=01
			myOutput[2 * i + 1] = PermuteBit((*v->mLabels)[0]);

#if 1
			if (parties[0].isLocalParty())
			{
				ostreamLock(std::cout) << i << ": slt= " << int(myOutput[2 * i]) << int(myOutput[2 * i + 1]) << "    A\n";// << (*v1->mLabels)[0] << std::endl;
				std::cout << i << ": final= " << invert.getValue() << " vs " << lt.getValue() << " \n--------------\n";

			}

			if (parties[1].isLocalParty())
			{
				//std::cout << i << ": lt= " << lt.getValue() << " vs " << invert.getValue() << std::endl;
				ostreamLock(std::cout) << i << ": slt= " << int(myOutput[2 * i]) << int(myOutput[2 * i + 1]) << "    B\n";// << (*v1->mLabels)[0] << std::endl;
			}
#endif

		}


	}


	//void testCircuit_o()
	//{
	//	Timer timer;
	//	IOService ios;
	//	Session ep01(ios, "127.0.0.1", SessionMode::Server);
	//	Session ep10(ios, "127.0.0.1", SessionMode::Client);
	//	Channel chl01 = ep01.addChannel();
	//	Channel chl10 = ep10.addChannel();

	//	int securityParams = 128;
	//	int inDimension = 1;
	//	int inExMod = 20;

	//	int inMod = pow(2, inExMod);
	//	PRNG prng(ZeroBlock);
	//	u64 numberTest = 10;
	//

	//	std::vector<Word> xx(numberTest), x1(numberTest), x2(numberTest);
	//	std::vector<Word> yy(numberTest), y1(numberTest), y2(numberTest);
	//	for (i64 i = 0; i < numberTest; i++)
	//	{
	//		//xx[i] = 1000 + i;//p0.mPrng.get<Word>() % inMod;
	//		xx[i] = signExtend1(prng.get<Word>(), inExMod);
	//		x1[i] = signExtend1(prng.get<Word>(), inExMod);
	//		x2[i] = signExtend1((xx[i]-x1[i]), inExMod);

	//		yy[i] = 2000 + i; // p0.mPrng.get<Word>() % inMod;
	//		y1[i] = signExtend1(prng.get<Word>(), inExMod);
	//		y2[i] = signExtend1((yy[i] - y1[i]), inExMod);

	//		if(xx[i] < yy[i])
	//			std::cout << xx[i] << "<" << yy[i]<< ": 1 Expected\n";
	//		else
	//			std::cout << xx[i] << "<" << yy[i] << ": 0 Expected\n";

	//	}

	//	ShGcRuntime rt0, rt1;
	//	std::array<Party, 2> parties0{
	//		Party(rt0, 0),
	//		Party(rt0, 1)
	//	};

	//	std::array<Party, 2> parties1{
	//		Party(rt1, 0),
	//		Party(rt1, 1)
	//	};

	//	std::thread thrd = std::thread([&]() {
	//		rt0.init(chl01, prng.get<block>(), ShGcRuntime::Evaluator, 1);;
	//	});
	//	rt1.init(chl10, prng.get<block>(), ShGcRuntime::Garbler, 0);

	//	thrd.join();

	//	thrd = std::thread([&]() {
	//		for (i64 i = 0; i < numberTest; i++)
	//			programLessThan22(parties0, x1[i], y1[i], inExMod);
	//	});


	//	for (i64 i = 0; i < numberTest; i++)
	//		programLessThan22(parties1, x2[i], y2[i], inExMod);

	//	thrd.join();


	//	std::cout <<"================programDiv==================\n";

	//	for (i64 i = 0; i < numberTest; i++)
	//	{
	//			std::cout << xx[i] << "/" << yy[i] << " = " <<  (xx[i] / yy[i])<<"  Expected\n";
	//	}

	///*	thrd = std::thread([&]() {
	//		for (i64 i = 0; i < numberTest; i++)
	//			programDiv(parties0, x1[i], y1[i], inExMod);
	//	});

	//	for (i64 i = 0; i < numberTest; i++)
	//		programDiv(parties1, x2[i], y2[i], inExMod);*/

	//	thrd.join();
	//}

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

			numA = prng.get<i32>() % radixM;
			numB = prng.get<i32>() % radixM;// prng.get<i32>();;
			auto bitsA = numA.getBinary();
			//auto bitsB = numA.getBinary();

			std::cout << numA.get() << " " << numB.get() << "  " << bitsA << std::endl;

			u32 sA = 0, sB = 0;
			for (u64 i = 0; i < bitsA.size(); i++)
			{

				baseSend[i][0] = (prng.get<u32>() + radixM) % radixM;
				baseSend[i][1] = (u32)(numB.mVal*pow(2, i) + baseSend[i][0]) % radixM;
				baseRecv[i] = baseSend[i][bitsA[i]];
				auto mi = (u32)((u32)numB.mVal*bitsA[i] * pow(2, i) + baseSend[i][0]) % radixM;
				std::cout << "  " << bitsA[i] << "  " << baseRecv[i] << "  " << baseSend[i][0] << "  " << baseSend[i][1] << std::endl;
				std::cout << "mi  " << mi << "\n";
				//std::cout << "mi  " << (u32)numB.mVal << "\n";
				sA += baseRecv[i];
				sB += baseSend[i][0];


			}
			sB = (0 - sB) % radixM;
			u32 sum = (sA + sB) % radixM;
			u32 sum2 = (numA.mVal*numB.mVal) % radixM;


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
			auto bitsA = getBinary(numA, bitLen);
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

	void loadTxtFile(const std::string & fileName, int mDimension, std::vector<std::vector<i64>>& inputA, std::vector<std::vector<i64>>& inputB)
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

			if (mDimension != results.size())
			{
				std::cout << "inDimension!= results.size()" << results.size() << std::endl;
				throw std::runtime_error(LOCATION);
			}

			for (size_t i = 0; i < results.size(); i++)
				idata[i] = stoi(results[i]);

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

		std::cout << inputA.size() << " \t " << inputB.size() << "\n";

		for (size_t i = 0; i < inputA.size(); i++)
		{
			for (int j = 0; j < inputA[i].size(); j++)
				std::cout << inputA[i][j] << " ";

			std::cout << "\n ";
		}
	}




	void DistTest()
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
		u64 inNumCluster = 3;


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


		for (u64 i = inNumCluster / 2; i < inNumCluster; i++)
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


		//=======================online MUL===============================
#pragma region MUL


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
		thrd.join();
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
				i64 ourDist = (p0.mDist[i][k] + p1.mDist[i][k]) % (i64)pow(p0.mMod, 1);

				if (expectedDist != ourDist)
				{
					std::cout << i << "-" << k << ": ";
					std::cout << p0.mDist[i][k] << " + " << p1.mDist[i][k] << " = " << ourDist << " vs ";
					std::cout << expectedDist << "\n";

					for (u64 d = 0; d < p0.mDimension; d++)
					{
						std::cout << points[i][d] << " vs " << (p0.mSharePoint[i][d].mArithShare + p1.mSharePoint[i][d].mArithShare) % p0.mMod << "= " << p0.mSharePoint[i][d].mArithShare << " + " << p1.mSharePoint[i][d].mArithShare << " p \n";
						std::cout << clusters[k][d] << "= " << p0.mShareCluster[k][d] << " + " << p1.mShareCluster[k][d] << " c \n";
						Word diff2p0 = (p0.mSharePoint[i][d].mArithShare - p0.mShareCluster[k][d]) % p0.mMod;
						Word diff2p1 = (p1.mSharePoint[i][d].mArithShare - p1.mShareCluster[k][d]) % p0.mMod;

						Word secondtermp0 = (p0.mProdPointPPC[i][d][k] - p0.mProdPointPC[i][d][k] + p0.mProdCluster[k][d]) % p0.mMod;
						Word secondtermp1 = (p1.mProdPointPPC[i][d][k] - p1.mProdPointPC[i][d][k] + p1.mProdCluster[k][d]) % p0.mMod;

						std::cout << diff2p0 << " * " << diff2p1 << " = " << (diff2p0*diff2p1) % (p0.mMod) << " \n";
						std::cout << secondtermp1 << " + " << secondtermp0 << " = " << (secondtermp1 + secondtermp0) % (p0.mMod) << " \n";



						/*	Word distP0 = (Word)(pow(diff2p0, 2) + 2 * secondtermp0) % (i64)pow(p0.mMod, 2);
						Word distP1 = (Word)(pow(diff2p1, 2) + 2 * secondtermp1) % (i64)pow(p0.mMod, 2);

						std::cout << diff2p0 << " vs " << secondtermp0 << ": " << distP0 << " p0\n";
						std::cout << diff2p1 << " vs " << secondtermp1 << ": " << distP1 << " p1\n";*/


					}



					throw std::exception();
				}
			}
#endif
		std::cout << " ------ED done-------\n";
#pragma endregion


		timer.setTimePoint("OTkeysDone");

		p0.Print();
		p1.Print();





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
		u64 inNumCluster = 3;


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


		for (u64 i = inNumCluster / 2; i < inNumCluster; i++)
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


		//=======================online MUL===============================
#pragma region MUL


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
		thrd.join();
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
				i64 ourDist = (p0.mDist[i][k] + p1.mDist[i][k]) % (i64)pow(p0.mMod, 1);

				if (expectedDist != ourDist)
				{
					std::cout << i << "-" << k << ": ";
					std::cout << p0.mDist[i][k] << " + " << p1.mDist[i][k] << " = " << ourDist << " vs ";
					std::cout << expectedDist << "\n";

					for (u64 d = 0; d < p0.mDimension; d++)
					{
						std::cout << points[i][d] << " vs " << (p0.mSharePoint[i][d].mArithShare + p1.mSharePoint[i][d].mArithShare) % p0.mMod << "= " << p0.mSharePoint[i][d].mArithShare << " + " << p1.mSharePoint[i][d].mArithShare << " p \n";
						std::cout << clusters[k][d] << "= " << p0.mShareCluster[k][d] << " + " << p1.mShareCluster[k][d] << " c \n";
						Word diff2p0 = (p0.mSharePoint[i][d].mArithShare - p0.mShareCluster[k][d]) % p0.mMod;
						Word diff2p1 = (p1.mSharePoint[i][d].mArithShare - p1.mShareCluster[k][d]) % p0.mMod;

						Word secondtermp0 = (p0.mProdPointPPC[i][d][k] - p0.mProdPointPC[i][d][k] + p0.mProdCluster[k][d]) % p0.mMod;
						Word secondtermp1 = (p1.mProdPointPPC[i][d][k] - p1.mProdPointPC[i][d][k] + p1.mProdCluster[k][d]) % p0.mMod;

						std::cout << diff2p0 << " * " << diff2p1 << " = " << (diff2p0*diff2p1) % (p0.mMod) << " \n";
						std::cout << secondtermp1 << " + " << secondtermp0 << " = " << (secondtermp1 + secondtermp0) % (p0.mMod) << " \n";



						/*	Word distP0 = (Word)(pow(diff2p0, 2) + 2 * secondtermp0) % (i64)pow(p0.mMod, 2);
							Word distP1 = (Word)(pow(diff2p1, 2) + 2 * secondtermp1) % (i64)pow(p0.mMod, 2);

							std::cout << diff2p0 << " vs " << secondtermp0 << ": " << distP0 << " p0\n";
							std::cout << diff2p1 << " vs " << secondtermp1 << ": " << distP1 << " p1\n";*/


					}



					throw std::exception();
				}
			}
#endif
		std::cout << " ------ED done-------\n";
#pragma endregion

		//=======================online closet cluster===============================
		
#if 1
		thrd = std::thread([&]() { //party 1
			int stepIdxMin = 1;
			u64 numNodeThisLevel = p0.mNumCluster;
			std::vector<Word> lastNode(p0.mTotalNumPoints); //[i][#cluster-1]
			BitVector oneBit("1");
			std::vector<std::vector<Word>> outShareSend, outShareRecv;
			std::vector<std::vector<BitVector>> outIdxShareSend, outIdxShareRecv;

			//=================1st level //TODO: remove dist
			for (u64 i = 0; i < p0.mTotalNumPoints; i++)
			{
				if (numNodeThisLevel % 2) //odd number
					lastNode[i] = p0.mDist[i][p0.mNumCluster - 1];

				std::vector<i64> dist1(numNodeThisLevel / 2), dist2(numNodeThisLevel / 2);
				for (u64 k = 0; k < dist1.size(); k++)
				{
					memcpy((u8*)&dist1[k], (u8*)&p0.mDist[i][2 * k], sizeof(Word));
					memcpy((u8*)&dist2[k], (u8*)&p0.mDist[i][2 * k + 1], sizeof(Word));					
				}
				
				programLessThan3(p0.parties, dist1, dist2, p0.mVecGcMinOutput[i], p0.mLenMod);

				p0.mVecIdxMin[i].append(p0.mVecGcMinOutput[i]);
				if (numNodeThisLevel % 2) //odd number
					p0.mVecIdxMin[i].append(oneBit); //make sure last vecIdxMin[i]=1 

			}

			p0.amortBinArithMulsend(outShareSend, p0.mVecGcMinOutput, p0.mDist); //(b^A \xor b^B)*(P^A)
			p0.amortBinArithMULrecv(outShareRecv, p0.mVecGcMinOutput); //(b^A \xor b^B)*(P^B)
			p0.computeShareMin(outShareSend, outShareRecv);//compute (b1^A \xor b1^B)*(P1^A+P1^B)+(b2^A \xor b2^B)*(P2^A+P2^B)

			if (numNodeThisLevel % 2 == 1) //odd number => add last node to this level
				for (u64 i = 0; i < p0.mTotalNumPoints; i++)
					p0.mShareMin[i].push_back(lastNode[i]);


			std::cout << IoStream::lock;
			for (u64 i = 0; i < p0.mTotalNumPoints; i++)
				std::cout << i << "-" << stepIdxMin << " mVecIdxMin: " << p0.mVecIdxMin[i] << "    A\n";
			std::cout << IoStream::unlock;

			//=============2nd level loop until root==================================
			while (p0.mShareMin[0].size()>1)
			{
				stepIdxMin *= 2;

				ostreamLock(std::cout) << "p0.mShareMin[0].size()=" << p0.mShareMin[0].size() << "\n";

				numNodeThisLevel = p0.mShareMin[0].size();

				for (u64 i = 0; i < p0.mTotalNumPoints; i++)
				{
					if (numNodeThisLevel % 2) //odd number, keep last for next level
						lastNode[i] = p0.mShareMin[i][p0.mShareMin[i].size() - 1];
					
					std::vector<i64> dist1(numNodeThisLevel / 2), dist2(numNodeThisLevel / 2);
					for (u64 k = 0; k < dist1.size(); k++)
					{
						memcpy((u8*)&dist1[k], (u8*)&p0.mShareMin[i][2 * k], sizeof(Word));
						memcpy((u8*)&dist2[k], (u8*)&p0.mShareMin[i][2 * k + 1], sizeof(Word));
					}
					programLessThan3(p0.parties, dist1, dist2, p0.mVecGcMinOutput[i], p0.mLenMod);
				}

				p0.amortBinArithMulGCsend(outShareSend, outIdxShareSend, p0.mVecGcMinOutput, p0.mShareMin, p0.mVecIdxMin, stepIdxMin); //(b^A \xor b^B)*(P^A)
				p0.amortBinArithMulGCrecv(outShareRecv, outIdxShareRecv, p0.mVecGcMinOutput, stepIdxMin); //(b^A \xor b^B)*(P^B)
				p0.computeShareMin(outShareSend, outShareRecv);//compute (b1^A \xor b1^B)*(P1^A+P1^B)+(b2^A \xor b2^B)*(P2^A+P2^B)
				p0.computeShareIdxMin(outIdxShareSend, outIdxShareRecv);

				/*std::cout << IoStream::lock;
				for (u64 i = 0; i < p0.mTotalNumPoints; i++)
				std::cout << i << "-" << stepIdxMin << " mVecIdxMin: " << p0.mVecIdxMin[i] << "    bp A\n";
				std::cout << IoStream::unlock;*/

				if (numNodeThisLevel % 2 == 1) //odd number => add last node to this level
					for (u64 i = 0; i < p0.mTotalNumPoints; i++)
						p0.mShareMin[i].push_back(lastNode[i]);


				std::cout << IoStream::lock;
				for (u64 i = 0; i < p0.mTotalNumPoints; i++)
					std::cout << i << "-" << stepIdxMin << " mVecIdxMin: " << p0.mVecIdxMin[i] << "    A\n";
				std::cout << IoStream::unlock;
			}


		});
		//party 2
		int stepIdxMin = 1;
		u64 numNodeThisLevel = p1.mNumCluster;
		BitVector zeroBit("0");
		std::vector<Word> lastNode(p1.mTotalNumPoints); //[i][#cluster-1]
														//=================1st level //TODO: remove dist
		std::vector<std::vector<Word>> outShareSend, outShareRecv;
		std::vector<std::vector<BitVector>> outIdxShareSend, outIdxShareRecv;

		for (u64 i = 0; i < p1.mTotalNumPoints; i++)
		{
			if (numNodeThisLevel % 2) //odd number
				lastNode[i] = p1.mDist[i][p1.mNumCluster - 1];

			std::vector<i64> dist1(numNodeThisLevel / 2), dist2(numNodeThisLevel / 2);
			for (u64 k = 0; k < dist1.size(); k++)
			{
				memcpy((u8*)&dist1[k], (u8*)&p1.mDist[i][2 * k], sizeof(Word));
				memcpy((u8*)&dist2[k], (u8*)&p1.mDist[i][2 * k + 1], sizeof(Word));
			}
			programLessThan3(p1.parties, dist1, dist2, p1.mVecGcMinOutput[i], p1.mLenMod);

			p1.mVecIdxMin[i].append(p1.mVecGcMinOutput[i]);//first level 10||01||01||01|1
			if (numNodeThisLevel % 2) //odd number
				p1.mVecIdxMin[i].append(zeroBit); //make sure last vecIdxMin[i]=1 

		}

		p1.amortBinArithMULrecv(outShareRecv, p1.mVecGcMinOutput); //(b^A \xor b^B)*(P^A)
		p1.amortBinArithMulsend(outShareSend, p1.mVecGcMinOutput, p1.mDist); //(b^A \xor b^B)*(P^B)
		p1.computeShareMin(outShareSend, outShareRecv); //compute (b1^A \xor b1^B)*(P1^A+P1^B)+(b2^A \xor b2^B)*(P2^A+P2^B)

		if (numNodeThisLevel % 2 == 1) //odd number => add last node to this level
			for (u64 i = 0; i < p1.mTotalNumPoints; i++)
				p1.mShareMin[i].push_back(lastNode[i]);


		std::cout << IoStream::lock;
		for (u64 i = 0; i < p0.mTotalNumPoints; i++)
			std::cout << i << "-" << stepIdxMin << " mVecIdxMin: " << p1.mVecIdxMin[i] << "    B\n";
		std::cout << IoStream::unlock;

		//=============2nd level loop until root==================================



		while (p1.mShareMin[0].size()>1)
		{
			stepIdxMin *= 2;

			ostreamLock(std::cout) << "p1.mShareMin[0].size()=" << p1.mShareMin[0].size() << "\n";

			numNodeThisLevel = p1.mShareMin[0].size();

			for (u64 i = 0; i < p1.mTotalNumPoints; i++)
			{
				if (numNodeThisLevel % 2) //odd number, keep last for next level
					lastNode[i] = p1.mShareMin[i][p1.mShareMin[i].size() - 1];

				std::vector<i64> dist1(numNodeThisLevel / 2), dist2(numNodeThisLevel / 2);
				for (u64 k = 0; k < dist1.size(); k++)
				{
					memcpy((u8*)&dist1[k], (u8*)&p1.mShareMin[i][2 * k], sizeof(Word));
					memcpy((u8*)&dist2[k], (u8*)&p1.mShareMin[i][2 * k + 1], sizeof(Word));
				}
				programLessThan3(p1.parties, dist1, dist2, p1.mVecGcMinOutput[i], p1.mLenMod);

			}

			if (p1.mShareMin[1].size() == 2) //near root
			{
				std::cout << IoStream::lock;
				std::cout << p1.mVecGcMinOutput[1] << " ========= mVecGcMinOutput r==========\n";
				std::cout << IoStream::unlock;
			}

			p1.amortBinArithMulGCrecv(outShareRecv, outIdxShareRecv, p1.mVecGcMinOutput, stepIdxMin); //(b^A \xor b^B)*(P^A)
			p1.amortBinArithMulGCsend(outShareSend, outIdxShareSend, p1.mVecGcMinOutput, p1.mShareMin, p1.mVecIdxMin, stepIdxMin); //(b^A \xor b^B)*(P^B)
			p1.computeShareMin(outShareSend, outShareRecv); //compute (b1^A \xor b1^B)*(P1^A+P1^B)+(b2^A \xor b2^B)*(P2^A+P2^B)
			p1.computeShareIdxMin(outIdxShareSend, outIdxShareRecv);


			/*std::cout << IoStream::lock;
			for (u64 i = 0; i < p0.mTotalNumPoints; i++)
			std::cout << i << "-" << stepIdxMin << " mVecIdxMin: " << p1.mVecIdxMin[i] << "    bp B\n";
			std::cout << IoStream::unlock;*/

			if (numNodeThisLevel % 2 == 1) //odd number => add last node to this level
				for (u64 i = 0; i < p1.mTotalNumPoints; i++)
					p1.mShareMin[i].push_back(lastNode[i]);



			std::cout << IoStream::lock;
			for (u64 i = 0; i < p0.mTotalNumPoints; i++)
				std::cout << i << "-" << stepIdxMin << " mVecIdxMin: " << p1.mVecIdxMin[i] << "    B\n";
			std::cout << IoStream::unlock;
		}

		ostreamLock(std::cout) << "p1.mShareMin[0].size()=" << p1.mShareMin[0].size() << " end\n";

		thrd.join();

#endif



#if 0
		for (u64 i = 0; i < p0.mTotalNumPoints; i++)
		{
			Word minDist = (p0.mShareMin[i][0] + p1.mShareMin[i][0]) % p0.mMod;
			BitVector vecDist = p0.mVecIdxMin[i] ^ p1.mVecIdxMin[i];

			u64 minIdx;

			for (u64 k = 0; k < vecDist.size(); k++)
				if (vecDist[k] == 1)
				{
					minIdx = k;
					break;
				}

			Word actualMin = (p0.mDist[i][0] + p1.mDist[i][0]) % p0.mMod;
			Word actualMinIdx = 0;
			for (u64 k = 1; k < p0.mNumCluster; k++)
			{
				Word point = (p0.mDist[i][k] + p1.mDist[i][k]) % p0.mMod;
				if (actualMin > point)
				{
					actualMin = point;
					actualMinIdx = k;
				}
				//std::cout << point << " ";
			}

			if (actualMin != minDist || actualMinIdx != minIdx)
			{
				std::cout << i << ": min= " << minDist << " "
					<< vecDist << " idx= " << minIdx << "\n";

				std::cout << actualMin << " " << actualMinIdx << "\t ";


				for (u64 k = 0; k < p0.mNumCluster; k++)
				{
					Word point = (p0.mDist[i][k] + p1.mDist[i][k]) % p0.mMod;
					std::cout << point << " ";
				}

				throw std::exception();

			}
		}

#endif

		for (u64 i = 0; i < p0.mTotalNumPoints; i++)
		{
			std::cout << i << ": min=";
			for (u64 k = 0; k < p0.mShareMin[i].size(); k++)
			{
				Word minDist = (p0.mShareMin[i][k] + p1.mShareMin[i][k]) % p0.mMod;
				std::cout << minDist << " ";
			}
			BitVector vecDist = p0.mVecIdxMin[i] ^ p1.mVecIdxMin[i];
			std::cout << vecDist << " ";


			std::cout << " \t vs \t ";

			for (u64 k = 0; k < p0.mNumCluster; k++)
			{
				Word point = (p0.mDist[i][k] + p1.mDist[i][k]) % p0.mMod;
				std::cout << point << " ";
			}
			std::cout << "\n";
		}


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


		for (u64 i = inNumCluster / 2; i < inNumCluster; i++)
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
		std::cout << p0.mSendAllOtKeys.size() << " = " << p0.mChoiceAllBitSharePoints.size() << " ====\n";


		for (u64 i = 0; i < p0.mSendAllOtKeys.size(); i++)
		{
			std::cout << p1.mSendAllOtKeys[i][0]
				<< " vs " << p1.mSendAllOtKeys[i][1] << "\t";

			std::cout << p0.mRecvAllOtKeys[i] << " vs "
				<< p0.mChoiceAllBitSharePoints[i] << "\n";
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
						<< p0.mSharePoint[i][j].mBitShare[l] << " ttt\n";

					idx++;
				}
				std::cout << "============\n";
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
		block* plaintexts1 = new block[10];
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

	void testMinDistFirstLevel()
	{
		Timer timer; IOService ios;
		Session ep01(ios, "127.0.0.1", SessionMode::Server); Session ep10(ios, "127.0.0.1", SessionMode::Client);
		Channel chl01 = ep01.addChannel(); Channel chl10 = ep10.addChannel();

		u64 securityParams = 128, inDimension = 1, inExMod = 20, inNumCluster = 7;

		int inMod = pow(2, inExMod);
		std::vector<std::vector<Word>> inputA, inputB;
		//loadTxtFile("I:/kmean-impl/dataset/s1.txt", inDimension, inputA, inputB);

		PRNG prng(ZeroBlock);
		u64 numberTest = 4;
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

				//std::cout << inputA[i][j] << "\t" << inputB[i][j] << " p\n";
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

#if 0
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


		for (u64 i = inNumCluster / 2; i < inNumCluster; i++)
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

		//fake dist
		for (u64 i = 0; i < p0.mTotalNumPoints; i++)
			for (u64 k = 0; k < p0.mNumCluster; k++)
			{
				u64 num = rand() % 10;
				p0.mDist[i][k] = prng.get<Word>() % p0.mMod;
				p1.mDist[i][k] = prng.get<Word>() % p0.mMod;;
				std::cout << num << ":" << p0.mDist[i][k] << " + " << p1.mDist[i][k] << " = " << (p0.mDist[i][k] + p1.mDist[i][k]) % p0.mMod << " dist\n";

			}



		bool debug = false;

		u64 numLeaveGC = p0.mNumCluster / 2;

		/*	u64 idxPoint = 0;

		for (u64 k = 0; k < p0.mNumCluster; k++)
		std::cout  << p0.mDist[idxPoint][k] << " + " << p1.mDist[idxPoint][k] << " = " << (p0.mDist[idxPoint][k] + p1.mDist[idxPoint][k]) % p0.mMod << " dist\n";*/

		//TODO: case for odd #cluster

		std::vector<std::vector<Word>> outShareSend0, outShareRecv0;
		std::vector<std::vector<Word>> outShareSend1, outShareRecv1;


		thrd = std::thread([&]() { //party 1



			for (u64 i = 0; i < p0.mTotalNumPoints; i++)
			{
				std::vector<i64> dist1(numLeaveGC), dist2(numLeaveGC);
				for (u64 k = 0; k < numLeaveGC; k++)
				{
					memcpy((u8*)&dist1[k], (u8*)&p0.mDist[i][2 * k], sizeof(Word));
					memcpy((u8*)&dist2[k], (u8*)&p0.mDist[i][2 * k+1], sizeof(Word));

					//std::cout << IoStream::lock;
					////for (u64 j = 0; j < dist1.size(); j++)
					//{
					//	std::cout << dist1[k] << "   diff1A\n";
					//	std::cout << dist2[k] << "   diff2A\n";
					//}
					//std::cout << IoStream::unlock;

				}

				programLessThan3(p0.parties, dist1, dist2, p0.mVecGcMinOutput[i], p0.mLenMod);
			}

			//p0.amortBinArithMulsend(outShareSend0, p0.mVecGcMinOutput, p0.mDist); //(b^A \xor b^B)*(P^A)
			//p0.amortBinArithMULrecv(outShareRecv0, p0.mVecGcMinOutput); //(b^A \xor b^B)*(P^B)
			//p0.computeShareMin(outShareSend0, outShareRecv0);//compute (b1^A \xor b1^B)*(P1^A+P1^B)+(b2^A \xor b2^B)*(P2^A+P2^B)

		});
		std::vector<std::vector<Word>> outShareSend, outShareRecv;

		for (u64 i = 0; i < p0.mTotalNumPoints; i++)
		{

			std::vector<i64> dist1(numLeaveGC), dist2(numLeaveGC);
			for (u64 k = 0; k < numLeaveGC; k++)
			{
				memcpy((u8*)&dist1[k], (u8*)&p1.mDist[i][2 * k], sizeof(Word));
				memcpy((u8*)&dist2[k], (u8*)&p1.mDist[i][2 * k + 1], sizeof(Word));
			}


			/*std::cout << IoStream::lock;
			for (u64 j = 0; j < diffDist.size(); j++)
			std::cout << diffDist[j] << "   diffDistB\n";
			std::cout << IoStream::unlock;*/

			programLessThan3(p1.parties, dist1, dist2, p1.mVecGcMinOutput[i], p1.mLenMod);


		}
		//party 2

		//p1.amortBinArithMULrecv(outShareSend1, p1.mVecGcMinOutput); //(b^A \xor b^B)*(P^A)
		//p1.amortBinArithMulsend(outShareRecv1, p1.mVecGcMinOutput, p1.mDist); //(b^A \xor b^B)*(P^B)
		//p1.computeShareMin(outShareSend1, outShareRecv1); //compute (b1^A \xor b1^B)*(P1^A+P1^B)+(b2^A \xor b2^B)*(P2^A+P2^B)

		thrd.join();

		//ostreamLock(std::cout) << p0.mVecGcMinOutput[0] << " bitv A\n";
		//ostreamLock(std::cout) << p1.mVecGcMinOutput[0] << " bitv B\n";

#if 1 //min GC
		for (u64 i = 0; i < p0.mTotalNumPoints; i++)
			for (u64 k = 0; k < numLeaveGC; k++)
			{
				i64 dist1 = (p0.mDist[i][2 * k] + p1.mDist[i][2 * k]) % p0.mMod;
				i64 dist2 = (p0.mDist[i][2 * k + 1] + p1.mDist[i][2 * k + 1]) % p0.mMod;
				if (dist1 < dist2)
				{
					u8 res1 = p0.mVecGcMinOutput[i][2 * k] ^ p1.mVecGcMinOutput[i][2 * k];
					u8 res2 = p0.mVecGcMinOutput[i][2 * k + 1] ^ p1.mVecGcMinOutput[i][2 * k + 1];
					if (res1 != 1 || res2 != 0)
					{
						std::cout << "GC wrong\n";
						std::cout << k << ": " << p0.mDist[i][2 * k] << " + " << p1.mDist[i][2 * k] << " = " << dist1 << "\n";
						std::cout << k << ": " << p0.mDist[i][2 * k+1] << " + " << p1.mDist[i][2 * k+1] <<" = "<<dist2 << "\n";
						std::cout << k << ": " << dist1 << " < " << dist2 << "\n";
						std::cout << k << ": " << p0.mVecGcMinOutput[i][2 * k] << "^" << p0.mVecGcMinOutput[i][2 * k] << "=" << int(res1) << "\n";
						std::cout << k << ": " << p0.mVecGcMinOutput[i][2 * k + 1] << "^" << p0.mVecGcMinOutput[i][2 * k + 1] << "=" << int(res2) << "\n";
						//throw std::exception();
					}
				}
			}
#endif

#if 1  //double check (b^A \xor b^B)*(P^A)
		for (u64 i = 0; i < p0.mVecGcMinOutput.size(); i++)
			for (u64 k = 0; k < p0.mVecGcMinOutput[i].size(); k++)
			{
				u8 b = p0.mVecGcMinOutput[i][k] ^ p1.mVecGcMinOutput[i][k];
				Word res1 = b*p0.mDist[i][k]; //(b^A \xor b^B)*(P^A)
				Word res2 = (outShareSend0[i][k] + outShareRecv1[i][k]) % p0.mMod;

				if (res1 != res2)
				{
					std::cout << i << " - " << k << ": ";
					std::cout << p0.mVecGcMinOutput[i][k] << " ^ " << p1.mVecGcMinOutput[i][k] << " = " << int(b) << "\n";
					std::cout << int(b) << " * " << p0.mDist[i][k] << " = " << res1 << "\n";
					std::cout << outShareSend0[i][k] << " + " << outShareRecv1[i][k] << " = " << res2 << "\n";
					//throw std::exception();
				}

				res1 = b*p1.mDist[i][k]; //(b^A \xor b^B)*(P^B)
				res2 = (outShareRecv0[i][k] + outShareSend1[i][k]) % p0.mMod;

				if (res1 != res2)
				{
					std::cout << i << " - " << k << ": ";
					std::cout << p0.mVecGcMinOutput[i][k] << " ^ " << p1.mVecGcMinOutput[i][k] << " = " << int(b) << "\n";
					std::cout << int(b) << " * " << p1.mDist[i][k] << " = " << res1 << "\n";
					std::cout << outShareRecv0[i][k] << " + " << outShareSend1[i][k] << " = " << res2 << "\n";
					//throw std::exception();
				}
			}

#endif

#if 0 //double check (b1^A \xor b1^B)*(P1^A+P1^B)+(b2^A \xor b2^B)*(P2^A+P2^B)
		for (u64 i = 0; i < p0.mVecGcMinOutput.size(); i++)
			for (u64 k = 0; k < p0.mVecGcMinOutput[i].size() / 2; k++)
			{
				u8 b1 = p0.mVecGcMinOutput[i][2 * k] ^ p1.mVecGcMinOutput[i][2 * k];
				u8 b2 = p0.mVecGcMinOutput[i][2 * k + 1] ^ p1.mVecGcMinOutput[i][2 * k + 1];
				Word point1 = (p0.mDist[i][2 * k] + p1.mDist[i][2 * k]) % p0.mMod;
				Word point2 = (p0.mDist[i][2 * k + 1] + p1.mDist[i][2 * k + 1]) % p0.mMod;
				Word res1 = (b1*point1 + b2*point2) % p0.mMod; //b1*p1+b2*p2
				Word res2 = (p0.mShareMin[i][k] + p1.mShareMin[i][k]) % p0.mMod;

				if (res1 != res2)
				{
					std::cout << i << " - " << k << ":  ";
					std::cout << int(b1) << " ^ " << int(b2) << " = " << int(b1^b2) << "\n";
					std::cout << int(b1) << " * " << point1 << " + " << int(b2) << " * " << point2 << " = " << res1 << "\n";
					std::cout << p0.mShareMin[i][k] << " + " << p1.mShareMin[i][k] << " = " << res2 << " \t mShareMin\n";
					throw std::exception();
				}

				//if(point1<point2) //min=poin1
				//if (point1 != res1)
				{
					std::cout << i << " - " << k << ":  " << point1 << " vs " << point2 << ":  " << res1 << "\n";
					//throw std::exception();
				}
			}
#endif



		timer.setTimePoint("OTkeysDone");




		//p0.Print();
		//p1.Print();





	}


	void testMinDistFirstLevel_old ()
	{
		Timer timer; IOService ios;
		Session ep01(ios, "127.0.0.1", SessionMode::Server); Session ep10(ios, "127.0.0.1", SessionMode::Client);
		Channel chl01 = ep01.addChannel(); Channel chl10 = ep10.addChannel();

		u64 securityParams = 128, inDimension = 1, inExMod = 20, inNumCluster = 7;

		int inMod = pow(2, inExMod);
		std::vector<std::vector<Word>> inputA, inputB;
		//loadTxtFile("I:/kmean-impl/dataset/s1.txt", inDimension, inputA, inputB);

		PRNG prng(ZeroBlock);
		u64 numberTest = 4;
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

				//std::cout << inputA[i][j] << "\t" << inputB[i][j] << " p\n";
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

#if 0
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


		for (u64 i = inNumCluster / 2; i < inNumCluster; i++)
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

		//fake dist
		for (u64 i = 0; i < p0.mTotalNumPoints; i++)
			for (u64 k = 0; k < p0.mNumCluster; k++)
			{
				u64 num = rand() % 10;
				p0.mDist[i][k] = prng.get<Word>() % p0.mMod;
				p1.mDist[i][k] = (num - p0.mDist[i][k]) % p0.mMod;;
				std::cout << num << ":" << p0.mDist[i][k] << " + " << p1.mDist[i][k] << " = " << (p0.mDist[i][k] + p1.mDist[i][k]) % p0.mMod << " dist\n";

			}



		bool debug = false;

		u64 numLeaveGC = p0.mNumCluster / 2;

		/*	u64 idxPoint = 0;

			for (u64 k = 0; k < p0.mNumCluster; k++)
				std::cout  << p0.mDist[idxPoint][k] << " + " << p1.mDist[idxPoint][k] << " = " << (p0.mDist[idxPoint][k] + p1.mDist[idxPoint][k]) % p0.mMod << " dist\n";*/

				//TODO: case for odd #cluster

		std::vector<std::vector<Word>> outShareSend0, outShareRecv0;
		std::vector<std::vector<Word>> outShareSend1, outShareRecv1;


		thrd = std::thread([&]() { //party 1



			for (u64 i = 0; i < p0.mTotalNumPoints; i++)
			{
				std::vector<i64> diffDist;
				for (u64 k = 0; k < numLeaveGC; k++)
					diffDist.push_back(p0.mDist[i][2 * k] - p0.mDist[i][2 * k + 1]);

				//std::cout << IoStream::lock;
				//for (u64 j = 0; j < diffDist.size(); j++)
				//	std::cout << diffDist[j] << "   diffDistA\n";
				//std::cout << IoStream::unlock;

				programLessThan(p0.parties, diffDist, p0.mVecGcMinOutput[i], p0.mLenMod);
			}

			p0.amortBinArithMulsend(outShareSend0,p0.mVecGcMinOutput, p0.mDist); //(b^A \xor b^B)*(P^A)
			p0.amortBinArithMULrecv(outShareRecv0, p0.mVecGcMinOutput); //(b^A \xor b^B)*(P^B)
			p0.computeShareMin(outShareSend0, outShareRecv0);//compute (b1^A \xor b1^B)*(P1^A+P1^B)+(b2^A \xor b2^B)*(P2^A+P2^B)

		});
		std::vector<std::vector<Word>> outShareSend, outShareRecv;

		for (u64 i = 0; i < p0.mTotalNumPoints; i++)
		{
			std::vector<i64> diffDist;

			for (u64 k = 0; k < numLeaveGC; k++)
				diffDist.push_back(p1.mDist[i][2 * k + 1] - p1.mDist[i][2 * k]);


			/*std::cout << IoStream::lock;
			for (u64 j = 0; j < diffDist.size(); j++)
				std::cout << diffDist[j] << "   diffDistB\n";
			std::cout << IoStream::unlock;*/

			programLessThan(p1.parties, diffDist, p1.mVecGcMinOutput[i], p1.mLenMod);


		}
		//party 2

		p1.amortBinArithMULrecv(outShareSend1,p1.mVecGcMinOutput); //(b^A \xor b^B)*(P^A)
		p1.amortBinArithMulsend(outShareRecv1,p1.mVecGcMinOutput, p1.mDist); //(b^A \xor b^B)*(P^B)
		p1.computeShareMin(outShareSend1, outShareRecv1); //compute (b1^A \xor b1^B)*(P1^A+P1^B)+(b2^A \xor b2^B)*(P2^A+P2^B)

		thrd.join();

		//ostreamLock(std::cout) << p0.mVecGcMinOutput[0] << " bitv A\n";
		//ostreamLock(std::cout) << p1.mVecGcMinOutput[0] << " bitv B\n";

#if 1 //min GC
		for (u64 i = 0; i < p0.mTotalNumPoints; i++)
			for (u64 k = 0; k < numLeaveGC; k++)
			{
				i64 dist1 = (p0.mDist[i][2 * k] + p1.mDist[i][2 * k]) % p0.mMod;
				i64 dist2 = (p0.mDist[i][2 * k + 1] + p1.mDist[i][2 * k + 1]) % p0.mMod;
				if (dist1 < dist2)
				{
					u8 res1 = p0.mVecGcMinOutput[i][2 * k] ^ p1.mVecGcMinOutput[i][2 * k];
					u8 res2 = p0.mVecGcMinOutput[i][2 * k + 1] ^ p1.mVecGcMinOutput[i][2 * k + 1];
					if (res1 != 1 || res2 != 0)
					{
						std::cout << "GC wrong\n";
						std::cout << k << ": " << dist1 << " < " << dist2 << "\n";
						std::cout << k << ": " << p0.mVecGcMinOutput[i][2 * k] << "^" << p0.mVecGcMinOutput[i][2 * k] << "=" << int(res1) << "\n";
						std::cout << k << ": " << p0.mVecGcMinOutput[i][2 * k + 1] << "^" << p0.mVecGcMinOutput[i][2 * k + 1] << "=" << int(res2) << "\n";
						throw std::exception();
					}
				}
			}
#endif

#if 0  //double check (b^A \xor b^B)*(P^A)
		for (u64 i = 0; i < p0.mVecGcMinOutput.size(); i++)
			for (u64 k = 0; k < p0.mVecGcMinOutput[i].size(); k++)
			{
				u8 b = p0.mVecGcMinOutput[i][k] ^ p1.mVecGcMinOutput[i][k];
				Word res1 = b*p0.mDist[i][k]; //(b^A \xor b^B)*(P^A)
				Word res2 = (outShareSend0[i][k] + outShareRecv1[i][k]) % p0.mMod;

				if (res1 != res2)
				{
					std::cout << i << " - " << k << ": ";
					std::cout << p0.mVecGcMinOutput[i][k] << " ^ " << p1.mVecGcMinOutput[i][k] << " = " << int(b) << "\n";
					std::cout << int(b) << " * " << p0.mDist[i][k] << " = " << res1 << "\n";
					std::cout << outShareSend0[i][k] << " + " << outShareRecv1[i][k] << " = " << res2 << "\n";
					throw std::exception();
				}

				res1 = b*p1.mDist[i][k]; //(b^A \xor b^B)*(P^B)
				res2 = (outShareRecv0[i][k] + outShareSend1[i][k]) % p0.mMod;

				if (res1 != res2)
				{
					std::cout << i << " - " << k << ": ";
					std::cout << p0.mVecGcMinOutput[i][k] << " ^ " << p1.mVecGcMinOutput[i][k] << " = " << int(b) << "\n";
					std::cout << int(b) << " * " << p1.mDist[i][k] << " = " << res1 << "\n";
					std::cout << outShareRecv0[i][k] << " + " << outShareSend1[i][k] << " = " << res2 << "\n";
					throw std::exception();
				}
			}
	
#endif

#if 1 //double check (b1^A \xor b1^B)*(P1^A+P1^B)+(b2^A \xor b2^B)*(P2^A+P2^B)
				for (u64 i = 0; i < p0.mVecGcMinOutput.size(); i++)
					for (u64 k = 0; k < p0.mVecGcMinOutput[i].size()/2; k++)
					{
						u8 b1 = p0.mVecGcMinOutput[i][2 * k] ^ p1.mVecGcMinOutput[i][2 * k];
						u8 b2 = p0.mVecGcMinOutput[i][2*k+1] ^ p1.mVecGcMinOutput[i][2*k+1];
						Word point1 = (p0.mDist[i][2 * k] + p1.mDist[i][2 * k]) % p0.mMod;
						Word point2 = (p0.mDist[i][2 * k+1] + p1.mDist[i][2 * k+1]) % p0.mMod;
						Word res1 = (b1*point1 + b2*point2) % p0.mMod; //b1*p1+b2*p2
						Word res2 = (p0.mShareMin[i][k] + p1.mShareMin[i][k]) % p0.mMod;

						if (res1 != res2)
						{
							std::cout << i << " - " << k << ":  ";
							std::cout << int(b1) << " ^ " << int(b2) << " = " << int(b1^b2) << "\n";
							std::cout <<  int(b1) << " * " << point1 <<" + " <<int(b2) << " * " << point2 << " = " << res1 << "\n";
							std::cout << p0.mShareMin[i][k] << " + " << p1.mShareMin[i][k] << " = " << res2 << " \t mShareMin\n";
							throw std::exception();
						}

						//if(point1<point2) //min=poin1
							//if (point1 != res1)
							{
								std::cout << i << " - " << k << ":  " << point1 << " vs " << point2 << ":  " << res1 <<"\n";
								//throw std::exception();
							}
					}
#endif



				timer.setTimePoint("OTkeysDone");




				//p0.Print();
				//p1.Print();





			}

	void testMinDist_o()
			{
				Timer timer; IOService ios;
				Session ep01(ios, "127.0.0.1", SessionMode::Server); Session ep10(ios, "127.0.0.1", SessionMode::Client);
				Channel chl01 = ep01.addChannel(); Channel chl10 = ep10.addChannel();

				u64 securityParams = 128, inDimension = 1, inExMod = 20, inNumCluster = 4;

				int inMod = pow(2, inExMod);
				std::vector<std::vector<Word>> inputA, inputB;
				//loadTxtFile("I:/kmean-impl/dataset/s1.txt", inDimension, inputA, inputB);

				PRNG prng(ZeroBlock);
				u64 numberTest = 2;
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

						//std::cout << inputA[i][j] << "\t" << inputB[i][j] << " p\n";
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

#if 0
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


				for (u64 i = inNumCluster / 2; i < inNumCluster; i++)
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

				//fake dist
				u64 num = 99;
				u64 num2 = 1;
				for (u64 i = 0; i < p0.mTotalNumPoints; i++)
					for (u64 k = 0; k < p0.mNumCluster; k++)
					{
						if (i % 2)
						{	num = rand() % 1000;
							p0.mDist[i][k] = prng.get<Word>() % p0.mMod;
							p1.mDist[i][k] = (num - p0.mDist[i][k]) % p0.mMod;;
							std::cout << num << ":" << p0.mDist[i][k] << " + " << p1.mDist[i][k] << " = " << (p0.mDist[i][k] + p1.mDist[i][k]) % p0.mMod << " dist\n";
							num--;
						}
						else
						{	num2 = rand() % 1000;
							p0.mDist[i][k] = prng.get<Word>() % p0.mMod;
							p1.mDist[i][k] = prng.get<Word>() % p0.mMod;;
							std::cout << num << ":" << p0.mDist[i][k] << " + " << p1.mDist[i][k] << " = " << (p0.mDist[i][k] + p1.mDist[i][k]) % p0.mMod << " dist\n";
							num2++;
						}
					}

				//41 467 334 500 169 724 478 358 962 464
				thrd = std::thread([&]() { //party 1
					int stepIdxMin = 1;
					u64 numNodeThisLevel = p0.mNumCluster;
					std::vector<Word> lastNode(p0.mTotalNumPoints); //[i][#cluster-1]
					BitVector oneBit("1");
					std::vector<std::vector<Word>> outShareSend, outShareRecv;
					std::vector<std::vector<BitVector>> outIdxShareSend, outIdxShareRecv;



					//=================1st level //TODO: remove dist
					for (u64 i = 0; i < p0.mTotalNumPoints; i++)
					{
						if (numNodeThisLevel % 2) //odd number
							lastNode[i] = p0.mDist[i][p0.mNumCluster - 1];

						std::vector<i64> diffDist; //lastNode move to next level
						for (u64 k = 0; k < numNodeThisLevel / 2; k++)
							diffDist.push_back((p0.mDist[i][2 * k] - p0.mDist[i][2 * k + 1])%p0.mMod);

						std::cout << IoStream::lock;
						if (i == 0) //
						{
							std::cout << p0.mDist[i][0] << " " << p0.mDist[i][1] << " d="<<diffDist[0]<<  " mShareMin s\n";

							/*std::cout << i << "===================\n";
							for (u64 j = 0; j < diffDist.size(); j++)
								std::cout << diffDist[j] << "   diffDistA\n";*/
						}
						std::cout << IoStream::unlock;



						programLessThan(p0.parties, diffDist, p0.mVecGcMinOutput[i], p0.mLenMod);
						p0.mVecIdxMin[i].append(p0.mVecGcMinOutput[i]);

						if (numNodeThisLevel % 2) //odd number
							p0.mVecIdxMin[i].append(oneBit); //make sure last vecIdxMin[i]=1 

					}

					p0.amortBinArithMulsend(outShareSend,p0.mVecGcMinOutput, p0.mDist); //(b^A \xor b^B)*(P^A)
					p0.amortBinArithMULrecv(outShareRecv,p0.mVecGcMinOutput); //(b^A \xor b^B)*(P^B)
					p0.computeShareMin(outShareSend, outShareRecv);//compute (b1^A \xor b1^B)*(P1^A+P1^B)+(b2^A \xor b2^B)*(P2^A+P2^B)

					if (numNodeThisLevel % 2 == 1) //odd number => add last node to this level
						for (u64 i = 0; i < p0.mTotalNumPoints; i++)
							p0.mShareMin[i].push_back(lastNode[i]);


					std::cout << IoStream::lock;
					for (u64 i = 0; i < p0.mTotalNumPoints; i++)
						std::cout << i << "-" << stepIdxMin << " mVecIdxMin: " << p0.mVecIdxMin[i] << "    A\n";
					std::cout << IoStream::unlock;

					//=============2nd level loop until root==================================
					while (p0.mShareMin[0].size()>1)
					{
						stepIdxMin *= 2;

						ostreamLock(std::cout) << "p0.mShareMin[0].size()=" << p0.mShareMin[0].size() << "\n";

						numNodeThisLevel = p0.mShareMin[0].size();

						for (u64 i = 0; i < p0.mTotalNumPoints; i++)
						{
							if (numNodeThisLevel % 2) //odd number, keep last for next level
								lastNode[i] = p0.mShareMin[i][p0.mShareMin[i].size() - 1];
							std::vector<i64> diffDist;
							for (u64 k = 0; k < numNodeThisLevel / 2; k++)
								diffDist.push_back((p0.mShareMin[i][2 * k] - p0.mShareMin[i][2 * k + 1]) % p0.mMod);

							std::cout << IoStream::lock;
							if (p0.mShareMin[1].size() == 3 && i==0) //
							{
								std::cout << p0.mShareMin[i][0] << " " << p0.mShareMin[i][1] << " mShareMin s\n";

								std::cout << i << "===================\n";
								for (u64 j = 0; j < diffDist.size(); j++)
									std::cout << diffDist[j] << "   diffDistA\n";
							}
							std::cout << IoStream::unlock;



							programLessThan(p0.parties, diffDist, p0.mVecGcMinOutput[i], p0.mLenMod);
						}


						if (p0.mShareMin[1].size() == 2) //near root
						{
							std::cout << IoStream::lock;
							std::cout << p0.mVecGcMinOutput[1] << " =========mVecGcMinOutput[i]==========\n";
							std::cout << IoStream::unlock;
						}

						p0.amortBinArithMulGCsend(outShareSend, outIdxShareSend, p0.mVecGcMinOutput, p0.mShareMin, p0.mVecIdxMin, stepIdxMin); //(b^A \xor b^B)*(P^A)
						p0.amortBinArithMulGCrecv(outShareRecv, outIdxShareRecv, p0.mVecGcMinOutput, stepIdxMin); //(b^A \xor b^B)*(P^B)
						p0.computeShareMin(outShareSend, outShareRecv);//compute (b1^A \xor b1^B)*(P1^A+P1^B)+(b2^A \xor b2^B)*(P2^A+P2^B)
						p0.computeShareIdxMin(outIdxShareSend, outIdxShareRecv);

						/*std::cout << IoStream::lock;
						for (u64 i = 0; i < p0.mTotalNumPoints; i++)
							std::cout << i << "-" << stepIdxMin << " mVecIdxMin: " << p0.mVecIdxMin[i] << "    bp A\n";
						std::cout << IoStream::unlock;*/

						if (numNodeThisLevel % 2 == 1) //odd number => add last node to this level
							for (u64 i = 0; i < p0.mTotalNumPoints; i++)
								p0.mShareMin[i].push_back(lastNode[i]);


						std::cout << IoStream::lock;
						for (u64 i = 0; i < p0.mTotalNumPoints; i++)
							std::cout << i << "-" << stepIdxMin << " mVecIdxMin: " << p0.mVecIdxMin[i] << "    A\n";
						std::cout << IoStream::unlock;
					}


				});
				//party 2 60512 1	 745463 60512 532159 1040128 
				int stepIdxMin = 1;
				u64 numNodeThisLevel = p1.mNumCluster;
				BitVector zeroBit("0");
				std::vector<Word> lastNode(p1.mTotalNumPoints); //[i][#cluster-1]
																//=================1st level //TODO: remove dist
				std::vector<std::vector<Word>> outShareSend, outShareRecv;
				std::vector<std::vector<BitVector>> outIdxShareSend, outIdxShareRecv;

				for (u64 i = 0; i < p1.mTotalNumPoints; i++)
				{
					if (numNodeThisLevel % 2) //odd number
						lastNode[i] = p1.mDist[i][p1.mNumCluster - 1];

					std::vector<i64> diffDist; //lastNode move to next level
					for (u64 k = 0; k < numNodeThisLevel / 2; k++)
						diffDist.push_back((p1.mDist[i][2 * k + 1] - p1.mDist[i][2 * k]) % p0.mMod);

					std::cout << IoStream::lock;
					if (i == 0) //
					{
						std::cout << p1.mDist[i][0] << " " << p1.mDist[i][1] << " d=" << diffDist[0] << " mShareMin r\n";

						/*std::cout << i << "===================\n";
						for (u64 j = 0; j < diffDist.size(); j++)
						std::cout << diffDist[j] << "   diffDistA\n";*/
					}
					std::cout << IoStream::unlock;

					programLessThan(p1.parties, diffDist, p1.mVecGcMinOutput[i], p1.mLenMod);

					p1.mVecIdxMin[i].append(p1.mVecGcMinOutput[i]);//first level 10||01||01||01|1
					if (numNodeThisLevel % 2) //odd number
						p1.mVecIdxMin[i].append(zeroBit); //make sure last vecIdxMin[i]=1 

				}

				p1.amortBinArithMULrecv(outShareRecv,p1.mVecGcMinOutput); //(b^A \xor b^B)*(P^A)
				p1.amortBinArithMulsend(outShareSend,p1.mVecGcMinOutput, p1.mDist); //(b^A \xor b^B)*(P^B)
				p1.computeShareMin(outShareSend,outShareRecv); //compute (b1^A \xor b1^B)*(P1^A+P1^B)+(b2^A \xor b2^B)*(P2^A+P2^B)

				if (numNodeThisLevel % 2 == 1) //odd number => add last node to this level
					for (u64 i = 0; i < p1.mTotalNumPoints; i++)
						p1.mShareMin[i].push_back(lastNode[i]);


				std::cout << IoStream::lock;
				for (u64 i = 0; i < p0.mTotalNumPoints; i++)
					std::cout << i << "-" << stepIdxMin << " mVecIdxMin: " << p1.mVecIdxMin[i] << "    B\n";
				std::cout << IoStream::unlock;
				
				//=============2nd level loop until root==================================

				
				
				while(p1.mShareMin[0].size()>1)
				{
					stepIdxMin *= 2;

					ostreamLock(std::cout) << "p1.mShareMin[0].size()=" << p1.mShareMin[0].size() << "\n";

					numNodeThisLevel = p1.mShareMin[0].size();

					for (u64 i = 0; i < p1.mTotalNumPoints; i++)
					{
						if (numNodeThisLevel % 2) //odd number, keep last for next level
							lastNode[i] = p1.mShareMin[i][p1.mShareMin[i].size() - 1];

						std::vector<i64> diffDist;
						for (u64 k = 0; k < numNodeThisLevel / 2; k++)
							diffDist.push_back((p1.mShareMin[i][2 * k + 1] - p1.mShareMin[i][2 * k]) % p0.mMod);

						std::cout << IoStream::lock;
						if (p1.mShareMin[1].size() == 3 && i == 0) //
						{
							std::cout << p1.mShareMin[i][0] << " " << p1.mShareMin[i][1] << " mShareMin r\n";

							std::cout << i << "===================\n";
							for (u64 j = 0; j < diffDist.size(); j++)
								std::cout << diffDist[j] << "   diffDistB\n";
						}
						std::cout << IoStream::unlock;
						programLessThan(p1.parties, diffDist, p1.mVecGcMinOutput[i], p1.mLenMod);
					}

					if (p1.mShareMin[1].size() == 2) //near root
					{
						std::cout << IoStream::lock;
						std::cout << p1.mVecGcMinOutput[1] << " ========= mVecGcMinOutput r==========\n";
						std::cout << IoStream::unlock;
					}

					p1.amortBinArithMulGCrecv(outShareRecv, outIdxShareRecv,p1.mVecGcMinOutput, stepIdxMin); //(b^A \xor b^B)*(P^A)
					p1.amortBinArithMulGCsend(outShareSend, outIdxShareSend,p1.mVecGcMinOutput, p1.mShareMin, p1.mVecIdxMin, stepIdxMin); //(b^A \xor b^B)*(P^B)
					p1.computeShareMin(outShareSend, outShareRecv); //compute (b1^A \xor b1^B)*(P1^A+P1^B)+(b2^A \xor b2^B)*(P2^A+P2^B)
					p1.computeShareIdxMin(outIdxShareSend, outIdxShareRecv);

					
					/*std::cout << IoStream::lock;
					for (u64 i = 0; i < p0.mTotalNumPoints; i++)
						std::cout << i << "-" << stepIdxMin << " mVecIdxMin: " << p1.mVecIdxMin[i] << "    bp B\n";
					std::cout << IoStream::unlock;*/

					if (numNodeThisLevel % 2 == 1) //odd number => add last node to this level
						for (u64 i = 0; i < p1.mTotalNumPoints; i++)
							p1.mShareMin[i].push_back(lastNode[i]);



					std::cout << IoStream::lock;
					for (u64 i = 0; i < p0.mTotalNumPoints; i++)
						std::cout << i << "-" << stepIdxMin << " mVecIdxMin: " << p1.mVecIdxMin[i] << "    B\n";
					std::cout << IoStream::unlock;
				}

				ostreamLock(std::cout) << "p1.mShareMin[0].size()=" << p1.mShareMin[0].size() << " end\n";

				thrd.join();




#if 0
				for (u64 i = 0; i < p0.mTotalNumPoints; i++)
				{
					Word minDist= (p0.mShareMin[i][0] + p1.mShareMin[i][0]) % p0.mMod;
					BitVector vecDist = p0.mVecIdxMin[i] ^ p1.mVecIdxMin[i];

					u64 minIdx;

					for (u64 k = 0; k < vecDist.size(); k++)
						if (vecDist[k] == 1)
						{
							minIdx = k;
							break;
						}

					Word actualMin = (p0.mDist[i][0] + p1.mDist[i][0]) % p0.mMod;
					Word actualMinIdx = 0;
					for (u64 k = 1; k < p0.mNumCluster; k++)
					{
						Word point = (p0.mDist[i][k] + p1.mDist[i][k]) % p0.mMod;
						if (actualMin > point)
						{
							actualMin = point;
							actualMinIdx = k;
						}
						//std::cout << point << " ";
					}

					if (actualMin != minDist || actualMinIdx != minIdx)
					{
						std::cout << i << ": min= " << minDist << " "
							<< vecDist << " idx= " << minIdx << "\n";

						std::cout << actualMin << " " << actualMinIdx <<"\t ";


						for (u64 k = 0; k < p0.mNumCluster; k++)
						{
							Word point = (p0.mDist[i][k] + p1.mDist[i][k]) % p0.mMod;
							std::cout << point << " ";
						}

						throw std::exception();

					}
				}

#endif
				for (u64 i = 0; i < p0.mTotalNumPoints; i++)
				{
					std::cout << i << ": min=";
					for (u64 k = 0; k < p0.mShareMin[i].size(); k++)
					{
						Word minDist = (p0.mShareMin[i][k] + p1.mShareMin[i][k]) % p0.mMod;
						std::cout << minDist << " ";
					}
					BitVector vecDist = p0.mVecIdxMin[i] ^ p1.mVecIdxMin[i];
					std::cout << vecDist << " ";


					std::cout << " \t vs \t ";

					for (u64 k = 0; k < p0.mNumCluster; k++)
					{
						Word point = (p0.mDist[i][k] + p1.mDist[i][k]) % p0.mMod;
						std::cout << point << " ";
					}
					std::cout << "\n";
				}




				timer.setTimePoint("OTkeysDone");

/*
				block data = p0.mPrng.get<block>();
				u64 aa1 = ((u64*)&data)[0];
				u64 aa2 = ((u64*)&data)[1];
				std::cout << data << "\n";
				std::cout << toBlock(aa1) << "\n";
				std::cout << toBlock(aa2) << "\n";*/



				//p0.Print();
				//p1.Print();





			}

	void testMinDist()
			{
				Timer timer; IOService ios;
				Session ep01(ios, "127.0.0.1", SessionMode::Server); Session ep10(ios, "127.0.0.1", SessionMode::Client);
				Channel chl01 = ep01.addChannel(); Channel chl10 = ep10.addChannel();

				u64 securityParams = 128, inDimension = 1, inExMod = 20, inNumCluster = 4;

				int inMod = pow(2, inExMod);
				std::vector<std::vector<Word>> inputA, inputB;
				//loadTxtFile("I:/kmean-impl/dataset/s1.txt", inDimension, inputA, inputB);

				PRNG prng(ZeroBlock);
				u64 numberTest = 2;
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

						//std::cout << inputA[i][j] << "\t" << inputB[i][j] << " p\n";
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

	

				//fake dist
				u64 num = 99;
				u64 num2 = 1;
				for (u64 i = 0; i < p0.mTotalNumPoints; i++)
					for (u64 k = 0; k < p0.mNumCluster; k++)
					{
						if (i % 2)
						{
							num = rand() % 1000;
							p0.mDist[i][k] = prng.get<Word>() % p0.mMod;
							p1.mDist[i][k] = (num - p0.mDist[i][k]) % p0.mMod;;
							std::cout << num << ":" << p0.mDist[i][k] << " + " << p1.mDist[i][k] << " = " << (p0.mDist[i][k] + p1.mDist[i][k]) % p0.mMod << " dist\n";
							num--;
						}
						else
						{
							num2 = rand() % 1000;
							p0.mDist[i][k] = prng.get<Word>() % p0.mMod;
							p1.mDist[i][k] = prng.get<Word>() % p0.mMod;;
							std::cout << num << ":" << p0.mDist[i][k] << " + " << p1.mDist[i][k] << " = " << (p0.mDist[i][k] + p1.mDist[i][k]) % p0.mMod << " dist\n";
							num2++;
						}
					}

				//41 467 334 500 169 724 478 358 962 464
				thrd = std::thread([&]() { //party 1
					int stepIdxMin = 1;
					u64 numNodeThisLevel = p0.mNumCluster;
					std::vector<Word> lastNode(p0.mTotalNumPoints); //[i][#cluster-1]
					BitVector oneBit("1");
					std::vector<std::vector<Word>> outShareSend, outShareRecv;
					std::vector<std::vector<BitVector>> outIdxShareSend, outIdxShareRecv;



					//=================1st level //TODO: remove dist
					for (u64 i = 0; i < p0.mTotalNumPoints; i++)
					{
						if (numNodeThisLevel % 2) //odd number
							lastNode[i] = p0.mDist[i][p0.mNumCluster - 1];

						//std::vector<i64> diffDist; //lastNode move to next level
						//for (u64 k = 0; k < numNodeThisLevel / 2; k++)
						//	diffDist.push_back((p0.mDist[i][2 * k] - p0.mDist[i][2 * k + 1]) % p0.mMod);

						
						std::vector<i64> dist1(numNodeThisLevel / 2), dist2(numNodeThisLevel / 2);
						for (u64 k = 0; k < dist1.size(); k++)
						{
							memcpy((u8*)&dist1[k], (u8*)&p0.mDist[i][2 * k], sizeof(Word));
							memcpy((u8*)&dist2[k], (u8*)&p0.mDist[i][2 * k + 1], sizeof(Word));
						}

						std::cout << IoStream::lock;
						if (i == 0) //
						{
							//std::cout << p0.mDist[i][0] << " " << p0.mDist[i][1] << " d=" << diffDist[0] << " mShareMin s\n";

							/*std::cout << i << "===================\n";
							for (u64 j = 0; j < diffDist.size(); j++)
							std::cout << diffDist[j] << "   diffDistA\n";*/
						}
						std::cout << IoStream::unlock;



						programLessThan3(p0.parties, dist1, dist2, p0.mVecGcMinOutput[i], p0.mLenMod);
						p0.mVecIdxMin[i].append(p0.mVecGcMinOutput[i]);

						if (numNodeThisLevel % 2) //odd number
							p0.mVecIdxMin[i].append(oneBit); //make sure last vecIdxMin[i]=1 

					}

					p0.amortBinArithMulsend(outShareSend, p0.mVecGcMinOutput, p0.mDist); //(b^A \xor b^B)*(P^A)
					p0.amortBinArithMULrecv(outShareRecv, p0.mVecGcMinOutput); //(b^A \xor b^B)*(P^B)
					p0.computeShareMin(outShareSend, outShareRecv);//compute (b1^A \xor b1^B)*(P1^A+P1^B)+(b2^A \xor b2^B)*(P2^A+P2^B)

					if (numNodeThisLevel % 2 == 1) //odd number => add last node to this level
						for (u64 i = 0; i < p0.mTotalNumPoints; i++)
							p0.mShareMin[i].push_back(lastNode[i]);


					std::cout << IoStream::lock;
					for (u64 i = 0; i < p0.mTotalNumPoints; i++)
						std::cout << i << "-" << stepIdxMin << " mVecIdxMin: " << p0.mVecIdxMin[i] << "    A\n";
					std::cout << IoStream::unlock;

					//=============2nd level loop until root==================================
					while (p0.mShareMin[0].size()>1)
					{
						stepIdxMin *= 2;

						ostreamLock(std::cout) << "p0.mShareMin[0].size()=" << p0.mShareMin[0].size() << "\n";

						numNodeThisLevel = p0.mShareMin[0].size();

						for (u64 i = 0; i < p0.mTotalNumPoints; i++)
						{
							if (numNodeThisLevel % 2) //odd number, keep last for next level
								lastNode[i] = p0.mShareMin[i][p0.mShareMin[i].size() - 1];
							
							
							std::vector<i64> dist1(numNodeThisLevel / 2), dist2(numNodeThisLevel / 2);
							for (u64 k = 0; k < dist1.size(); k++)
							{
								memcpy((u8*)&dist1[k], (u8*)&p0.mShareMin[i][2 * k], sizeof(Word));
								memcpy((u8*)&dist2[k], (u8*)&p0.mShareMin[i][2 * k + 1], sizeof(Word));
							}

							/*std::vector<i64> diffDist;
							for (u64 k = 0; k < numNodeThisLevel / 2; k++)
								diffDist.push_back((p0.mShareMin[i][2 * k] - p0.mShareMin[i][2 * k + 1]) % p0.mMod);*/

							std::cout << IoStream::lock;
							if (p0.mShareMin[1].size() == 3 && i == 0) //
							{
								std::cout << p0.mShareMin[i][0] << " " << p0.mShareMin[i][1] << " mShareMin s\n";

								std::cout << i << "===================\n";
								//for (u64 j = 0; j < diffDist.size(); j++)
								//	std::cout << diffDist[j] << "   diffDistA\n";
							}
							std::cout << IoStream::unlock;



							programLessThan3(p0.parties, dist1,dist2, p0.mVecGcMinOutput[i], p0.mLenMod);
						}


						if (p0.mShareMin[1].size() == 2) //near root
						{
							std::cout << IoStream::lock;
							std::cout << p0.mVecGcMinOutput[1] << " =========mVecGcMinOutput[i]==========\n";
							std::cout << IoStream::unlock;
						}

						p0.amortBinArithMulGCsend(outShareSend, outIdxShareSend, p0.mVecGcMinOutput, p0.mShareMin, p0.mVecIdxMin, stepIdxMin); //(b^A \xor b^B)*(P^A)
						p0.amortBinArithMulGCrecv(outShareRecv, outIdxShareRecv, p0.mVecGcMinOutput, stepIdxMin); //(b^A \xor b^B)*(P^B)
						p0.computeShareMin(outShareSend, outShareRecv);//compute (b1^A \xor b1^B)*(P1^A+P1^B)+(b2^A \xor b2^B)*(P2^A+P2^B)
						p0.computeShareIdxMin(outIdxShareSend, outIdxShareRecv);

						/*std::cout << IoStream::lock;
						for (u64 i = 0; i < p0.mTotalNumPoints; i++)
						std::cout << i << "-" << stepIdxMin << " mVecIdxMin: " << p0.mVecIdxMin[i] << "    bp A\n";
						std::cout << IoStream::unlock;*/

						if (numNodeThisLevel % 2 == 1) //odd number => add last node to this level
							for (u64 i = 0; i < p0.mTotalNumPoints; i++)
								p0.mShareMin[i].push_back(lastNode[i]);


						std::cout << IoStream::lock;
						for (u64 i = 0; i < p0.mTotalNumPoints; i++)
							std::cout << i << "-" << stepIdxMin << " mVecIdxMin: " << p0.mVecIdxMin[i] << "    A\n";
						std::cout << IoStream::unlock;
					}


				});
				//party 2 60512 1	 745463 60512 532159 1040128 
				int stepIdxMin = 1;
				u64 numNodeThisLevel = p1.mNumCluster;
				BitVector zeroBit("0");
				std::vector<Word> lastNode(p1.mTotalNumPoints); //[i][#cluster-1]
																//=================1st level //TODO: remove dist
				std::vector<std::vector<Word>> outShareSend, outShareRecv;
				std::vector<std::vector<BitVector>> outIdxShareSend, outIdxShareRecv;

				for (u64 i = 0; i < p1.mTotalNumPoints; i++)
				{
					if (numNodeThisLevel % 2) //odd number
						lastNode[i] = p1.mDist[i][p1.mNumCluster - 1];

					//std::vector<i64> diffDist; //lastNode move to next level
					//for (u64 k = 0; k < numNodeThisLevel / 2; k++)
					//	diffDist.push_back((p1.mDist[i][2 * k + 1] - p1.mDist[i][2 * k]) % p0.mMod);

					std::vector<i64> dist1(numNodeThisLevel / 2), dist2(numNodeThisLevel / 2);
					for (u64 k = 0; k < dist1.size(); k++)
					{
						memcpy((u8*)&dist1[k], (u8*)&p1.mDist[i][2 * k], sizeof(Word));
						memcpy((u8*)&dist2[k], (u8*)&p1.mDist[i][2 * k + 1], sizeof(Word));
					}


					std::cout << IoStream::lock;
					if (i == 0) //
					{
						//std::cout << p1.mDist[i][0] << " " << p1.mDist[i][1] << " d=" << diffDist[0] << " mShareMin r\n";

						/*std::cout << i << "===================\n";
						for (u64 j = 0; j < diffDist.size(); j++)
						std::cout << diffDist[j] << "   diffDistA\n";*/
					}
					std::cout << IoStream::unlock;

					programLessThan3(p1.parties, dist1,dist2, p1.mVecGcMinOutput[i], p1.mLenMod);

					p1.mVecIdxMin[i].append(p1.mVecGcMinOutput[i]);//first level 10||01||01||01|1
					if (numNodeThisLevel % 2) //odd number
						p1.mVecIdxMin[i].append(zeroBit); //make sure last vecIdxMin[i]=1 

				}

				p1.amortBinArithMULrecv(outShareRecv, p1.mVecGcMinOutput); //(b^A \xor b^B)*(P^A)
				p1.amortBinArithMulsend(outShareSend, p1.mVecGcMinOutput, p1.mDist); //(b^A \xor b^B)*(P^B)
				p1.computeShareMin(outShareSend, outShareRecv); //compute (b1^A \xor b1^B)*(P1^A+P1^B)+(b2^A \xor b2^B)*(P2^A+P2^B)

				if (numNodeThisLevel % 2 == 1) //odd number => add last node to this level
					for (u64 i = 0; i < p1.mTotalNumPoints; i++)
						p1.mShareMin[i].push_back(lastNode[i]);


				std::cout << IoStream::lock;
				for (u64 i = 0; i < p0.mTotalNumPoints; i++)
					std::cout << i << "-" << stepIdxMin << " mVecIdxMin: " << p1.mVecIdxMin[i] << "    B\n";
				std::cout << IoStream::unlock;

				//=============2nd level loop until root==================================



				while (p1.mShareMin[0].size()>1)
				{
					stepIdxMin *= 2;

					ostreamLock(std::cout) << "p1.mShareMin[0].size()=" << p1.mShareMin[0].size() << "\n";

					numNodeThisLevel = p1.mShareMin[0].size();

					for (u64 i = 0; i < p1.mTotalNumPoints; i++)
					{
						if (numNodeThisLevel % 2) //odd number, keep last for next level
							lastNode[i] = p1.mShareMin[i][p1.mShareMin[i].size() - 1];

						/*std::vector<i64> diffDist;
						for (u64 k = 0; k < numNodeThisLevel / 2; k++)
							diffDist.push_back((p1.mShareMin[i][2 * k + 1] - p1.mShareMin[i][2 * k]) % p0.mMod);
*/
						std::vector<i64> dist1(numNodeThisLevel / 2), dist2(numNodeThisLevel / 2);
						for (u64 k = 0; k < dist1.size(); k++)
						{
							memcpy((u8*)&dist1[k], (u8*)&p1.mShareMin[i][2 * k], sizeof(Word));
							memcpy((u8*)&dist2[k], (u8*)&p1.mShareMin[i][2 * k + 1], sizeof(Word));
						}

						std::cout << IoStream::lock;
						if (p1.mShareMin[1].size() == 3 && i == 0) //
						{
							std::cout << p1.mShareMin[i][0] << " " << p1.mShareMin[i][1] << " mShareMin r\n";

							std::cout << i << "===================\n";
							//for (u64 j = 0; j < diffDist.size(); j++)
							//	std::cout << diffDist[j] << "   diffDistB\n";
						}
						std::cout << IoStream::unlock;
						programLessThan3(p1.parties, dist1,dist2, p1.mVecGcMinOutput[i], p1.mLenMod);
					}

					if (p1.mShareMin[1].size() == 2) //near root
					{
						std::cout << IoStream::lock;
						std::cout << p1.mVecGcMinOutput[1] << " ========= mVecGcMinOutput r==========\n";
						std::cout << IoStream::unlock;
					}

					p1.amortBinArithMulGCrecv(outShareRecv, outIdxShareRecv, p1.mVecGcMinOutput, stepIdxMin); //(b^A \xor b^B)*(P^A)
					p1.amortBinArithMulGCsend(outShareSend, outIdxShareSend, p1.mVecGcMinOutput, p1.mShareMin, p1.mVecIdxMin, stepIdxMin); //(b^A \xor b^B)*(P^B)
					p1.computeShareMin(outShareSend, outShareRecv); //compute (b1^A \xor b1^B)*(P1^A+P1^B)+(b2^A \xor b2^B)*(P2^A+P2^B)
					p1.computeShareIdxMin(outIdxShareSend, outIdxShareRecv);


					/*std::cout << IoStream::lock;
					for (u64 i = 0; i < p0.mTotalNumPoints; i++)
					std::cout << i << "-" << stepIdxMin << " mVecIdxMin: " << p1.mVecIdxMin[i] << "    bp B\n";
					std::cout << IoStream::unlock;*/

					if (numNodeThisLevel % 2 == 1) //odd number => add last node to this level
						for (u64 i = 0; i < p1.mTotalNumPoints; i++)
							p1.mShareMin[i].push_back(lastNode[i]);



					std::cout << IoStream::lock;
					for (u64 i = 0; i < p0.mTotalNumPoints; i++)
						std::cout << i << "-" << stepIdxMin << " mVecIdxMin: " << p1.mVecIdxMin[i] << "    B\n";
					std::cout << IoStream::unlock;
				}

				ostreamLock(std::cout) << "p1.mShareMin[0].size()=" << p1.mShareMin[0].size() << " end\n";

				thrd.join();




#if 0
				for (u64 i = 0; i < p0.mTotalNumPoints; i++)
				{
					Word minDist = (p0.mShareMin[i][0] + p1.mShareMin[i][0]) % p0.mMod;
					BitVector vecDist = p0.mVecIdxMin[i] ^ p1.mVecIdxMin[i];

					u64 minIdx;

					for (u64 k = 0; k < vecDist.size(); k++)
						if (vecDist[k] == 1)
						{
							minIdx = k;
							break;
						}

					Word actualMin = (p0.mDist[i][0] + p1.mDist[i][0]) % p0.mMod;
					Word actualMinIdx = 0;
					for (u64 k = 1; k < p0.mNumCluster; k++)
					{
						Word point = (p0.mDist[i][k] + p1.mDist[i][k]) % p0.mMod;
						if (actualMin > point)
						{
							actualMin = point;
							actualMinIdx = k;
						}
						//std::cout << point << " ";
					}

					if (actualMin != minDist || actualMinIdx != minIdx)
					{
						std::cout << i << ": min= " << minDist << " "
							<< vecDist << " idx= " << minIdx << "\n";

						std::cout << actualMin << " " << actualMinIdx << "\t ";


						for (u64 k = 0; k < p0.mNumCluster; k++)
						{
							Word point = (p0.mDist[i][k] + p1.mDist[i][k]) % p0.mMod;
							std::cout << point << " ";
						}

						throw std::exception();

					}
				}

#endif
				for (u64 i = 0; i < p0.mTotalNumPoints; i++)
				{
					std::cout << i << ": min=";
					for (u64 k = 0; k < p0.mShareMin[i].size(); k++)
					{
						Word minDist = (p0.mShareMin[i][k] + p1.mShareMin[i][k]) % p0.mMod;
						std::cout << minDist << " ";
					}
					BitVector vecDist = p0.mVecIdxMin[i] ^ p1.mVecIdxMin[i];
					std::cout << vecDist << " ";


					std::cout << " \t vs \t ";

					for (u64 k = 0; k < p0.mNumCluster; k++)
					{
						Word point = (p0.mDist[i][k] + p1.mDist[i][k]) % p0.mMod;
						std::cout << point << " ";
					}
					std::cout << "\n";
				}




				timer.setTimePoint("OTkeysDone");

				/*
				block data = p0.mPrng.get<block>();
				u64 aa1 = ((u64*)&data)[0];
				u64 aa2 = ((u64*)&data)[1];
				std::cout << data << "\n";
				std::cout << toBlock(aa1) << "\n";
				std::cout << toBlock(aa2) << "\n";*/



				//p0.Print();
				//p1.Print();





			}

	void testTranspose()
			{
				Timer timer; IOService ios;
				Session ep01(ios, "127.0.0.1", SessionMode::Server); Session ep10(ios, "127.0.0.1", SessionMode::Client);
				Channel chl01 = ep01.addChannel(); Channel chl10 = ep10.addChannel();

				u64 securityParams = 128, inDimension = 1, inExMod = 20, inNumCluster = 15;
				u64 numberTest = 4;

				int inMod = pow(2, inExMod);
				std::vector<std::vector<Word>> inputA, inputB;
				//loadTxtFile("I:/kmean-impl/dataset/s1.txt", inDimension, inputA, inputB);

#pragma region offline
				PRNG prng(ZeroBlock);
				
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

						//std::cout << inputA[i][j] << "\t" << inputB[i][j] << " p\n";
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

#pragma endregion



				//fake dist
				u64 num = 99;
				u64 num2 = 1;
				for (u64 i = 0; i < p0.mTotalNumPoints; i++)
					for (u64 k = 0; k < p0.mNumCluster; k++)
					{
						if (i % 2)
						{
							num = rand() % 1000;
							p0.mDist[i][k] = prng.get<Word>() % p0.mMod;
							p1.mDist[i][k] = (num - p0.mDist[i][k]) % p0.mMod;;
							std::cout << num << ":" << p0.mDist[i][k] << " + " << p1.mDist[i][k] << " = " << (p0.mDist[i][k] + p1.mDist[i][k]) % p0.mMod << " dist\n";
							num--;
						}
						else
						{
							num2 = rand() % 1000;
							p0.mDist[i][k] = prng.get<Word>() % p0.mMod;
							p1.mDist[i][k] = prng.get<Word>() % p0.mMod;;
							std::cout << num << ":" << p0.mDist[i][k] << " + " << p1.mDist[i][k] << " = " << (p0.mDist[i][k] + p1.mDist[i][k]) % p0.mMod << " dist\n";
							num2++;
						}
					}

				//fake compute mVecIdxMin
				for (u64 i = 0; i < p0.mTotalNumPoints; i++)
				{
					Word actualMin = (p0.mDist[i][0] + p1.mDist[i][0]) % p0.mMod;
					Word actualMinIdx = 0;
					for (u64 k = 1; k < p0.mNumCluster; k++)
					{
						Word point = (p0.mDist[i][k] + p1.mDist[i][k]) % p0.mMod;
						if (actualMin > point)
						{
							actualMin = point;
							actualMinIdx = k;
						}
					}
					p0.mVecIdxMin[i].resize(p0.mNumCluster);
					p1.mVecIdxMin[i].resize(p1.mNumCluster);
					p0.mVecIdxMin[i].randomize(p0.mPrng);
					p1.mVecIdxMin[i] = p0.mVecIdxMin[i];
					if(p0.mVecIdxMin[i][actualMinIdx])
						p0.mVecIdxMin[i][actualMinIdx] = 0;
					else
						p0.mVecIdxMin[i][actualMinIdx] = 1;

				}


				for (u64 i = 0; i < p0.mTotalNumPoints; i++)
				{
					
					BitVector vecDist = p0.mVecIdxMin[i] ^ p1.mVecIdxMin[i];
					std::cout << vecDist << " ";


					std::cout << " \t vs \t ";

					for (u64 k = 0; k < p0.mNumCluster; k++)
					{
						Word point = (p0.mDist[i][k] + p1.mDist[i][k]) % p0.mMod;
						std::cout << point << " ";
					}
					std::cout << "\n";
				}

				p0.vecMinTranspose();

						


			}


	void testUpdateCluster()
			{
				Timer timer; IOService ios;
				Session ep01(ios, "127.0.0.1", SessionMode::Server); Session ep10(ios, "127.0.0.1", SessionMode::Client);
				Channel chl01 = ep01.addChannel(); Channel chl10 = ep10.addChannel();

				u64 securityParams = 128, inDimension = 1, inExMod = 20, inNumCluster = 15;
				u64 numberTest = 4;

				int inMod = pow(2, inExMod);
				std::vector<std::vector<Word>> inputA, inputB;
				//loadTxtFile("I:/kmean-impl/dataset/s1.txt", inDimension, inputA, inputB);

#pragma region offline
				PRNG prng(ZeroBlock);

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

						//std::cout << inputA[i][j] << "\t" << inputB[i][j] << " p\n";
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

#pragma endregion



				//fake dist
				u64 num = 99;
				u64 num2 = 1;
				for (u64 i = 0; i < p0.mTotalNumPoints; i++)
					for (u64 k = 0; k < p0.mNumCluster; k++)
					{
						if (i % 2)
						{
							num = rand() % 1000;
							p0.mDist[i][k] = prng.get<Word>() % p0.mMod;
							p1.mDist[i][k] = (num - p0.mDist[i][k]) % p0.mMod;;
							std::cout << num << ":" << p0.mDist[i][k] << " + " << p1.mDist[i][k] << " = " << (p0.mDist[i][k] + p1.mDist[i][k]) % p0.mMod << " dist\n";
							num--;
						}
						else
						{
							num2 = rand() % 1000;
							p0.mDist[i][k] = prng.get<Word>() % p0.mMod;
							p1.mDist[i][k] = prng.get<Word>() % p0.mMod;;
							std::cout << num << ":" << p0.mDist[i][k] << " + " << p1.mDist[i][k] << " = " << (p0.mDist[i][k] + p1.mDist[i][k]) % p0.mMod << " dist\n";
							num2++;
						}
					}

				//fake compute mVecIdxMin
				for (u64 i = 0; i < p0.mTotalNumPoints; i++)
				{
					Word actualMin = (p0.mDist[i][0] + p1.mDist[i][0]) % p0.mMod;
					Word actualMinIdx = 0;
					for (u64 k = 1; k < p0.mNumCluster; k++)
					{
						Word point = (p0.mDist[i][k] + p1.mDist[i][k]) % p0.mMod;
						if (actualMin > point)
						{
							actualMin = point;
							actualMinIdx = k;
						}
					}
					p0.mVecIdxMin[i].resize(p0.mNumCluster);
					p1.mVecIdxMin[i].resize(p1.mNumCluster);
					p0.mVecIdxMin[i].randomize(p0.mPrng);
					p1.mVecIdxMin[i] = p0.mVecIdxMin[i];
					if (p0.mVecIdxMin[i][actualMinIdx])
						p0.mVecIdxMin[i][actualMinIdx] = 0;
					else
						p0.mVecIdxMin[i][actualMinIdx] = 1;

				}


				for (u64 i = 0; i < p0.mTotalNumPoints; i++)
				{

					BitVector vecDist = p0.mVecIdxMin[i] ^ p1.mVecIdxMin[i];
					std::cout << vecDist << " ";


					std::cout << " \t vs \t ";

					for (u64 k = 0; k < p0.mNumCluster; k++)
					{
						Word point = (p0.mDist[i][k] + p1.mDist[i][k]) % p0.mMod;
						std::cout << point << " ";
					}
					std::cout << "\n";
				}






				std::vector<std::vector<Word>> shareNomSend0, shareNomRecv0, shareNomSend1, shareNomRecv1;
				std::vector<Word> shareDenSend0, shareDenSend1, shareDenRecv0, shareDenRecv1;

				thrd = std::thread([&]() {
					p0.vecMinTranspose();

					p0.amortBinArithClustsend(shareNomSend0, shareDenSend0, p0.mVecIdxMinTranspose);

				});
				p1.vecMinTranspose();

				std::vector<std::vector<Word>> outShareSendNumeral, outShareRecvNumeral;
				p1.amortBinArithClustrecv(shareNomRecv1, shareDenRecv1, p0.mVecIdxMinTranspose);


				thrd.join();


			}



	}