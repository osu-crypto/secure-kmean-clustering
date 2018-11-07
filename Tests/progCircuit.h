#pragma once
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
namespace osuCrypto
{



	void programLessThan22(std::array<Party, 2> parties, iWord myInput1, iWord myInput2, u64 bitCount, int expLt)
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
				<< "    x  = " << input0.getValue() << "\t"
				<< "    y  = " << input1.getValue() << "\t"
				<< "    lt = " << ltVal << "\n"
				<< " minus = " << minus.getValue() << "\t --------------" << std::endl;
			if (passed)
				std::cout << Color::Green << "    Passed " << ColorDefault << std::endl;
			else
			{
				std::cout << Color::Red << "    Failed " << ColorDefault << std::endl;
				throw std::exception();
			}
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


	void programEqualZero(std::array<Party, 2> parties, i64 myInput1, u8& output, u64 bitCount)
	{

		auto input01 = parties[0].isLocalParty() ?  //x1
			parties[0].input<sInt>(myInput1, bitCount) :
			parties[0].input<sInt>(bitCount);

		auto input11 = parties[1].isLocalParty() ? //x2
			parties[1].input<sInt>(myInput1, bitCount) :
			parties[1].input<sInt>(bitCount);

		auto input0 = input01 + input11;
		auto eq = input0 > 0;

		parties[0].reveal(input0);
		//parties[0].reveal(eq);
		parties[0].reveal(eq);
		parties[1].getRuntime().processesQueue();

#if 1
		if (parties[0].isLocalParty())
		{
			output = eq.getValue();
			std::cout << IoStream::lock;
			std::cout << input0.getValue() << "?>0 =" << int(output) << " --------------\n";
			std::cout << IoStream::unlock;

		}

		if (parties[1].isLocalParty())
		{

			//output = eq.getValue();
			//std::cout << i << ": lt= " << lt.getValue() << " vs " << invert.getValue() << std::endl;
			//ostreamLock(std::cout) << i << ": slt= " << int(myOutput[2 * i]) << int(myOutput[2 * i + 1]) << "    B\n";// << (*v1->mLabels)[0] << std::endl;
		}
#endif



	}

	void programDiv(std::array<Party, 2> parties, i64 myInput1, i64 myInput2, iWord myShare, u64 bitCount)
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


		auto inputShare = parties[0].isLocalParty() ? //y2
			parties[0].input<sInt>(myShare, bitCount) :
			parties[0].input<sInt>(bitCount);
		auto share = div - inputShare;

		parties[1].reveal(share);

#ifdef PRINTALL
		parties[0].reveal(input0);
		parties[0].reveal(input1);
		parties[0].reveal(div);
		
#endif // PRINTALL
		parties[1].getRuntime().processesQueue();


		if (parties[1].isLocalParty())
		{
			myShare = share.getValue();
		}


#ifdef PRINTALL
		if (parties[0].isLocalParty())
		{
			std::cout << IoStream::lock;
			std::cout << input0.getValue() << "/" << input1.getValue() << "=" << div.getValue() << " --------------\n";
			std::cout << myShare << "  p0--------------\n";

			std::cout << IoStream::unlock;

		}

		if (parties[1].isLocalParty())
		{
			myShare = share.getValue();
			std::cout << IoStream::lock;
			std::cout << myShare << "  p1--------------\n";
			std::cout << IoStream::unlock;
			//std::cout << i << ": lt= " << lt.getValue() << " vs " << invert.getValue() << std::endl;
			//ostreamLock(std::cout) << i << ": slt= " << int(myOutput[2 * i]) << int(myOutput[2 * i + 1]) << "    B\n";// << (*v1->mLabels)[0] << std::endl;
		}
#endif

	}


	void programLessThan(std::array<Party, 2> parties, std::vector<iWord>& myInput1
		, std::vector<iWord> myInput2, BitVector& myOutput, u64 bitCount, std::vector<int> expLt = {})
	{

		myOutput.resize(2 * myInput1.size());

		for (u64 i = 0; i < myInput1.size(); i++)
		{
			auto input01 = parties[0].isLocalParty() ?  //x1
				parties[0].input<sInt>(myInput1[i], bitCount) :
				parties[0].input<sInt>(bitCount);

			auto input11 = parties[1].isLocalParty() ? //x2
				parties[1].input<sInt>(myInput1[i], bitCount) :
				parties[1].input<sInt>(bitCount);

			auto input02 = parties[0].isLocalParty() ? //y1
				parties[0].input<sInt>(myInput2[i], bitCount) :
				parties[0].input<sInt>(bitCount);

			auto input12 = parties[1].isLocalParty() ? //y2
				parties[1].input<sInt>(myInput2[i], bitCount) :
				parties[1].input<sInt>(bitCount);

			auto input0 = input01 + input11;
			auto input1 = input02 + input12;

			auto lt = input0 < input1;
			auto invert = ~lt;

#ifdef PRINTALL
			auto minus = input0 - input1;
			parties[0].reveal(input0);
			parties[0].reveal(input1);
			parties[0].reveal(lt);
			parties[0].reveal(minus);
#endif // PRINTALL		

			parties[1].getRuntime().processesQueue();


			ShGcInt * v = static_cast<ShGcInt*>(lt.mData.get());
			ShGcInt * v1 = static_cast<ShGcInt*>(invert.mData.get());
			myOutput[2 * i] = PermuteBit((*v->mLabels)[0]); //YES=10, NO=01
			myOutput[2 * i + 1] = PermuteBit((*v1->mLabels)[0]);

#ifdef PRINTALL
			if (parties[0].isLocalParty())
			{

				auto ltVal = lt.getValue();

				bool passed = expLt[i] == ltVal;
				std::cout << "eval:\n"
					<< "    x  = " << input0.getValue() << "\t"
					<< "    y  = " << input1.getValue() << "\t"
					<< "    lt = " << ltVal << "\t"
					<< " minus = " << minus.getValue() << "\t --------------" << std::endl;
				if (passed)
					std::cout << Color::Green << "    Passed " << ColorDefault << std::endl;
				else
				{
					std::cout << Color::Red << "    Failed " << ColorDefault << std::endl;
					throw std::exception();
				}

			}

			if (parties[1].isLocalParty())
			{
				//std::cout << i << ": lt= " << lt.getValue() << " vs " << invert.getValue() << std::endl;
				//ostreamLock(std::cout) << i << ": slt= " << int(myOutput[2 * i]) << int(myOutput[2 * i + 1]) << "    B\n";// << (*v1->mLabels)[0] << std::endl;
			}
#endif

		}

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






	void programLessThanDiff(std::array<Party, 2> parties, std::vector<i64>& myInput, BitVector& myOutput, u64 bitCount)
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

}