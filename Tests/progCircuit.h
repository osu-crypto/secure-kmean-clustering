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

	void programDiv(std::array<Party, 2> parties, i64 myInput1, i64 myInput2, iWord& myShare, u64 bitCount)
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
		, std::vector<iWord>& myInput2, BitVector& myOutput, u64 bitCount, std::vector<int> expLt = {})
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


	void programLessThanBaseLine(std::array<Party, 2> parties, std::vector<iWord>& myInput, BitVector& myOutput, u64 bitCount)
	{


		myOutput.resize(myInput.size());

		if (myInput.size() == 4)
		{
			std::vector<sInt> mysInt0(myInput.size());
			std::vector<sInt> mysInt1(myInput.size());
			std::vector<sInt> realInput(myInput.size());

			for (u64 i = 0; i < myInput.size(); i++)
			{
				mysInt0[i] = parties[0].isLocalParty() ?  //x1
					parties[0].input<sInt>(myInput[i], bitCount) :
					parties[0].input<sInt>(bitCount);

				mysInt1[i] = parties[1].isLocalParty() ? //x2
					parties[1].input<sInt>(myInput[i], bitCount) :
					parties[1].input<sInt>(bitCount);

				realInput[i] = mysInt0[i] + mysInt1[i];

			}
		

			auto min01 = (realInput[0] < realInput[1]).ifelse(realInput[0], realInput[1]);
			auto min23 = (realInput[2] < realInput[3]).ifelse(realInput[2], realInput[3]);
			auto min= (min01 < min23).ifelse(min01, min23); //find min

			std::vector<sInt> minBit(myInput.size());
			std::vector<sInt> bb(myInput.size());

			for (u64 i = 0; i < myInput.size(); i++)
			{
				minBit[i]=min.ifequal(realInput[i]);
				minBit[i] = ~minBit[i];

				
//#define PRINTALL

#ifdef PRINTALL
				parties[0].reveal(minBit[i]);
				parties[0].reveal(realInput[i]);
#endif

			}

#ifdef PRINTALL
			parties[0].reveal(min);
			parties[0].reveal(min01);
			parties[0].reveal(min23);
#endif
			parties[1].getRuntime().processesQueue();

			for (u64 i = 0; i < myInput.size(); i++)
			{
				ShGcInt * v = static_cast<ShGcInt*>(minBit[i].mData.get());
				myOutput[i] = PermuteBit((*v->mLabels)[0]); //YES=1
			}
#ifdef PRINTALL
			if (parties[0].isLocalParty())
			{

				std::cout << IoStream::lock;
				std::cout << "eval:\n"
					<< "    min01  = " << min01.getValue() << "\t"
					<< "    min23  = " << min23.getValue() << "\t"
					<< "    min = " << min.getValue() << "\t --------------" << std::endl;
			
				for (u64 i = 0; i < myInput.size(); i++)
				{
					std::cout << minBit[i].getValue() << " ";
					std::cout << myOutput[i] << "\t";
					std::cout << realInput[i].getValue() << "\t";

				}
				std::cout << "\n";


				
				for (u64 i = 0; i < myInput.size(); i++)
				{
					std::cout << myOutput[i] << "";
				}
				std::cout << " p0\n";
				std::cout << IoStream::unlock;
			}

			if (parties[1].isLocalParty())
			{

				std::cout << IoStream::lock;
				for (u64 i = 0; i < myInput.size(); i++)
				{
					std::cout << myOutput[i] << "";
				}
				std::cout << " p1\n";
				std::cout << IoStream::unlock;
				
			}
#endif
		}
		else if (myInput.size() == 16)
			{
				std::vector<sInt> mysInt0(myInput.size());
				std::vector<sInt> mysInt1(myInput.size());
				std::vector<sInt> realInput(myInput.size());

				for (u64 i = 0; i < myInput.size(); i++)
				{
					mysInt0[i] = parties[0].isLocalParty() ?  //x1
						parties[0].input<sInt>(myInput[i], bitCount) :
						parties[0].input<sInt>(bitCount);

					mysInt1[i] = parties[1].isLocalParty() ? //x2
						parties[1].input<sInt>(myInput[i], bitCount) :
						parties[1].input<sInt>(bitCount);

					realInput[i] = mysInt0[i] + mysInt1[i];

				}

				std::vector<sInt> minIJ(myInput.size() / 2);
				for (u64 i = 0; i < myInput.size()/2; i++)
				{
					minIJ[i] = (realInput[2*i] < realInput[2*i+1]).ifelse(realInput[2*i], realInput[2 * i + 1]);
				}


				auto min1 = (minIJ[0] < minIJ[1]).ifelse(minIJ[0], minIJ[1]); //find min
				auto min4 = (minIJ[2] < minIJ[3]).ifelse(minIJ[2], minIJ[3]); //find min
				auto min8 = (minIJ[4] < minIJ[5]).ifelse(minIJ[4], minIJ[5]); //find min
				auto min12 = (minIJ[6] < minIJ[7]).ifelse(minIJ[6], minIJ[7]); //find min

				auto min14 = (min1 < min4).ifelse(min1, min4); //find min
				auto min812 = (min8 < min12).ifelse(min8, min12); //find min

				auto min= (min14 < min812).ifelse(min14, min812); //find min


				std::vector<sInt> minBit(myInput.size());
				std::vector<sInt> bb(myInput.size());

				for (u64 i = 0; i < myInput.size(); i++)
				{
					minBit[i] = min.ifequal(realInput[i]);
					minBit[i] = ~minBit[i];

//#define PRINTALL

#ifdef PRINTALL
					parties[0].reveal(minBit[i]);
					parties[0].reveal(realInput[i]);
#endif

				}

#ifdef PRINTALL
				parties[0].reveal(min);
#endif
				parties[1].getRuntime().processesQueue();

				for (u64 i = 0; i < myInput.size(); i++)
				{
					ShGcInt * v = static_cast<ShGcInt*>(minBit[i].mData.get());
					myOutput[i] = PermuteBit((*v->mLabels)[0]); //YES=1
				}
#ifdef PRINTALL
				if (parties[0].isLocalParty())
				{

					std::cout << IoStream::lock;
					std::cout << "eval:\n"
						<< "    min = " << min.getValue() << "----------" << std::endl;

					for (u64 i = 0; i < myInput.size(); i++)
					{
						std::cout << minBit[i].getValue() << " ";
						std::cout << myOutput[i] << "\t";
						std::cout << realInput[i].getValue() << "\t";

					}
					std::cout << "\n";



					for (u64 i = 0; i < myInput.size(); i++)
					{
						std::cout << myOutput[i] << "";
					}
					std::cout << " p0--------------------\n";
					std::cout << IoStream::unlock;
				}

				if (parties[1].isLocalParty())
				{

		/*			std::cout << IoStream::lock;
					for (u64 i = 0; i < myInput.size(); i++)
					{
						std::cout << myOutput[i] << "";
					}
					std::cout << " p1\n";
					std::cout << IoStream::unlock;*/

				}
#endif
			}

		else
		{
			std::cout << "does not support! \n";
			throw std::exception();
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


	void programDistNorm1(std::array<Party, 2> parties, std::vector<iWord>& mySharePoint
		, std::vector<iWord>& myShareCluster, iWord& myShare, u64 bitCount)
	{

//#define PRINTALL
		std::vector<sInt> diff(mySharePoint.size());
		std::vector<sInt> abss(mySharePoint.size());
		std::vector<sInt> diff2(mySharePoint.size());
		std::vector<sInt> abss2(mySharePoint.size());

		sInt max;
		for (u64 i = 0; i < mySharePoint.size(); i++) //[d]
		{
			auto inputPoint0 = parties[0].isLocalParty() ?  //x1
				parties[0].input<sInt>(mySharePoint[i], bitCount) :
				parties[0].input<sInt>(bitCount);

			auto inputPoint1 = parties[1].isLocalParty() ? //x2
				parties[1].input<sInt>(mySharePoint[i], bitCount) :
				parties[1].input<sInt>(bitCount);

			auto inputCluster0 = parties[0].isLocalParty() ? //y1
				parties[0].input<sInt>(myShareCluster[i], bitCount) :
				parties[0].input<sInt>(bitCount);

			auto inputCluster1 = parties[1].isLocalParty() ? //y2
				parties[1].input<sInt>(myShareCluster[i], bitCount) :
				parties[1].input<sInt>(bitCount);

			auto inputPoint = inputPoint0 + inputPoint1;
			auto inputCluster = inputCluster0 + inputCluster1;

			diff[i] = inputPoint - inputCluster;

			if (i == 0)
				max = diff[i].abs();
			else
			{
				abss[i] = diff[i].abs();
				max = (max > abss[i]).ifelse(max, abss[i]);
			}

#ifdef PRINTALL
			if (i != 0) {
				diff2[i] = inputCluster - inputPoint;
				abss2[i] = diff2[i].abs();

				parties[0].reveal(diff[i]);
				parties[0].reveal(abss[i]);
				parties[0].reveal(diff2[i]);
				parties[0].reveal(abss2[i]);
			}
#endif // PRINTALL

		}





		auto inputShare = parties[0].isLocalParty() ? //y2
			parties[0].input<sInt>(myShare, bitCount) :
			parties[0].input<sInt>(bitCount);
		
		auto share = max - inputShare;

		parties[1].reveal(share);

#ifdef PRINTALL
		parties[1].reveal(max);
#endif // PRINTALL		

			parties[1].getRuntime().processesQueue();

			if (parties[1].isLocalParty())
			{
				myShare = share.getValue();// signExtend(share.getValue(), bitCount);
				
		/*		std::cout << IoStream::lock;
				std::cout << "myShare  = " << myShare << " p1\n";
				std::cout << "max  = " << max.getValue() << "\n";
				std::cout << IoStream::unlock;*/

			}

			if (parties[0].isLocalParty())
			{
				//std::cout << IoStream::lock;
				//std::cout << "myShare  = " << myShare << " p0\t";
				//std::cout << IoStream::unlock;
			}
#ifdef PRINTALL
			if (parties[0].isLocalParty())
			{
				std::cout << "myShare  = " << myShare << " p0\t";
				std::cout << "max  = " << max.getValue() << "\t";
				for (u64 i = 0; i < mySharePoint.size(); i++) //[d]
				{
					if (i != 0) {
						std::cout << "    diff  = " << diff[i].getValue() << "\t"
							<< "    abss  = " << abss[i].getValue() << "\t"
							<< "    diff2 = " << diff2[i].getValue() << "\t"
							<< " abss2 = " << abss2[i].getValue() << "\t --------------" << std::endl;
					}
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