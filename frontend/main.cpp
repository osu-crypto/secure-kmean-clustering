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
#include "progCircuit.h"

#include "CLP.h"
#include "main.h"

#include <boost/thread/thread.hpp>
using namespace osuCrypto;


int securityParams = 128;
int inDimension = 2;
int inExMod = 31;
u64 inNumCluster = 4;
u64 numberTestA = 1 << 5;
u64 numberTestB = 1 << 5;
u64 numInteration = 2;

std::vector<std::vector<iWord>> p0TestDist;
std::vector<std::vector<iWord>> p1TestDist;
std::vector<BitVector> p0TestVecIdxMin;
std::vector<BitVector> p1TestVecIdxMin;


void generateDist_VecIdxMin()
{
	PRNG prng(ZeroBlock);

	u64 totalNumPoints = numberTestA + numberTestB;
	p0TestDist.resize(totalNumPoints);
	p1TestDist.resize(totalNumPoints);
	p0TestVecIdxMin.resize(totalNumPoints);
	p1TestVecIdxMin.resize(totalNumPoints);

	for (u64 i = 0; i < totalNumPoints; i++) //original points
	{
		p0TestDist[i].resize(inNumCluster);
		p1TestDist[i].resize(inNumCluster);

		for (u64 k = 0; k < inNumCluster; k++) //original cluster
		{
			p0TestDist[i][k] = signExtend(prng.get<Word>(), inExMod);
			p1TestDist[i][k] = signExtend(prng.get<Word>(), inExMod);
		}
	}
	//compute mVecIdxMin
	for (u64 i = 0; i < totalNumPoints; i++)
	{
		iWord actualMin = signExtend(p0TestDist[i][0] + p1TestDist[i][0], inExMod);
		Word actualMinIdx = 0;
		for (u64 k = 1; k < inNumCluster; k++)
		{
			iWord point = signExtend(p0TestDist[i][k] + p1TestDist[i][k], inExMod);
			if (actualMin > point)
			{
				actualMin = point;
				actualMinIdx = k;
			}
		}
		p0TestVecIdxMin[i].resize(inNumCluster);
		p1TestVecIdxMin[i].resize(inNumCluster);
		p0TestVecIdxMin[i].randomize(prng);
		p1TestVecIdxMin[i] = p0TestVecIdxMin[i];
		if (p0TestVecIdxMin[i][actualMinIdx])
			p0TestVecIdxMin[i][actualMinIdx] = 0;
		else
			p0TestVecIdxMin[i][actualMinIdx] = 1;


#ifdef PRINTALL
		//test
		BitVector vecDist = p0TestVecIdxMin[i] ^ p1TestVecIdxMin[i];
		std::cout << vecDist << " | " << actualMin;

		std::cout << " \t vs \t ";

		for (u64 k = 0; k < inNumCluster; k++)
		{
			iWord dist = signExtend(p0TestDist[i][k] + p1TestDist[i][k], inExMod);
			std::cout << dist << " ";
		}
		std::cout << "\n";
#endif //PRINTALL
	}

	
}

void party0_Dist()
{
	Timer timer;
	IOService ios;
	Session ep01(ios, "127.0.0.1", SessionMode::Server);
	Channel chl01 = ep01.addChannel();

	u64 inMod = pow(2, inExMod);
	std::vector<std::vector<Word>> inputA;
	//loadTxtFile("I:/kmean-impl/dataset/s1.txt", inDimension, inputA, inputB);

	PRNG prng(ZeroBlock);

	inputA.resize(numberTestA);
	for (int i = 0; i < numberTestA; i++)
	{
		inputA[i].resize(inDimension);
		for (size_t j = 0; j < inDimension; j++)
		{
			inputA[i][j] = prng.get<Word>() % inMod;

		}
	}

	u64 inTotalPoint = inputA.size() + numberTestB;
	//=======================offline===============================
	DataShare p0;

	p0.init(0, chl01, toBlock(34265), securityParams, inTotalPoint
		, inNumCluster, 0, inNumCluster / 2, inputA, inExMod, inDimension, numInteration);

	NaorPinkas baseOTs;
	baseOTs.send(p0.mSendBaseMsg, p0.mPrng, p0.mChl, 1); //first OT for D_B
	p0.recv.setBaseOts(p0.mSendBaseMsg);


	baseOTs.receive(p0.mBaseChoices, p0.mRecvBaseMsg, p0.mPrng, p0.mChl, 1); //second OT for D_A
	p0.sender.setBaseOts(p0.mRecvBaseMsg, p0.mBaseChoices); //set base OT


	timer.setTimePoint("baseOTDone");
	//std::cout << "baseOTDone\n";

	//=======================OT extension===============================
		//1st OT
	p0.mChoiceAllBitSharePointsOffline.resize(p0.mTotalNumPoints*p0.mDimension*p0.mLenMod);
	p0.mChoiceAllBitSharePointsOffline.randomize(p0.mPrng);

	p0.recv.receive(p0.mChoiceAllBitSharePointsOffline, p0.mRecvAllOtKeys, p0.mPrng, p0.mChl);

	//other OT direction
	p0.sender.send(p0.mSendAllOtKeys, p0.mPrng, p0.mChl);


	//===For cluster
	p0.allChoicesClusterOffline.randomize(p0.mPrng);
	p0.recv.receive(p0.allChoicesClusterOffline, p0.recvOTmsgClusterOffline, p0.mPrng, p0.mChl); //randome OT




	timer.setTimePoint("offlineDone");
	//std::cout << "offlineDone\n";

	std::cout << "d=" << p0.mDimension << " | "
		<< "K= " << p0.mNumCluster << " | "
		<< "n= " << p0.mTotalNumPoints << " | "
		<< "l= " << p0.mLenMod << " | "
		<< "T= " << p0.mIteration << "\t party0_Dist\n";


	//=======================online (sharing)===============================

	p0.sendShareInput(0, 0, inNumCluster / 2);
	p0.recvShareInput(p0.mPoint.size(), inNumCluster / 2, inNumCluster);

	timer.setTimePoint("sharingInputsDone");
	//std::cout << "sharingInputsDone\n";


	//=======================online OT (setting up keys for adaptive ED)===============================

	p0.correctAllChoiceRecv();//1st OT
	p0.correctAllChoiceSender();////other OT direction
	//std::cout << "correctAllChoice\n";
	timer.setTimePoint("correctOTDone");
	p0.setPRNGseeds();

	timer.setTimePoint("OtKeysDone");
	//std::cout << "OtKeysDone\n";


	for (u64 idxIter = 0; idxIter < numInteration; idxIter++)
	{
		//std::cout << "-";
		//=======================online MUL===============================

//(c^A[k][d]*c^B[k][d])
		p0.mProdCluster = p0.amortMULrecv(p0.mShareCluster, idxIter*p0.mNumCluster*p0.mDimension*p0.mLenMod); //compute C^Ak*C^Bk
															 //(p^A[i][d]*(p^B[i][d]-c^B[k][d]) => A receiver
		for (u64 i = 0; i < p0.mTotalNumPoints; i++)
			for (u64 d = 0; d < p0.mDimension; d++)
				p0.mProdPointPPC[i][d] = p0.amortAdaptMULrecv(i, d, p0.mNumCluster); //for each point to all clusters

																					 //(p^B[i][d]*c^A[k][d]) => A is sender
		for (u64 d = 0; d < p0.mDimension; d++)
			for (u64 k = 0; k < p0.mNumCluster; k++)
				memcpy((i8*)&p0.prodTempC[d][k], (u8*)&p0.mShareCluster[k][d], p0.mLenModinByte); //c^A[k][d]

		for (u64 i = 0; i < p0.mTotalNumPoints; i++)
			for (u64 d = 0; d < p0.mDimension; d++)
				p0.mProdPointPC[i][d] = p0.amortAdaptMULsend(i, d, p0.prodTempC[d]); //for each point to all clusters

			//=======================online locally compute ED===============================
		p0.computeDist();
	}

	timer.setTimePoint("DistDone");
	std::cout << "DistDone\n";

	//p0.Print();


	std::cout << timer << "\n";
	u64 bandwith = (p0.mChl.getTotalDataRecv() + p0.mChl.getTotalDataSent()) / (pow(10, 6));
	std::cout << "comm. = " << bandwith << " MB\n";

}
void party1_Dist()
{
	Timer timer;
	IOService ios;
	Session ep10(ios, "127.0.0.1", SessionMode::Client);
	Channel chl10 = ep10.addChannel();
	u64 inMod = pow(2, inExMod);
	std::vector<std::vector<Word>> inputB;
	//loadTxtFile("I:/kmean-impl/dataset/s1.txt", inDimension, inputA, inputB);

	PRNG prng(ZeroBlock);
	inputB.resize(numberTestB);
	for (int i = 0; i < numberTestB; i++)
	{
		inputB[i].resize(inDimension);
		for (size_t j = 0; j < inDimension; j++)
			inputB[i][j] = prng.get<Word>() % inMod;
	}

	u64 inTotalPoint = numberTestA + inputB.size();
	//=======================offline===============================
	DataShare  p1;

	timer.setTimePoint("starts");

	p1.init(1, chl10, toBlock(34265), securityParams, inTotalPoint
		, inNumCluster, inNumCluster / 2, inNumCluster, inputB, inExMod, inDimension, numInteration);

	NaorPinkas baseOTs;
	baseOTs.receive(p1.mBaseChoices, p1.mRecvBaseMsg, p1.mPrng, p1.mChl, 1); //first OT for D_B
	p1.sender.setBaseOts(p1.mRecvBaseMsg, p1.mBaseChoices); //set base OT

	baseOTs.send(p1.mSendBaseMsg, p1.mPrng, p1.mChl, 1); //second OT for D_A
	p1.recv.setBaseOts(p1.mSendBaseMsg);

	timer.setTimePoint("baseOTDone");
	//std::cout << "baseOTDone\n";
	//=======================OT extension===============================
	//1st OT
	p1.sender.send(p1.mSendAllOtKeys, p1.mPrng, p1.mChl);

	//other OT direction
	p1.mChoiceAllBitSharePointsOffline.resize(p1.mTotalNumPoints*p1.mDimension*p1.mLenMod);
	p1.mChoiceAllBitSharePointsOffline.randomize(p1.mPrng);
	p1.recv.receive(p1.mChoiceAllBitSharePointsOffline, p1.mRecvAllOtKeys, p1.mPrng, p1.mChl);

	//===For cluster
	p1.sender.send(p1.sendOTmsgsClusterOffline, p1.mPrng, p1.mChl); //randome OT

	timer.setTimePoint("offlineDone");

	std::cout << "d=" << p1.mDimension << " | "
		<< "K= " << p1.mNumCluster << " | "
		<< "n= " << p1.mTotalNumPoints << " | "
		<< "l= " << p1.mLenMod << " | "
		<< "T= " << p1.mIteration << "\t party1_Dist\n";


	std::cout << "offlineDone\n";


	//=======================online (sharing)===============================
	p1.recvShareInput(0, 0, inNumCluster / 2);
	p1.sendShareInput(p1.mTheirNumPoints, inNumCluster / 2, inNumCluster);

	timer.setTimePoint("sharingInputsDone");

	//=======================online OT (setting up keys for adaptive ED)===============================
	p1.correctAllChoiceSender(); //1st OT
	p1.correctAllChoiceRecv();////other OT direction
	std::cout << "correctOTDone\n";
	timer.setTimePoint("correctOTDone");
	p1.setPRNGseeds();

	timer.setTimePoint("OTkeysDone");
	std::cout << "OTkeysDone\n";


	for (u64 idxIter = 0; idxIter < numInteration; idxIter++)
	{
		std::cout << "-";

		//=======================online MUL===============================
		p1.mProdCluster = p1.amortMULsend(p1.mShareCluster, idxIter*p1.mNumCluster*p1.mDimension*p1.mLenMod);//(c^A[k][d]*c^B[k][d])

															//(p^A[i][d]*(p^B[i][d]-c^B[k][d])
		for (u64 i = 0; i < p1.mTotalNumPoints; i++)
			for (u64 d = 0; d < p1.mDimension; d++)
			{
				//prodTempPC=pid-ckl
				for (u64 k = 0; k < p1.mNumCluster; k++)
					p1.prodTempPC[i][d][k] = (p1.mSharePoint[i][d].mArithShare - p1.mShareCluster[k][d]);

				p1.mProdPointPPC[i][d] = p1.amortAdaptMULsend(i, d, p1.prodTempPC[i][d]);

			}

		//(p^B[i][d]*c^A[k][d]) => B is recv
		for (u64 i = 0; i < p1.mTotalNumPoints; i++)
			for (u64 d = 0; d < p1.mDimension; d++)
				p1.mProdPointPC[i][d] = p1.amortAdaptMULrecv(i, d, p1.mNumCluster); //for each point to all clusters

		//=======================online locally compute ED===============================
		p1.computeDist();
	}

	timer.setTimePoint("DistDone");

	std::cout << "\nDistDone";

	std::cout << timer << "\n";
	u64 bandwith = (p1.mChl.getTotalDataRecv() + p1.mChl.getTotalDataSent()) / (pow(10, 6));
	std::cout << "comm. = " << bandwith << " MB\n";


	//p1.Print();

}

void party0_DistNorm(int norm1) //0 is inf, 1 is norm1
{
	Timer timer;
	IOService ios;
	Session ep01(ios, "127.0.0.1", SessionMode::Server);
	Channel chl01 = ep01.addChannel();

	u64 inMod = pow(2, inExMod);
	std::vector<std::vector<Word>> inputA;
	//loadTxtFile("I:/kmean-impl/dataset/s1.txt", inDimension, inputA, inputB);

	PRNG prng(ZeroBlock);

	inputA.resize(numberTestA);
	for (int i = 0; i < numberTestA; i++)
	{
		inputA[i].resize(inDimension);
		for (size_t j = 0; j < inDimension; j++)
		{
			inputA[i][j] = prng.get<Word>() % inMod;

		}
	}

	u64 inTotalPoint = inputA.size() + numberTestB;
	//=======================offline===============================
	DataShare p0;

	p0.init(0, chl01, toBlock(34265), securityParams, inTotalPoint
		, inNumCluster, 0, inNumCluster / 2, inputA, inExMod, inDimension, numInteration);

	NaorPinkas baseOTs;
	baseOTs.send(p0.mSendBaseMsg, p0.mPrng, p0.mChl, 1); //first OT for D_B
	p0.recv.setBaseOts(p0.mSendBaseMsg);


	baseOTs.receive(p0.mBaseChoices, p0.mRecvBaseMsg, p0.mPrng, p0.mChl, 1); //second OT for D_A
	p0.sender.setBaseOts(p0.mRecvBaseMsg, p0.mBaseChoices); //set base OT


	timer.setTimePoint("baseOTDone");	
	timer.setTimePoint("offlineDone");
	//std::cout << "offlineDone\n";

	std::cout << "d=" << p0.mDimension << " | "
		<< "K= " << p0.mNumCluster << " | "
		<< "n= " << p0.mTotalNumPoints << " | "
		<< "l= " << p0.mLenMod << " | "
		<< "T= " << p0.mIteration << "\t party0_DistNorm(" << norm1 << ")\n";


	//=======================online (sharing)===============================

	p0.sendShareInput(0, 0, inNumCluster / 2);
	p0.recvShareInput(p0.mPoint.size(), inNumCluster / 2, inNumCluster);

	timer.setTimePoint("sharingInputsDone");
	//std::cout << "sharingInputsDone\n";

	//=======================Dist Norm1===============================
	for (u64 idxIter = 0; idxIter < numInteration; idxIter++)
	{
		std::vector<std::vector<iWord>> myShareCluster(p0.mNumCluster);

		for (u64 k = 0; k < p0.mNumCluster; k++)
		{
			myShareCluster[k].resize(p0.mDimension);
			for (u64 d = 0; d < p0.mDimension; d++)
				memcpy((i8*)&myShareCluster[k][d], (u8*)&p0.mShareCluster[k][d], sizeof(Word));
		}

		for (u64 i = 0; i < p0.mTotalNumPoints; i++)
		{
			std::vector<iWord> mySharePoint(p0.mDimension);
			for (u64 d = 0; d < p0.mDimension; d++)
			{
				memcpy((i8*)&mySharePoint[d], (i8*)&p0.mSharePoint[i][d], sizeof(iWord));
			}

			for (u64 k = 0; k < p0.mNumCluster; k++)
			{
				p0.mDist[i][k] = signExtend(p0.mPrng.get<iWord>(), p0.mLenMod);
				if(norm1==1)
					programDistNorm1(p0.parties, mySharePoint, myShareCluster[k], p0.mDist[i][k], p0.mLenMod);
				else
					programDistNormInf(p0.parties, mySharePoint, myShareCluster[k], p0.mDist[i][k], p0.mLenMod);

				//std::cout << p0.mDist[i][k] << "  p0.mDist[i][k]\n";

			}
		}
	}

	timer.setTimePoint("DistDone");
	std::cout << "DistDone\n";

	//p0.Print();


	std::cout << timer << "\n";
	u64 bandwith = (p0.mChl.getTotalDataRecv() + p0.mChl.getTotalDataSent()) / (pow(10, 6));
	std::cout << "comm. = " << bandwith << " MB\n";


}
void party1_DistNorm(int norm1) //0 is inf, 1 is norm1
{
	Timer timer;
	IOService ios;
	Session ep10(ios, "127.0.0.1", SessionMode::Client);
	Channel chl10 = ep10.addChannel();
	u64 inMod = pow(2, inExMod);
	std::vector<std::vector<Word>> inputB;
	//loadTxtFile("I:/kmean-impl/dataset/s1.txt", inDimension, inputA, inputB);

	PRNG prng(ZeroBlock);
	inputB.resize(numberTestB);
	for (int i = 0; i < numberTestB; i++)
	{
		inputB[i].resize(inDimension);
		for (size_t j = 0; j < inDimension; j++)
			inputB[i][j] = prng.get<Word>() % inMod;
	}

	u64 inTotalPoint = numberTestA + inputB.size();
	//=======================offline===============================
	DataShare  p1;

	timer.setTimePoint("starts");

	p1.init(1, chl10, toBlock(34265), securityParams, inTotalPoint
		, inNumCluster, inNumCluster / 2, inNumCluster, inputB, inExMod, inDimension, numInteration);

	NaorPinkas baseOTs;
	baseOTs.receive(p1.mBaseChoices, p1.mRecvBaseMsg, p1.mPrng, p1.mChl, 1); //first OT for D_B
	p1.sender.setBaseOts(p1.mRecvBaseMsg, p1.mBaseChoices); //set base OT

	baseOTs.send(p1.mSendBaseMsg, p1.mPrng, p1.mChl, 1); //second OT for D_A
	p1.recv.setBaseOts(p1.mSendBaseMsg);

	timer.setTimePoint("baseOTDone");
	timer.setTimePoint("offlineDone");

	std::cout << "d=" << p1.mDimension << " | "
		<< "K= " << p1.mNumCluster << " | "
		<< "n= " << p1.mTotalNumPoints << " | "
		<< "l= " << p1.mLenMod << " | "
		<< "T= " << p1.mIteration << "\t party1_DistNorm("<< norm1 <<")\n";


	std::cout << "offlineDone\n";


	//=======================online (sharing)===============================
	p1.recvShareInput(0, 0, inNumCluster / 2);
	p1.sendShareInput(p1.mTheirNumPoints, inNumCluster / 2, inNumCluster);

	timer.setTimePoint("sharingInputsDone");

	//=======================Dist Norm1===============================
	for (u64 idxIter = 0; idxIter < numInteration; idxIter++)
	{

		std::vector<std::vector<iWord>> myShareCluster(p1.mNumCluster);

		for (u64 k = 0; k < p1.mNumCluster; k++)
		{
			myShareCluster[k].resize(p1.mDimension);
			for (u64 d = 0; d < p1.mDimension; d++)
			{
				memcpy((i8*)&myShareCluster[k][d], (u8*)&p1.mShareCluster[k][d], sizeof(Word));
				
				/*std::cout << IoStream::lock;
				std::cout << p1.mShareCluster[k][d] << " vs " << myShareCluster[k][d] << "\n";
				std::cout << IoStream::unlock;*/

			}

		}

		for (u64 i = 0; i < p1.mTotalNumPoints; i++)
		{
			std::vector<iWord> mySharePoint(p1.mDimension);
			for (u64 d = 0; d < p1.mDimension; d++)
			{
				memcpy((i8*)&mySharePoint[d], (i8*)&p1.mSharePoint[i][d], sizeof(iWord));
			}

			for (u64 k = 0; k < p1.mNumCluster; k++)
			{

				if (norm1 == 1)
					programDistNorm1(p1.parties, mySharePoint, myShareCluster[k], p1.mDist[i][k], p1.mLenMod);
				else
					programDistNormInf(p1.parties, mySharePoint, myShareCluster[k], p1.mDist[i][k], p1.mLenMod);

				/*std::cout << IoStream::lock;
				std::cout << p1.mDist[i][k] << "  p1.mDist[i][k]\n";
				std::cout << IoStream::unlock;*/
			
			}
		}
	}

	timer.setTimePoint("DistDone");
	std::cout << "DistDone\n";
	std::cout << timer << "\n";
	u64 bandwith = (p1.mChl.getTotalDataRecv() + p1.mChl.getTotalDataSent()) / (pow(10, 6));
	std::cout << "comm. = " << bandwith << " MB\n";

	//p1.Print();

}


void party0_Min()
{
	Timer timer;
	IOService ios;
	Session ep01(ios, "127.0.0.1", SessionMode::Server);
	Channel chl01 = ep01.addChannel();

	u64 inMod = pow(2, inExMod);
	std::vector<std::vector<Word>> inputA;
	//loadTxtFile("I:/kmean-impl/dataset/s1.txt", inDimension, inputA, inputB);

	PRNG prng(ZeroBlock);

	inputA.resize(numberTestA);
	for (int i = 0; i < numberTestA; i++)
	{
		inputA[i].resize(inDimension);
		for (size_t j = 0; j < inDimension; j++)
		{
			inputA[i][j] = prng.get<Word>() % inMod;

		}
	}

	u64 inTotalPoint = inputA.size() + numberTestB;
	//=======================offline===============================
	DataShare p0;

	p0.init(0, chl01, toBlock(34265), securityParams, inTotalPoint
		, inNumCluster, 0, inNumCluster / 2, inputA, inExMod, inDimension, numInteration);

	NaorPinkas baseOTs;
	baseOTs.send(p0.mSendBaseMsg, p0.mPrng, p0.mChl, 1); //first OT for D_B
	p0.recv.setBaseOts(p0.mSendBaseMsg);


	baseOTs.receive(p0.mBaseChoices, p0.mRecvBaseMsg, p0.mPrng, p0.mChl, 1); //second OT for D_A
	p0.sender.setBaseOts(p0.mRecvBaseMsg, p0.mBaseChoices); //set base OT


	timer.setTimePoint("baseOTDone");
	//std::cout << "baseOTDone\n";

	//=======================OT extension===============================
	//1st OT
	p0.mChoiceAllBitSharePointsOffline.resize(p0.mTotalNumPoints*p0.mDimension*p0.mLenMod);
	p0.mChoiceAllBitSharePointsOffline.randomize(p0.mPrng);

	p0.recv.receive(p0.mChoiceAllBitSharePointsOffline, p0.mRecvAllOtKeys, p0.mPrng, p0.mChl);

	//other OT direction
	p0.sender.send(p0.mSendAllOtKeys, p0.mPrng, p0.mChl);


	//===For cluster
	p0.allChoicesClusterOffline.randomize(p0.mPrng);
	p0.recv.receive(p0.allChoicesClusterOffline, p0.recvOTmsgClusterOffline, p0.mPrng, p0.mChl); //randome OT




	timer.setTimePoint("offlineDone");
	//std::cout << "offlineDone\n";

	std::cout << "d=" << p0.mDimension << " | "
		<< "K= " << p0.mNumCluster << " | "
		<< "n= " << p0.mTotalNumPoints << " | "
		<< "l= " << p0.mLenMod << " | "
		<< "T= " << p0.mIteration << "\t party0_Min\n";


	//=======================fake dist===============================

	for (u64 i = 0; i < p0.mTotalNumPoints; i++)
		for (u64 k = 0; k < p0.mNumCluster; k++)
		{
				p0.mDist[i][k] = signExtend(prng.get<Word>(), p0.mLenMod);
		}

	timer.setTimePoint("MinStart");

	std::vector<std::vector<iWord>> outShareSend0, outShareRecv0;
	std::vector<std::vector<BitVector>> outIdxShareSend0, outIdxShareRecv0;

	for (u64 idxIter = 0; idxIter < numInteration; idxIter++)
	{

		//=======================compute MIN===============================
		u64 numNodeThisLevel = p0.mNumCluster;
		BitVector oneBit("1");

		//=================1st level //TODO: remove dist
		for (u64 i = 0; i < p0.mTotalNumPoints; i++)
		{
			if (numNodeThisLevel % 2) //odd number
				p0.lastNode[i] = p0.mDist[i][p0.mNumCluster - 1];


			u64 sss= (numNodeThisLevel / 2);

			p0.mVecGcMinOutput[i].resize(sss *2);
			for (u64 k = 0; k < numNodeThisLevel / 2; k++)
			{
				programLessThan(p0.parties, p0.mDist[i][2 * k], p0.mDist[i][2 * k + 1], p0.mVecGcMinOutput[i], k, p0.mLenMod);
			}
			
			p0.mVecIdxMin[i].append(p0.mVecGcMinOutput[i]);

			if (numNodeThisLevel % 2) //odd number
				p0.mVecIdxMin[i].append(oneBit); //make sure last vecIdxMin[i]=1 

		}
		timer.setTimePoint("GC done");
		p0.amortBinArithMulsend(outShareSend0, p0.mVecGcMinOutput, p0.mDist); //(b^A \xor b^B)*(P^A)
		p0.amortBinArithMULrecv(outShareRecv0, p0.mVecGcMinOutput); //(b^A \xor b^B)*(P^B)
		p0.computeShareMin(outShareSend0, outShareRecv0);//compute (b1^A \xor b1^B)*(P1^A+P1^B)+(b2^A \xor b2^B)*(P2^A+P2^B)

		if (numNodeThisLevel % 2 == 1) //odd number => add last node to this level
			for (u64 i = 0; i < p0.mTotalNumPoints; i++)
				p0.mShareMin[i].push_back(p0.lastNode[i]);

		while (p0.mShareMin[0].size() > 1)//while (0)
		{
			//std::cout << "=======mShareMin============\n";

			p0.stepIdxMin *= 2;
			u64 numNodeThisLevel = p0.mShareMin[0].size();

			for (u64 i = 0; i < p0.mTotalNumPoints; i++)
			{
				if (numNodeThisLevel % 2) //odd number, keep last for next level
					p0.lastNode[i] = p0.mShareMin[i][p0.mShareMin[i].size() - 1];


				std::vector<iWord> dist1(numNodeThisLevel / 2), dist2(numNodeThisLevel / 2);
				for (u64 k = 0; k < dist1.size(); k++)
				{
					memcpy((i8*)&dist1[k], (i8*)&p0.mShareMin[i][2 * k], sizeof(iWord));
					memcpy((i8*)&dist2[k], (i8*)&p0.mShareMin[i][2 * k + 1], sizeof(iWord));
				}

				programLessThan(p0.parties, dist1, dist2, p0.mVecGcMinOutput[i], p0.mLenMod);
			}

			p0.amortBinArithMulGCsend(outShareSend0, outIdxShareSend0, p0.mVecGcMinOutput, p0.mShareMin, p0.mVecIdxMin, p0.stepIdxMin); //(b^A \xor b^B)*(P^A)
			p0.amortBinArithMulGCrecv(outShareRecv0, outIdxShareRecv0, p0.mVecGcMinOutput, p0.stepIdxMin); //(b^A \xor b^B)*(P^B)
			p0.computeShareMin(outShareSend0, outShareRecv0);//compute (b1^A \xor b1^B)*(P1^A+P1^B)+(b2^A \xor b2^B)*(P2^A+P2^B)
			p0.computeShareIdxMin(outIdxShareSend0, outIdxShareRecv0);


			if (numNodeThisLevel % 2 == 1) //odd number => add last node to this level
				for (u64 i = 0; i < p0.mTotalNumPoints; i++)
					p0.mShareMin[i].push_back(p0.lastNode[i]);
		}
	
	
	
	}
	timer.setTimePoint("MinDone");
	std::cout << "MinDone\n";

	//p0.Print();

	std::cout << timer << "\n";
	u64 bandwith = (p0.mChl.getTotalDataRecv() + p0.mChl.getTotalDataSent()) / (pow(10, 6));
	std::cout << "comm. = " << bandwith << " MB\n";
}
void party1_Min()
{
	Timer timer;
	IOService ios;
	Session ep10(ios, "127.0.0.1", SessionMode::Client);
	Channel chl10 = ep10.addChannel();

	u64 inMod = pow(2, inExMod);
	std::vector<std::vector<Word>> inputB;
	//loadTxtFile("I:/kmean-impl/dataset/s1.txt", inDimension, inputA, inputB);

	PRNG prng(ZeroBlock);
	inputB.resize(numberTestB);
	for (int i = 0; i < numberTestB; i++)
	{
		inputB[i].resize(inDimension);
		for (size_t j = 0; j < inDimension; j++)
			inputB[i][j] = prng.get<Word>() % inMod;
	}

	u64 inTotalPoint = numberTestA + inputB.size();
	//=======================offline===============================
	DataShare  p1;

	timer.setTimePoint("starts");

	p1.init(1, chl10, toBlock(34265), securityParams, inTotalPoint
		, inNumCluster, inNumCluster / 2, inNumCluster, inputB, inExMod, inDimension, numInteration);

	NaorPinkas baseOTs;
	baseOTs.receive(p1.mBaseChoices, p1.mRecvBaseMsg, p1.mPrng, p1.mChl, 1); //first OT for D_B
	p1.sender.setBaseOts(p1.mRecvBaseMsg, p1.mBaseChoices); //set base OT

	baseOTs.send(p1.mSendBaseMsg, p1.mPrng, p1.mChl, 1); //second OT for D_A
	p1.recv.setBaseOts(p1.mSendBaseMsg);

	timer.setTimePoint("baseOTDone");
	//std::cout << "baseOTDone\n";
	//=======================OT extension===============================
	//1st OT
	p1.sender.send(p1.mSendAllOtKeys, p1.mPrng, p1.mChl);

	//other OT direction
	p1.mChoiceAllBitSharePointsOffline.resize(p1.mTotalNumPoints*p1.mDimension*p1.mLenMod);
	p1.mChoiceAllBitSharePointsOffline.randomize(p1.mPrng);
	p1.recv.receive(p1.mChoiceAllBitSharePointsOffline, p1.mRecvAllOtKeys, p1.mPrng, p1.mChl);

	//===For cluster
	p1.sender.send(p1.sendOTmsgsClusterOffline, p1.mPrng, p1.mChl); //randome OT

	timer.setTimePoint("offlineDone");

	std::cout << "d=" << p1.mDimension << " | "
		<< "K= " << p1.mNumCluster << " | "
		<< "n= " << p1.mTotalNumPoints << " | "
		<< "l= " << p1.mLenMod << " | "
		<< "T= " << p1.mIteration << "\t party1_Min\n";


	std::cout << "offlineDone\n";


	//=======================fake dist===============================

	for (u64 i = 0; i < p1.mTotalNumPoints; i++)
		for (u64 k = 0; k < p1.mNumCluster; k++)
		{
			p1.mDist[i][k] = signExtend(prng.get<Word>(), p1.mLenMod);
		}

	timer.setTimePoint("MinStart");


	for (u64 idxIter = 0; idxIter < numInteration; idxIter++)
	{
		std::cout << "-";
		//=======================compute MIN===============================
		std::vector<std::vector<iWord>> outShareSend1, outShareRecv1;
		std::vector<std::vector<BitVector>> outIdxShareSend1, outIdxShareRecv1;

		u64 numNodeThisLevel = p1.mNumCluster;
		BitVector zeroBit("0");

		//=================1st level //TODO: remove dist
		for (u64 i = 0; i < p1.mTotalNumPoints; i++)
		{
			if (numNodeThisLevel % 2) //odd number
				p1.lastNode[i] = p1.mDist[i][p1.mNumCluster - 1];
		
			u64 sss = (numNodeThisLevel / 2);


			p1.mVecGcMinOutput[i].resize(sss*2);
			for (u64 k = 0; k < numNodeThisLevel / 2; k++)
			{
				programLessThan(p1.parties, p1.mDist[i][2 * k], p1.mDist[i][2 * k + 1], p1.mVecGcMinOutput[i],k, p1.mLenMod);
			}

			p1.mVecIdxMin[i].append(p1.mVecGcMinOutput[i]);//first level 10||01||01||01|1
			if (numNodeThisLevel % 2) //odd number
				p1.mVecIdxMin[i].append(zeroBit); //make sure last vecIdxMin[i]=1 

		}




		p1.amortBinArithMULrecv(outShareRecv1, p1.mVecGcMinOutput); //(b^A \xor b^B)*(P^A)
		p1.amortBinArithMulsend(outShareSend1, p1.mVecGcMinOutput, p1.mDist); //(b^A \xor b^B)*(P^B)
		p1.computeShareMin(outShareSend1, outShareRecv1); //compute (b1^A \xor b1^B)*(P1^A+P1^B)+(b2^A \xor b2^B)*(P2^A+P2^B)

		if (numNodeThisLevel % 2 == 1) //odd number => add last node to this level
			for (u64 i = 0; i < p1.mTotalNumPoints; i++)
				p1.mShareMin[i].push_back(p1.lastNode[i]);


		//=============2nd level loop until root==================================
		
		while (p1.mShareMin[0].size() > 1) //while (0)
		{

			p1.stepIdxMin *= 2;
			numNodeThisLevel = p1.mShareMin[0].size();

			for (u64 i = 0; i < p1.mTotalNumPoints; i++)
			{
				if (numNodeThisLevel % 2) //odd number, keep last for next level
					p1.lastNode[i] = p1.mShareMin[i][p1.mShareMin[i].size() - 1];

				std::vector<iWord> dist1(numNodeThisLevel / 2), dist2(numNodeThisLevel / 2);
				for (u64 k = 0; k < dist1.size(); k++)
				{
					memcpy((i8*)&dist1[k], (i8*)&p1.mShareMin[i][2 * k], sizeof(iWord));
					memcpy((i8*)&dist2[k], (i8*)&p1.mShareMin[i][2 * k + 1], sizeof(iWord));
				}

				programLessThan(p1.parties, dist1, dist2, p1.mVecGcMinOutput[i], p1.mLenMod);
			}


			p1.amortBinArithMulGCrecv(outShareRecv1, outIdxShareRecv1, p1.mVecGcMinOutput, p1.stepIdxMin); //(b^A \xor b^B)*(P^A)
			p1.amortBinArithMulGCsend(outShareSend1, outIdxShareSend1, p1.mVecGcMinOutput, p1.mShareMin, p1.mVecIdxMin, p1.stepIdxMin); //(b^A \xor b^B)*(P^B)
			p1.computeShareMin(outShareSend1, outShareRecv1); //compute (b1^A \xor b1^B)*(P1^A+P1^B)+(b2^A \xor b2^B)*(P2^A+P2^B)
			p1.computeShareIdxMin(outIdxShareSend1, outIdxShareRecv1);


			if (numNodeThisLevel % 2 == 1) //odd number => add last node to this level
				for (u64 i = 0; i < p1.mTotalNumPoints; i++)
					p1.mShareMin[i].push_back(p1.lastNode[i]);

		}
	}

	timer.setTimePoint("MinDone");

	std::cout << "\nMinDone";

	std::cout << timer << "\n";

	u64 bandwith = (p1.mChl.getTotalDataRecv() + p1.mChl.getTotalDataSent()) / (pow(10, 6));
	std::cout << "comm. = " << bandwith << " MB\n";

	

	//p1.Print();

}


void party0_Min_BaseLine()
{
	Timer timer;
	IOService ios;
	Session ep01(ios, "127.0.0.1", SessionMode::Server);
	Channel chl01 = ep01.addChannel();

	u64 inMod = pow(2, inExMod);
	std::vector<std::vector<Word>> inputA;
	//loadTxtFile("I:/kmean-impl/dataset/s1.txt", inDimension, inputA, inputB);

	PRNG prng(ZeroBlock);

	inputA.resize(numberTestA);
	for (int i = 0; i < numberTestA; i++)
	{
		inputA[i].resize(inDimension);
		for (size_t j = 0; j < inDimension; j++)
		{
			inputA[i][j] = prng.get<Word>() % inMod;

		}
	}

	u64 inTotalPoint = inputA.size() + numberTestB;
	//=======================offline===============================
	DataShare p0;

	p0.init(0, chl01, toBlock(34265), securityParams, inTotalPoint
		, inNumCluster, 0, inNumCluster / 2, inputA, inExMod, inDimension, numInteration);

	NaorPinkas baseOTs;
	baseOTs.send(p0.mSendBaseMsg, p0.mPrng, p0.mChl, 1); //first OT for D_B
	p0.recv.setBaseOts(p0.mSendBaseMsg);


	baseOTs.receive(p0.mBaseChoices, p0.mRecvBaseMsg, p0.mPrng, p0.mChl, 1); //second OT for D_A
	p0.sender.setBaseOts(p0.mRecvBaseMsg, p0.mBaseChoices); //set base OT


	timer.setTimePoint("baseOTDone");
	//std::cout << "baseOTDone\n";

	//=======================OT extension===============================
	//1st OT
	p0.mChoiceAllBitSharePointsOffline.resize(p0.mTotalNumPoints*p0.mDimension*p0.mLenMod);
	p0.mChoiceAllBitSharePointsOffline.randomize(p0.mPrng);

	p0.recv.receive(p0.mChoiceAllBitSharePointsOffline, p0.mRecvAllOtKeys, p0.mPrng, p0.mChl);

	//other OT direction
	p0.sender.send(p0.mSendAllOtKeys, p0.mPrng, p0.mChl);


	//===For cluster
	p0.allChoicesClusterOffline.randomize(p0.mPrng);
	p0.recv.receive(p0.allChoicesClusterOffline, p0.recvOTmsgClusterOffline, p0.mPrng, p0.mChl); //randome OT




	timer.setTimePoint("offlineDone");
	//std::cout << "offlineDone\n";

	std::cout << "d=" << p0.mDimension << " | "
		<< "K= " << p0.mNumCluster << " | "
		<< "n= " << p0.mTotalNumPoints << " | "
		<< "l= " << p0.mLenMod << " | "
		<< "T= " << p0.mIteration << "\t party0_Min_BaseLine\n";


	//=======================fake dist===============================

	for (u64 i = 0; i < p0.mTotalNumPoints; i++)
		for (u64 k = 0; k < p0.mNumCluster; k++)
		{
			p0.mDist[i][k] = signExtend(prng.get<Word>(), p0.mLenMod);
		}

	timer.setTimePoint("MinStart");

	for (u64 idxIter = 0; idxIter < numInteration; idxIter++)
	{
		for (u64 i = 0; i < p0.mTotalNumPoints; i++)
		{
			programLessThanBaseLine(p0.parties, p0.mDist[i], p0.mVecIdxMin[i], p0.mLenMod);
		}
	}
	timer.setTimePoint("MinDone");
	std::cout << "MinDone\n";

	//p0.Print();

	std::cout << timer << "\n";
	u64 bandwith = (p0.mChl.getTotalDataRecv() + p0.mChl.getTotalDataSent()) / (pow(10, 6));
	std::cout << "comm. = " << bandwith << " MB\n";
}
void party1_Min_BaseLine()
{
	Timer timer;
	IOService ios;
	Session ep10(ios, "127.0.0.1", SessionMode::Client);
	Channel chl10 = ep10.addChannel();
	u64 inMod = pow(2, inExMod);
	std::vector<std::vector<Word>> inputB;
	//loadTxtFile("I:/kmean-impl/dataset/s1.txt", inDimension, inputA, inputB);

	PRNG prng(ZeroBlock);
	inputB.resize(numberTestB);
	for (int i = 0; i < numberTestB; i++)
	{
		inputB[i].resize(inDimension);
		for (size_t j = 0; j < inDimension; j++)
			inputB[i][j] = prng.get<Word>() % inMod;
	}

	u64 inTotalPoint = numberTestA + inputB.size();
	//=======================offline===============================
	DataShare  p1;

	timer.setTimePoint("starts");

	p1.init(1, chl10, toBlock(34265), securityParams, inTotalPoint
		, inNumCluster, inNumCluster / 2, inNumCluster, inputB, inExMod, inDimension, numInteration);

	NaorPinkas baseOTs;
	baseOTs.receive(p1.mBaseChoices, p1.mRecvBaseMsg, p1.mPrng, p1.mChl, 1); //first OT for D_B
	p1.sender.setBaseOts(p1.mRecvBaseMsg, p1.mBaseChoices); //set base OT

	baseOTs.send(p1.mSendBaseMsg, p1.mPrng, p1.mChl, 1); //second OT for D_A
	p1.recv.setBaseOts(p1.mSendBaseMsg);

	timer.setTimePoint("baseOTDone");
	//std::cout << "baseOTDone\n";
	//=======================OT extension===============================
	//1st OT
	p1.sender.send(p1.mSendAllOtKeys, p1.mPrng, p1.mChl);

	//other OT direction
	p1.mChoiceAllBitSharePointsOffline.resize(p1.mTotalNumPoints*p1.mDimension*p1.mLenMod);
	p1.mChoiceAllBitSharePointsOffline.randomize(p1.mPrng);
	p1.recv.receive(p1.mChoiceAllBitSharePointsOffline, p1.mRecvAllOtKeys, p1.mPrng, p1.mChl);

	//===For cluster
	p1.sender.send(p1.sendOTmsgsClusterOffline, p1.mPrng, p1.mChl); //randome OT

	timer.setTimePoint("offlineDone");

	std::cout << "d=" << p1.mDimension << " | "
		<< "K= " << p1.mNumCluster << " | "
		<< "n= " << p1.mTotalNumPoints << " | "
		<< "l= " << p1.mLenMod << " | "
		<< "T= " << p1.mIteration << "\t party1_Min_BaseLine\n";


	std::cout << "offlineDone\n";


	//=======================fake dist===============================

	for (u64 i = 0; i < p1.mTotalNumPoints; i++)
		for (u64 k = 0; k < p1.mNumCluster; k++)
		{
			p1.mDist[i][k] = signExtend(prng.get<Word>(), p1.mLenMod);
		}

	timer.setTimePoint("MinStart");


	for (u64 idxIter = 0; idxIter < numInteration; idxIter++)
	{
		for (u64 i = 0; i < p1.mTotalNumPoints; i++)
		{
			programLessThanBaseLine(p1.parties, p1.mDist[i], p1.mVecIdxMin[i], p1.mLenMod);
		}
	}

	timer.setTimePoint("MinDone");

	std::cout << "\nMinDone";

	std::cout << timer << "\n";

	u64 bandwith = (p1.mChl.getTotalDataRecv() + p1.mChl.getTotalDataSent()) / (pow(10, 6));
	std::cout << "comm. = " << bandwith << " MB\n";
	//p1.Print();

}




void party0_UpdateCluster()
{
	Timer timer;
	IOService ios;
	Session ep01(ios, "127.0.0.1", SessionMode::Server);
	Channel chl01 = ep01.addChannel();

	u64 inMod = pow(2, inExMod);
	std::vector<std::vector<Word>> inputA;
	//loadTxtFile("I:/kmean-impl/dataset/s1.txt", inDimension, inputA, inputB);

	PRNG prng(ZeroBlock);

	inputA.resize(numberTestA);
	for (int i = 0; i < numberTestA; i++)
	{
		inputA[i].resize(inDimension);
		for (size_t j = 0; j < inDimension; j++)
		{
			inputA[i][j] = prng.get<Word>() % inMod;

		}
	}

	u64 inTotalPoint = inputA.size() + numberTestB;
	//=======================offline===============================
	DataShare p0;

	p0.init(0, chl01, toBlock(34265), securityParams, inTotalPoint
		, inNumCluster, 0, inNumCluster / 2, inputA, inExMod, inDimension, numInteration);

	NaorPinkas baseOTs;
	baseOTs.send(p0.mSendBaseMsg, p0.mPrng, p0.mChl, 1); //first OT for D_B
	p0.recv.setBaseOts(p0.mSendBaseMsg);


	baseOTs.receive(p0.mBaseChoices, p0.mRecvBaseMsg, p0.mPrng, p0.mChl, 1); //second OT for D_A
	p0.sender.setBaseOts(p0.mRecvBaseMsg, p0.mBaseChoices); //set base OT


	timer.setTimePoint("baseOTDone");
	//std::cout << "baseOTDone\n";

	//=======================OT extension===============================
	//1st OT
	p0.mChoiceAllBitSharePointsOffline.resize(p0.mTotalNumPoints*p0.mDimension*p0.mLenMod);
	p0.mChoiceAllBitSharePointsOffline.randomize(p0.mPrng);

	p0.recv.receive(p0.mChoiceAllBitSharePointsOffline, p0.mRecvAllOtKeys, p0.mPrng, p0.mChl);

	//other OT direction
	p0.sender.send(p0.mSendAllOtKeys, p0.mPrng, p0.mChl);


	//===For cluster
	p0.allChoicesClusterOffline.randomize(p0.mPrng);
	p0.recv.receive(p0.allChoicesClusterOffline, p0.recvOTmsgClusterOffline, p0.mPrng, p0.mChl); //randome OT




	timer.setTimePoint("offlineDone");
	//std::cout << "offlineDone\n";

	std::cout << "d=" << p0.mDimension << " | "
		<< "K= " << p0.mNumCluster << " | "
		<< "n= " << p0.mTotalNumPoints << " | "
		<< "l= " << p0.mLenMod << " | "
		<< "T= " << p0.mIteration << "\t party0_UpdateCluster\n";


	//=======================online (sharing)===============================

	p0.sendShareInput(0, 0, inNumCluster / 2);
	p0.recvShareInput(p0.mPoint.size(), inNumCluster / 2, inNumCluster);

	timer.setTimePoint("sharingInputsDone");
	//std::cout << "sharingInputsDone\n";


	//=======================online OT (setting up keys for adaptive ED)===============================

	p0.correctAllChoiceRecv();//1st OT
	p0.correctAllChoiceSender();////other OT direction
								//std::cout << "correctAllChoice\n";
	timer.setTimePoint("correctOTDone");
	p0.setPRNGseeds();

	timer.setTimePoint("OtKeysDone");
	//std::cout << "OtKeysDone\n";

	//fake dist + vecMin
	for (u64 i = 0; i < p0.mTotalNumPoints; i++) // points
	{
		for (u64 k = 0; k < p0.mNumCluster; k++) // cluster
		{
			p0.mDist[i][k] = p0TestDist[i][k];
		}
		p0.mVecIdxMin[i] = p0TestVecIdxMin[i];
	}

	std::cout << p0.mDist[1][1] << "  vs  " << p0.mVecIdxMin[1] << "\n";
	timer.setTimePoint("UpdateStart");


	for (u64 idxIter = 0; idxIter < numInteration; idxIter++)
	{
		////=====================compute nom/dec===========================
		std::vector<std::vector<iWord>> shareNomSend0, shareNomRecv0;
		std::vector<iWord> shareDenSend0, shareDenRecv0;
		p0.vecMinTranspose();
		p0.amortBinArithClustsend(p0.mVecIdxMinTranspose, shareNomSend0, shareDenSend0, true); //compute Den as (b^A \xor b^B)*1
		p0.amortBinArithClustrecv(p0.mVecIdxMinTranspose, shareNomRecv0, shareDenRecv0, false); // no Den
		p0.computeShareCluster(shareNomSend0, shareNomRecv0, shareDenSend0, shareDenRecv0);


		////=====================division===========================
		u8 isDenZero0; //check den=0?
		for (u64 k = 0; k < p0.mNumCluster; k++)
		{
				programEqualZero(p0.parties, p0.mShareDecCluster[k], isDenZero0, p0.mLenMod);
				p0.mChl.send(isDenZero0);
				if (isDenZero0)
				{
					for (u64 d = 0; d < p0.mDimension; d++)
					{
						Word myRandomShare = p0.mPrng.get<Word>() % p0.mMod;
						programDiv(p0.parties, p0.mShareNomCluster[k][d], p0.mShareDecCluster[k], myRandomShare, p0.mLenMod);
						p0.mShareCluster[k][d] = myRandomShare;
					}
				}

		}

	}

	timer.setTimePoint("UpdateDone");
	std::cout << "UpdateDone\n";

	//p0.Print();


	std::cout << timer << "\n";
	u64 bandwith = (p0.mChl.getTotalDataRecv() + p0.mChl.getTotalDataSent()) / (pow(10, 6));
	std::cout << "comm. = " << bandwith << " MB\n";


}
void party1_UpdateCluster()
{

	Timer timer;
	IOService ios;
	Session ep10(ios, "127.0.0.1", SessionMode::Client);
	Channel chl10 = ep10.addChannel();
	u64 inMod = pow(2, inExMod);
	std::vector<std::vector<Word>> inputB;
	//loadTxtFile("I:/kmean-impl/dataset/s1.txt", inDimension, inputA, inputB);

	PRNG prng(ZeroBlock);
	inputB.resize(numberTestB);
	for (int i = 0; i < numberTestB; i++)
	{
		inputB[i].resize(inDimension);
		for (size_t j = 0; j < inDimension; j++)
			inputB[i][j] = prng.get<Word>() % inMod;
	}

	u64 inTotalPoint = numberTestA + inputB.size();
	//=======================offline===============================
	DataShare  p1;

	timer.setTimePoint("starts");

	p1.init(1, chl10, toBlock(34265), securityParams, inTotalPoint
		, inNumCluster, inNumCluster / 2, inNumCluster, inputB, inExMod, inDimension, numInteration);

	NaorPinkas baseOTs;
	baseOTs.receive(p1.mBaseChoices, p1.mRecvBaseMsg, p1.mPrng, p1.mChl, 1); //first OT for D_B
	p1.sender.setBaseOts(p1.mRecvBaseMsg, p1.mBaseChoices); //set base OT

	baseOTs.send(p1.mSendBaseMsg, p1.mPrng, p1.mChl, 1); //second OT for D_A
	p1.recv.setBaseOts(p1.mSendBaseMsg);

	timer.setTimePoint("baseOTDone");
	//std::cout << "baseOTDone\n";
	//=======================OT extension===============================
	//1st OT
	p1.sender.send(p1.mSendAllOtKeys, p1.mPrng, p1.mChl);

	//other OT direction
	p1.mChoiceAllBitSharePointsOffline.resize(p1.mTotalNumPoints*p1.mDimension*p1.mLenMod);
	p1.mChoiceAllBitSharePointsOffline.randomize(p1.mPrng);
	p1.recv.receive(p1.mChoiceAllBitSharePointsOffline, p1.mRecvAllOtKeys, p1.mPrng, p1.mChl);

	//===For cluster
	p1.sender.send(p1.sendOTmsgsClusterOffline, p1.mPrng, p1.mChl); //randome OT

	timer.setTimePoint("offlineDone");

	std::cout << "d=" << p1.mDimension << " | "
		<< "K= " << p1.mNumCluster << " | "
		<< "n= " << p1.mTotalNumPoints << " | "
		<< "l= " << p1.mLenMod << " | "
		<< "T= " << p1.mIteration << "\t party1_UpdateCluster\n";


	std::cout << "offlineDone\n";


	//=======================online (sharing)===============================
	p1.recvShareInput(0, 0, inNumCluster / 2);
	p1.sendShareInput(p1.mTheirNumPoints, inNumCluster / 2, inNumCluster);

	timer.setTimePoint("sharingInputsDone");

	//=======================online OT (setting up keys for adaptive ED)===============================
	p1.correctAllChoiceSender(); //1st OT
	p1.correctAllChoiceRecv();////other OT direction
	std::cout << "correctOTDone\n";
	timer.setTimePoint("correctOTDone");
	p1.setPRNGseeds();

	timer.setTimePoint("OTkeysDone");
	std::cout << "OTkeysDone\n";


	//std::cout << "OtKeysDone\n";

	//fake dist + vecMin
	for (u64 i = 0; i < p1.mTotalNumPoints; i++) // points
	{
		for (u64 k = 0; k < p1.mNumCluster; k++) // cluster
		{
			p1.mDist[i][k] = p1TestDist[i][k];
		}
		p1.mVecIdxMin[i] = p1TestVecIdxMin[i];
	}

	std::cout << p1.mDist[1][1] << "  vs  "<< p1.mVecIdxMin[1] <<"\n";
	timer.setTimePoint("UpdateStart");


	for (u64 idxIter = 0; idxIter < numInteration; idxIter++)
	{
		////=====================compute nom/dec===========================
		std::vector<std::vector<iWord>>  shareNomSend1, shareNomRecv1;
		std::vector<iWord> shareDenSend1, shareDenRecv1;
		p1.vecMinTranspose();
		p1.amortBinArithClustrecv(p1.mVecIdxMinTranspose, shareNomRecv1, shareDenRecv1, true);
		p1.amortBinArithClustsend(p1.mVecIdxMinTranspose, shareNomSend1, shareDenSend1, false);
		p1.computeShareCluster(shareNomSend1, shareNomRecv1, shareDenSend1, shareDenRecv1);

		////=====================division===========================
		u8 isDenZero1; //check den=0?
		for (u64 k = 0; k < p1.mNumCluster; k++)
		{
			programEqualZero(p1.parties, p1.mShareDecCluster[k], isDenZero1, p1.mLenMod);
			p1.mChl.recv(isDenZero1);
			if (isDenZero1)
			{
				Word myShare = 0;
				for (u64 d = 0; d < p1.mDimension; d++)
				{
					programDiv(p1.parties, p1.mShareNomCluster[k][d], p1.mShareDecCluster[k], myShare, p1.mLenMod);
					p1.mShareCluster[k][d] = myShare;
				}
			}
		}

	}

	timer.setTimePoint("UpdateDone");
	std::cout << "UpdateDone\n";

	//p0.Print();


	std::cout << timer << "\n";
	u64 bandwith = (p1.mChl.getTotalDataRecv() + p1.mChl.getTotalDataSent()) / (pow(10, 6));
	std::cout <<"comm. = "<< bandwith << " MB\n";


}


void party0_Clustering()
{
	Timer timer;
	IOService ios;
	Session ep01(ios, "127.0.0.1", SessionMode::Server);
	Channel chl01 = ep01.addChannel();

	u64 inMod = pow(2, inExMod);
	std::vector<std::vector<Word>> inputA;
	//loadTxtFile("I:/kmean-impl/dataset/s1.txt", inDimension, inputA, inputB);

	PRNG prng(ZeroBlock);

	inputA.resize(numberTestA);
	for (int i = 0; i < numberTestA; i++)
	{
		inputA[i].resize(inDimension);
		for (size_t j = 0; j < inDimension; j++)
		{
			inputA[i][j] = prng.get<Word>() % inMod;

		}
	}

	u64 inTotalPoint = inputA.size() + numberTestB;
	//=======================offline===============================
	DataShare p0;

	p0.init(0, chl01, toBlock(34265), securityParams, inTotalPoint
		, inNumCluster, 0, inNumCluster / 2, inputA, inExMod, inDimension, numInteration);

	NaorPinkas baseOTs;
	baseOTs.send(p0.mSendBaseMsg, p0.mPrng, p0.mChl, 1); //first OT for D_B
	p0.recv.setBaseOts(p0.mSendBaseMsg);


	baseOTs.receive(p0.mBaseChoices, p0.mRecvBaseMsg, p0.mPrng, p0.mChl, 1); //second OT for D_A
	p0.sender.setBaseOts(p0.mRecvBaseMsg, p0.mBaseChoices); //set base OT


	timer.setTimePoint("baseOTDone");
	//std::cout << "baseOTDone\n";

	//=======================OT extension===============================
	//1st OT
	p0.mChoiceAllBitSharePointsOffline.resize(p0.mTotalNumPoints*p0.mDimension*p0.mLenMod);
	p0.mChoiceAllBitSharePointsOffline.randomize(p0.mPrng);

	p0.recv.receive(p0.mChoiceAllBitSharePointsOffline, p0.mRecvAllOtKeys, p0.mPrng, p0.mChl);

	//other OT direction
	p0.sender.send(p0.mSendAllOtKeys, p0.mPrng, p0.mChl);


	//===For cluster
	p0.allChoicesClusterOffline.randomize(p0.mPrng);
	p0.recv.receive(p0.allChoicesClusterOffline, p0.recvOTmsgClusterOffline, p0.mPrng, p0.mChl); //randome OT




	timer.setTimePoint("offlineDone");
	//std::cout << "offlineDone\n";

	std::cout << "d=" << p0.mDimension << " | "
		<< "K= " << p0.mNumCluster << " | "
		<< "n= " << p0.mTotalNumPoints << " | "
		<< "l= " << p0.mLenMod << " | "
		<< "T= " << p0.mIteration << "\t party0_Dist\n";


	//=======================online (sharing)===============================

	p0.sendShareInput(0, 0, inNumCluster / 2);
	p0.recvShareInput(p0.mPoint.size(), inNumCluster / 2, inNumCluster);

	timer.setTimePoint("sharingInputsDone");
	//std::cout << "sharingInputsDone\n";


	//=======================online OT (setting up keys for adaptive ED)===============================

	p0.correctAllChoiceRecv();//1st OT
	p0.correctAllChoiceSender();////other OT direction
								//std::cout << "correctAllChoice\n";
	timer.setTimePoint("correctOTDone");
	p0.setPRNGseeds();

	timer.setTimePoint("OtKeysDone");
	//std::cout << "OtKeysDone\n";

	std::vector<std::vector<iWord>> outShareSend0, outShareRecv0;
	std::vector<std::vector<BitVector>> outIdxShareSend0, outIdxShareRecv0;
	for (u64 idxIter = 0; idxIter < numInteration; idxIter++)
	{
		//std::cout << "-";
		//=======================online MUL===============================

		//(c^A[k][d]*c^B[k][d])
		p0.mProdCluster = p0.amortMULrecv(p0.mShareCluster, idxIter*p0.mNumCluster*p0.mDimension*p0.mLenMod); //compute C^Ak*C^Bk
																											  //(p^A[i][d]*(p^B[i][d]-c^B[k][d]) => A receiver
		for (u64 i = 0; i < p0.mTotalNumPoints; i++)
			for (u64 d = 0; d < p0.mDimension; d++)
				p0.mProdPointPPC[i][d] = p0.amortAdaptMULrecv(i, d, p0.mNumCluster); //for each point to all clusters

																					 //(p^B[i][d]*c^A[k][d]) => A is sender
		for (u64 d = 0; d < p0.mDimension; d++)
			for (u64 k = 0; k < p0.mNumCluster; k++)
				memcpy((i8*)&p0.prodTempC[d][k], (u8*)&p0.mShareCluster[k][d], p0.mLenModinByte); //c^A[k][d]

		for (u64 i = 0; i < p0.mTotalNumPoints; i++)
			for (u64 d = 0; d < p0.mDimension; d++)
				p0.mProdPointPC[i][d] = p0.amortAdaptMULsend(i, d, p0.prodTempC[d]); //for each point to all clusters

																					 
       //=======================online locally compute ED===============================
		p0.computeDist();


		//=======================compute MIN===============================
		u64 numNodeThisLevel = p0.mNumCluster;
		BitVector oneBit("1");

		//=================1st level //TODO: remove dist
		for (u64 i = 0; i < p0.mTotalNumPoints; i++)
		{
			if (numNodeThisLevel % 2) //odd number
				p0.lastNode[i] = p0.mDist[i][p0.mNumCluster - 1];


			u64 sss = (numNodeThisLevel / 2);

			p0.mVecGcMinOutput[i].resize(sss * 2);
			for (u64 k = 0; k < numNodeThisLevel / 2; k++)
			{
				programLessThan(p0.parties, p0.mDist[i][2 * k], p0.mDist[i][2 * k + 1], p0.mVecGcMinOutput[i], k, p0.mLenMod);
			}

			p0.mVecIdxMin[i].append(p0.mVecGcMinOutput[i]);

			if (numNodeThisLevel % 2) //odd number
				p0.mVecIdxMin[i].append(oneBit); //make sure last vecIdxMin[i]=1 

		}
		p0.amortBinArithMulsend(outShareSend0, p0.mVecGcMinOutput, p0.mDist); //(b^A \xor b^B)*(P^A)
		p0.amortBinArithMULrecv(outShareRecv0, p0.mVecGcMinOutput); //(b^A \xor b^B)*(P^B)
		p0.computeShareMin(outShareSend0, outShareRecv0);//compute (b1^A \xor b1^B)*(P1^A+P1^B)+(b2^A \xor b2^B)*(P2^A+P2^B)

		if (numNodeThisLevel % 2 == 1) //odd number => add last node to this level
			for (u64 i = 0; i < p0.mTotalNumPoints; i++)
				p0.mShareMin[i].push_back(p0.lastNode[i]);

		while (p0.mShareMin[0].size() > 1)//while (0)
		{
			//std::cout << "=======mShareMin============\n";

			p0.stepIdxMin *= 2;
			u64 numNodeThisLevel = p0.mShareMin[0].size();

			for (u64 i = 0; i < p0.mTotalNumPoints; i++)
			{
				if (numNodeThisLevel % 2) //odd number, keep last for next level
					p0.lastNode[i] = p0.mShareMin[i][p0.mShareMin[i].size() - 1];


				std::vector<iWord> dist1(numNodeThisLevel / 2), dist2(numNodeThisLevel / 2);
				for (u64 k = 0; k < dist1.size(); k++)
				{
					memcpy((i8*)&dist1[k], (i8*)&p0.mShareMin[i][2 * k], sizeof(iWord));
					memcpy((i8*)&dist2[k], (i8*)&p0.mShareMin[i][2 * k + 1], sizeof(iWord));
				}

				programLessThan(p0.parties, dist1, dist2, p0.mVecGcMinOutput[i], p0.mLenMod);
			}

			p0.amortBinArithMulGCsend(outShareSend0, outIdxShareSend0, p0.mVecGcMinOutput, p0.mShareMin, p0.mVecIdxMin, p0.stepIdxMin); //(b^A \xor b^B)*(P^A)
			p0.amortBinArithMulGCrecv(outShareRecv0, outIdxShareRecv0, p0.mVecGcMinOutput, p0.stepIdxMin); //(b^A \xor b^B)*(P^B)
			p0.computeShareMin(outShareSend0, outShareRecv0);//compute (b1^A \xor b1^B)*(P1^A+P1^B)+(b2^A \xor b2^B)*(P2^A+P2^B)
			p0.computeShareIdxMin(outIdxShareSend0, outIdxShareRecv0);


			if (numNodeThisLevel % 2 == 1) //odd number => add last node to this level
				for (u64 i = 0; i < p0.mTotalNumPoints; i++)
					p0.mShareMin[i].push_back(p0.lastNode[i]);
		}


		////=====================compute nom/dec===========================
		std::vector<std::vector<iWord>> shareNomSend0, shareNomRecv0;
		std::vector<iWord> shareDenSend0, shareDenRecv0;
		p0.vecMinTranspose();
		p0.amortBinArithClustsend(p0.mVecIdxMinTranspose, shareNomSend0, shareDenSend0, true); //compute Den as (b^A \xor b^B)*1
		p0.amortBinArithClustrecv(p0.mVecIdxMinTranspose, shareNomRecv0, shareDenRecv0, false); // no Den
		p0.computeShareCluster(shareNomSend0, shareNomRecv0, shareDenSend0, shareDenRecv0);


		////=====================division===========================
		u8 isDenZero0; //check den=0?
		for (u64 k = 0; k < p0.mNumCluster; k++)
		{
			programEqualZero(p0.parties, p0.mShareDecCluster[k], isDenZero0, p0.mLenMod);
			p0.mChl.send(isDenZero0);
			if (isDenZero0)
			{
				for (u64 d = 0; d < p0.mDimension; d++)
				{
					Word myRandomShare = p0.mPrng.get<Word>() % p0.mMod;
					programDiv(p0.parties, p0.mShareNomCluster[k][d], p0.mShareDecCluster[k], myRandomShare, p0.mLenMod);
					p0.mShareCluster[k][d] = myRandomShare;
				}
			}

		}

	}

	timer.setTimePoint("ClusterDone");
	std::cout << "ClusterDone\n";

	//p0.Print();


	std::cout << timer << "\n";
	u64 bandwith = (p0.mChl.getTotalDataRecv() + p0.mChl.getTotalDataSent()) / (pow(10, 6));
	std::cout << "comm. = " << bandwith << " MB\n";

}
void party1_Clustering()
{
	Timer timer;
	IOService ios;
	Session ep10(ios, "127.0.0.1", SessionMode::Client);
	Channel chl10 = ep10.addChannel();
	u64 inMod = pow(2, inExMod);
	std::vector<std::vector<Word>> inputB;
	//loadTxtFile("I:/kmean-impl/dataset/s1.txt", inDimension, inputA, inputB);

	PRNG prng(ZeroBlock);
	inputB.resize(numberTestB);
	for (int i = 0; i < numberTestB; i++)
	{
		inputB[i].resize(inDimension);
		for (size_t j = 0; j < inDimension; j++)
			inputB[i][j] = prng.get<Word>() % inMod;
	}

	u64 inTotalPoint = numberTestA + inputB.size();
	//=======================offline===============================
	DataShare  p1;

	timer.setTimePoint("starts");

	p1.init(1, chl10, toBlock(34265), securityParams, inTotalPoint
		, inNumCluster, inNumCluster / 2, inNumCluster, inputB, inExMod, inDimension, numInteration);

	NaorPinkas baseOTs;
	baseOTs.receive(p1.mBaseChoices, p1.mRecvBaseMsg, p1.mPrng, p1.mChl, 1); //first OT for D_B
	p1.sender.setBaseOts(p1.mRecvBaseMsg, p1.mBaseChoices); //set base OT

	baseOTs.send(p1.mSendBaseMsg, p1.mPrng, p1.mChl, 1); //second OT for D_A
	p1.recv.setBaseOts(p1.mSendBaseMsg);

	timer.setTimePoint("baseOTDone");
	//std::cout << "baseOTDone\n";
	//=======================OT extension===============================
	//1st OT
	p1.sender.send(p1.mSendAllOtKeys, p1.mPrng, p1.mChl);

	//other OT direction
	p1.mChoiceAllBitSharePointsOffline.resize(p1.mTotalNumPoints*p1.mDimension*p1.mLenMod);
	p1.mChoiceAllBitSharePointsOffline.randomize(p1.mPrng);
	p1.recv.receive(p1.mChoiceAllBitSharePointsOffline, p1.mRecvAllOtKeys, p1.mPrng, p1.mChl);

	//===For cluster
	p1.sender.send(p1.sendOTmsgsClusterOffline, p1.mPrng, p1.mChl); //randome OT

	timer.setTimePoint("offlineDone");

	std::cout << "d=" << p1.mDimension << " | "
		<< "K= " << p1.mNumCluster << " | "
		<< "n= " << p1.mTotalNumPoints << " | "
		<< "l= " << p1.mLenMod << " | "
		<< "T= " << p1.mIteration << "\t party1_Dist\n";


	std::cout << "offlineDone\n";


	//=======================online (sharing)===============================
	p1.recvShareInput(0, 0, inNumCluster / 2);
	p1.sendShareInput(p1.mTheirNumPoints, inNumCluster / 2, inNumCluster);

	timer.setTimePoint("sharingInputsDone");

	//=======================online OT (setting up keys for adaptive ED)===============================
	p1.correctAllChoiceSender(); //1st OT
	p1.correctAllChoiceRecv();////other OT direction
	std::cout << "correctOTDone\n";
	timer.setTimePoint("correctOTDone");
	p1.setPRNGseeds();

	timer.setTimePoint("OTkeysDone");
	std::cout << "OTkeysDone\n";


	for (u64 idxIter = 0; idxIter < numInteration; idxIter++)
	{
		std::cout << "-";

		//=======================online MUL===============================
		p1.mProdCluster = p1.amortMULsend(p1.mShareCluster, idxIter*p1.mNumCluster*p1.mDimension*p1.mLenMod);//(c^A[k][d]*c^B[k][d])

																											 //(p^A[i][d]*(p^B[i][d]-c^B[k][d])
		for (u64 i = 0; i < p1.mTotalNumPoints; i++)
			for (u64 d = 0; d < p1.mDimension; d++)
			{
				//prodTempPC=pid-ckl
				for (u64 k = 0; k < p1.mNumCluster; k++)
					p1.prodTempPC[i][d][k] = (p1.mSharePoint[i][d].mArithShare - p1.mShareCluster[k][d]);

				p1.mProdPointPPC[i][d] = p1.amortAdaptMULsend(i, d, p1.prodTempPC[i][d]);

			}

		//(p^B[i][d]*c^A[k][d]) => B is recv
		for (u64 i = 0; i < p1.mTotalNumPoints; i++)
			for (u64 d = 0; d < p1.mDimension; d++)
				p1.mProdPointPC[i][d] = p1.amortAdaptMULrecv(i, d, p1.mNumCluster); //for each point to all clusters

		
																					
        //=======================online locally compute ED===============================
		p1.computeDist();


		//=======================compute MIN===============================
		std::vector<std::vector<iWord>> outShareSend1, outShareRecv1;
		std::vector<std::vector<BitVector>> outIdxShareSend1, outIdxShareRecv1;

		u64 numNodeThisLevel = p1.mNumCluster;
		BitVector zeroBit("0");

		//=================1st level //TODO: remove dist
		for (u64 i = 0; i < p1.mTotalNumPoints; i++)
		{
			if (numNodeThisLevel % 2) //odd number
				p1.lastNode[i] = p1.mDist[i][p1.mNumCluster - 1];

			u64 sss = (numNodeThisLevel / 2);


			p1.mVecGcMinOutput[i].resize(sss * 2);
			for (u64 k = 0; k < numNodeThisLevel / 2; k++)
			{
				programLessThan(p1.parties, p1.mDist[i][2 * k], p1.mDist[i][2 * k + 1], p1.mVecGcMinOutput[i], k, p1.mLenMod);
			}

			p1.mVecIdxMin[i].append(p1.mVecGcMinOutput[i]);//first level 10||01||01||01|1
			if (numNodeThisLevel % 2) //odd number
				p1.mVecIdxMin[i].append(zeroBit); //make sure last vecIdxMin[i]=1 

		}




		p1.amortBinArithMULrecv(outShareRecv1, p1.mVecGcMinOutput); //(b^A \xor b^B)*(P^A)
		p1.amortBinArithMulsend(outShareSend1, p1.mVecGcMinOutput, p1.mDist); //(b^A \xor b^B)*(P^B)
		p1.computeShareMin(outShareSend1, outShareRecv1); //compute (b1^A \xor b1^B)*(P1^A+P1^B)+(b2^A \xor b2^B)*(P2^A+P2^B)

		if (numNodeThisLevel % 2 == 1) //odd number => add last node to this level
			for (u64 i = 0; i < p1.mTotalNumPoints; i++)
				p1.mShareMin[i].push_back(p1.lastNode[i]);


		//=============2nd level loop until root==================================

		while (p1.mShareMin[0].size() > 1) //while (0)
		{

			p1.stepIdxMin *= 2;
			numNodeThisLevel = p1.mShareMin[0].size();

			for (u64 i = 0; i < p1.mTotalNumPoints; i++)
			{
				if (numNodeThisLevel % 2) //odd number, keep last for next level
					p1.lastNode[i] = p1.mShareMin[i][p1.mShareMin[i].size() - 1];

				std::vector<iWord> dist1(numNodeThisLevel / 2), dist2(numNodeThisLevel / 2);
				for (u64 k = 0; k < dist1.size(); k++)
				{
					memcpy((i8*)&dist1[k], (i8*)&p1.mShareMin[i][2 * k], sizeof(iWord));
					memcpy((i8*)&dist2[k], (i8*)&p1.mShareMin[i][2 * k + 1], sizeof(iWord));
				}

				programLessThan(p1.parties, dist1, dist2, p1.mVecGcMinOutput[i], p1.mLenMod);
			}


			p1.amortBinArithMulGCrecv(outShareRecv1, outIdxShareRecv1, p1.mVecGcMinOutput, p1.stepIdxMin); //(b^A \xor b^B)*(P^A)
			p1.amortBinArithMulGCsend(outShareSend1, outIdxShareSend1, p1.mVecGcMinOutput, p1.mShareMin, p1.mVecIdxMin, p1.stepIdxMin); //(b^A \xor b^B)*(P^B)
			p1.computeShareMin(outShareSend1, outShareRecv1); //compute (b1^A \xor b1^B)*(P1^A+P1^B)+(b2^A \xor b2^B)*(P2^A+P2^B)
			p1.computeShareIdxMin(outIdxShareSend1, outIdxShareRecv1);


			if (numNodeThisLevel % 2 == 1) //odd number => add last node to this level
				for (u64 i = 0; i < p1.mTotalNumPoints; i++)
					p1.mShareMin[i].push_back(p1.lastNode[i]);

		}

		////=====================compute nom/dec===========================
		std::vector<std::vector<iWord>>  shareNomSend1, shareNomRecv1;
		std::vector<iWord> shareDenSend1, shareDenRecv1;
		p1.vecMinTranspose();
		p1.amortBinArithClustrecv(p1.mVecIdxMinTranspose, shareNomRecv1, shareDenRecv1, true);
		p1.amortBinArithClustsend(p1.mVecIdxMinTranspose, shareNomSend1, shareDenSend1, false);
		p1.computeShareCluster(shareNomSend1, shareNomRecv1, shareDenSend1, shareDenRecv1);

		////=====================division===========================
		u8 isDenZero1; //check den=0?
		for (u64 k = 0; k < p1.mNumCluster; k++)
		{
			programEqualZero(p1.parties, p1.mShareDecCluster[k], isDenZero1, p1.mLenMod);
			p1.mChl.recv(isDenZero1);
			if (isDenZero1)
			{
				Word myShare = 0;
				for (u64 d = 0; d < p1.mDimension; d++)
				{
					programDiv(p1.parties, p1.mShareNomCluster[k][d], p1.mShareDecCluster[k], myShare, p1.mLenMod);
					p1.mShareCluster[k][d] = myShare;
				}
			}
		}
	}

	timer.setTimePoint("ClusterDone");

	std::cout << "\nClusterDone";

	std::cout << timer << "\n";
	u64 bandwith = (p1.mChl.getTotalDataRecv() + p1.mChl.getTotalDataSent()) / (pow(10, 6));
	std::cout << "comm. = " << bandwith << " MB\n";


	//p1.Print();

}


void testAccurancy()
{
	Timer timer;
	IOService ios;
	Session ep01(ios, "127.0.0.1", SessionMode::Server);
	Session ep10(ios, "127.0.0.1", SessionMode::Client);
	Channel chl01 = ep01.addChannel();
	Channel chl10 = ep10.addChannel();

	u64 inMod = pow(2, inExMod);
	std::vector<std::vector<Word>> inputA, inputB;
	//loadTxtFile("I:/kmean-impl/dataset/s1.txt", inDimension, inputA, inputB);

	PRNG prng(ZeroBlock);
	inputA.resize(numberTestA);
	inputB.resize(numberTestB);
	for (int i = 0; i < numberTestA; i++)
	{
		inputA[i].resize(inDimension);
		for (size_t j = 0; j < inDimension; j++)
		{
			inputA[i][j] = prng.get<Word>() % inMod;

		}
	}

	for (int i = 0; i < numberTestB; i++)
	{
		inputB[i].resize(inDimension);
		for (size_t j = 0; j < inDimension; j++)
		{
			inputB[i][j] = prng.get<Word>() % inMod;

		}
	}

	u64 inTotalPoint = inputA.size() + inputB.size();
	//=======================offline===============================
	DataShare p0, p1;

	timer.setTimePoint("starts");
	std::thread thrd = std::thread([&]() {
		p0.init(0, chl01, toBlock(34265), securityParams, inTotalPoint
			, inNumCluster, 0, inNumCluster / 2, inputA, inExMod, inDimension, numInteration);

		NaorPinkas baseOTs;
		baseOTs.send(p0.mSendBaseMsg, p0.mPrng, p0.mChl, 1); //first OT for D_B
		p0.recv.setBaseOts(p0.mSendBaseMsg);


		baseOTs.receive(p0.mBaseChoices, p0.mRecvBaseMsg, p0.mPrng, p0.mChl, 1); //second OT for D_A
		p0.sender.setBaseOts(p0.mRecvBaseMsg, p0.mBaseChoices); //set base OT


	});


	p1.init(1, chl10, toBlock(34265), securityParams, inTotalPoint
		, inNumCluster, inNumCluster / 2, inNumCluster, inputB, inExMod, inDimension, numInteration);

	NaorPinkas baseOTs;
	baseOTs.receive(p1.mBaseChoices, p1.mRecvBaseMsg, p1.mPrng, p1.mChl, 1); //first OT for D_B
	p1.sender.setBaseOts(p1.mRecvBaseMsg, p1.mBaseChoices); //set base OT


	baseOTs.send(p1.mSendBaseMsg, p1.mPrng, p1.mChl, 1); //second OT for D_A
	p1.recv.setBaseOts(p1.mSendBaseMsg);

	thrd.join();
	timer.setTimePoint("baseOTDone");



	//=======================online (sharing)===============================

	thrd = std::thread([&]() {

		p0.sendShareInput(0, 0, p0.mNumCluster / 2);
		p0.recvShareInput(p0.mPoint.size(), p0.mNumCluster / 2, p0.mNumCluster);

	});

	p1.recvShareInput(0, 0, p0.mNumCluster / 2);
	p1.sendShareInput(p1.mTheirNumPoints, p0.mNumCluster / 2, p0.mNumCluster);


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
				std::cout << i << "-" << j << ": " << p0.mSharePoint[i][j].mArithShare << " + " << p1.mSharePoint[i][j].mArithShare
					<< " = " << (p0.mSharePoint[i][j].mArithShare + p1.mSharePoint[i][j].mArithShare) % inMod
					<< " vs " << p0.mPoint[i][j] << "\n";
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

	std::cout << "d=" << p0.mDimension << " | "
		<< "K= " << p0.mNumCluster << " | "
		<< "n= " << p0.mTotalNumPoints << " | "
		<< "l= " << p0.mLenMod << " | "
		<< "T= " << p0.mIteration << "\t testAccurancy\n";


	timer.setTimePoint("offlineDone");



	std::vector<std::vector<Word>> points(p0.mTotalNumPoints); //[i][d]
	std::vector<std::vector<Word>> clusters(p0.mNumCluster); //[k][d]
	std::vector<std::vector<iWord>> eDists(p0.mTotalNumPoints); //[i][k]
	std::vector<BitVector> vecIdxMin(p0.mTotalNumPoints); //[i][k]
	std::vector<BitVector> vecIdxMinTranspose(p0.mNumCluster); //[k][i]

	std::vector<std::vector<iWord>> nomCluster(p0.mNumCluster);//[k][d]
	std::vector<iWord> denCluster(p0.mNumCluster,0);//[k]


	for (u64 i = 0; i < p0.mTotalNumPoints; i++) //original points
	{
		points[i].resize(p0.mDimension);
		for (u64 d = 0; d < p0.mDimension; d++)
			points[i][d] = (Word)(p0.mSharePoint[i][d].mArithShare + p1.mSharePoint[i][d].mArithShare);
	}


	//compute cluster
	for (u64 k = 0; k < p0.mNumCluster; k++) //original cluster
	{
		clusters[k].resize(p0.mDimension);
		for (u64 d = 0; d < p0.mDimension; d++)
			clusters[k][d] = (Word)(p0.mShareCluster[k][d] + p1.mShareCluster[k][d]);
	}

	for (u64 idxIter = 0; idxIter < numInteration; idxIter++)
	{
		//compute dist
		for (u64 i = 0; i < p0.mTotalNumPoints; i++) //original points
		{
			eDists[i].resize(p0.mTotalNumPoints,0);
			for (u64 k = 0; k < p0.mNumCluster; k++) //original cluster
			{
				for (u64 d = 0; d < p0.mDimension; d++)
				{
					iWord diff = signExtend((points[i][d] - clusters[k][d]), p0.mLenMod);
					eDists[i][k] = signExtend((eDists[i][k] + (iWord)pow(diff, 2)), p0.mLenMod);
				}
			}
		}

		//compute vecMin
		for (u64 i = 0; i < p0.mTotalNumPoints; i++)
		{
			iWord actualMin = eDists[i][0];
			Word actualMinIdx = 0;
			for (u64 k = 1; k < p0.mNumCluster; k++)
			{
				if (actualMin > eDists[i][k])
				{
					actualMin = eDists[i][k];
					actualMinIdx = k;
				}
			}
			vecIdxMin[i][actualMinIdx] = 1;
			std::cout << vecIdxMin[i] << "   vecIdxMin[i]\n";
		}

		//TODO: matrix transpose
		for (u64 k = 0; k <p0.mNumCluster; k++)
		{
			vecIdxMinTranspose[k].resize(p0.mTotalNumPoints);
			for (u64 i = 0; i < p0.mTotalNumPoints; i++)
			{
				vecIdxMinTranspose[k][i] = vecIdxMin[i][k];
			}

			std::cout << vecIdxMinTranspose[k] << "   vecIdxMin[i]\n";
		}

		//compute nom/den
		for (u64 k = 0; k <p0.mNumCluster; k++)
		{
			nomCluster[k].resize(p0.mDimension,0);
			for (u64 i = 0; i < p0.mTotalNumPoints; i++)
			{
				for (u64 d = 0; d < p0.mDimension; d++)
				{
					nomCluster[k][d] = signExtend(nomCluster[k][d] + vecIdxMinTranspose[k][i] * points[i][d], p0.mLenMod);

				}
				denCluster[k] = denCluster[k] + vecIdxMinTranspose[k][i];
			}
		}
		//divide
		for (u64 k = 0; k <p0.mNumCluster; k++)
			for (u64 d = 0; d < p0.mDimension; d++)
				clusters[k][d] = nomCluster[k][d] / denCluster[k];

	}

}




void unitTest()
{
	std::thread thrd = std::thread([&]() {
		//party0_Dist();
		//party0_Min();
		//party0_Min_BaseLine();
		//party0_DistNorm(1);
		//party0_UpdateCluster();
		party0_Clustering();
	});

	//party1_Dist();
	//party1_Min();
	//party1_Min_BaseLine();
	//party1_DistNorm(1);
	//party1_UpdateCluster();
	party1_Clustering();
	thrd.join();



}

int main(int argc, char** argv)
{
	generateDist_VecIdxMin();

	

	unitTest();


	if (argc == 2 && argv[1][0] == '-' && argv[1][1] == 't') {
		unitTest();
	}

	else if (argc == 3 && argv[1][0] == '-' && argv[1][1] == 'r' && atoi(argv[2]) == 0) {

		//party0_Dist();
		for (u64 d : { 2})
		{
			inDimension = d;
			for (u64 powNum : {16})
			{
				numberTestA = 1 << (powNum - 1);
				numberTestB = 1 << (powNum - 1);
				for (u64 K : {4,16})
				{
					inNumCluster = K;
					for (u64 T : { 10, 20})
					//for (u64 T : { 1})
					{
						numInteration = T;
						//	boost::this_thread::sleep(boost::posix_time::seconds(2));
							//party0_Dist();
							//party0_Min();
							//party0_Min_BaseLine();
						//party0_DistNorm(1);
						//party0_DistNorm(0);
						party0_UpdateCluster();
					}
				}
			}
		}
	}
	else if (argc == 3 && argv[1][0] == '-' && argv[1][1] == 'r' && atoi(argv[2]) == 1) {

		//party1_Dist();

		for (u64 d : { 2})
		{
			inDimension = d;
			for (u64 powNum : { 16})
			{
				numberTestA = 1 << (powNum - 1);
				numberTestB = 1 << (powNum - 1);
				for (u64 K : { 4,16})
				{
					inNumCluster = K;
					for (u64 T : {10, 20})
					//for (u64 T : { 1})
					{
						numInteration = T;
						//boost::this_thread::sleep(boost::posix_time::seconds(2));
						//party1_Dist();
						//party1_Min();
						//party1_Min_BaseLine();
						//party1_DistNorm(1);
						//party1_DistNorm(0);
						party1_UpdateCluster();

					}
				}
			}

		}
	
	}

	return 0;
}
