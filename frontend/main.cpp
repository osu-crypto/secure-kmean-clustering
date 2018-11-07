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
using namespace osuCrypto;


int securityParams = 128;
int inDimension = 2;
int inExMod = 31;
u64 inNumCluster = 1 << 2;
u64 numberTestA = 1 << 15;
u64 numberTestB = 1 << 15;
u64 numInteration = 10;

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
	std::cout << "baseOTDone\n";

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
	std::cout << "offlineDone\n";

	std::cout << "d=" << p0.mDimension << " | "
		<< "K= " << p0.mNumCluster << " | "
		<< "n= " << p0.mTotalNumPoints << " | "
		<< "l= " << p0.mLenMod << " | "
		<< "T= " << p0.mIteration << "\t party0\n";


	//=======================online (sharing)===============================

	p0.sendShareInput(0, 0, inNumCluster / 2);
	p0.recvShareInput(p0.mPoint.size(), inNumCluster / 2, inNumCluster);

	timer.setTimePoint("sharingInputsDone");
	std::cout << "sharingInputsDone\n";


	//=======================online OT (setting up keys for adaptive ED)===============================

	p0.correctAllChoiceRecv();//1st OT
	p0.correctAllChoiceSender();////other OT direction
	std::cout << "correctAllChoice\n";
	timer.setTimePoint("correctAllChoice");
	p0.setPRNGseeds();

	timer.setTimePoint("OtKeysDone");
	std::cout << "OtKeysDone\n";


	for (u64 idxIter = 0; idxIter < numInteration; idxIter++)
	{
		std::cout << "-";
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
		<< "T= " << p1.mIteration << "\t party1\n";

	//=======================online (sharing)===============================
	p1.recvShareInput(0, 0, inNumCluster / 2);
	p1.sendShareInput(p1.mTheirNumPoints, inNumCluster / 2, inNumCluster);

	timer.setTimePoint("sharingInputsDone");

	//=======================online OT (setting up keys for adaptive ED)===============================
	p1.correctAllChoiceSender(); //1st OT
	p1.correctAllChoiceRecv();////other OT direction
	p1.setPRNGseeds();

	timer.setTimePoint("OTkeysDone");

	for (u64 idxIter = 0; idxIter < numInteration; idxIter++)
	{
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

	std::cout << timer << "\n";


	//p1.Print();

}


int main(int argc, char** argv)
{




	/*std::thread thrd = std::thread([&]() {
		party0_Dist();
	});

	party1_Dist();

	thrd.join();*/


	if (argc == 2 && argv[1][0] == '-' && argv[1][1] == 't') {
		std::thread thrd = std::thread([&]() {
			party0_Dist();
		});

		party1_Dist();

		thrd.join();
	}
	else if (argc == 3 && argv[1][0] == '-' && argv[1][1] == 'r' && atoi(argv[2]) == 0) {
		party0_Dist();
	}
	else if (argc == 3 && argv[1][0] == '-' && argv[1][1] == 'r' && atoi(argv[2]) == 1) {
		party1_Dist();
	}

	return 0;
}
