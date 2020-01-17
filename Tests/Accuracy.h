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
#include <Ivory-Runtime/ivory/Circuit/CircuitLibrary.h>
#include <Ivory-Runtime/ivory/Runtime/sInt.h>
#include <Ivory-Runtime/ivory/Runtime/Party.h>
#include <Ivory-Runtime/ivory/Runtime/ShGc/ShGcInt.h>
#ifdef GetMessage
#undef GetMessage
#endif

#ifdef  _MSC_VER
#pragma warning(disable: 4800)
#pragma warning(disable:4996)
#endif //  _MSC_VER

using namespace std;
using namespace osuCrypto;
#include <Ivory-Runtime/ivory/Runtime/ShGc/ShGcRuntime.h>
#include "progCircuit.h"

namespace osuCrypto
{

	void loadTxtFile(const std::string& fileName, int mDimension, std::vector<std::vector<u64>>& input, std::vector<u64>& cluster)
	{
		std::ifstream inFile;
		inFile.open(fileName, std::ios::in);

		if (inFile.is_open() == false)
		{
			std::cout << "failed to open:\n     " << fileName << std::endl;
			throw std::runtime_error(LOCATION);
		}

		std::string line;

		//int iter = 0;
		while (getline(inFile, line))
		{
			boost::char_separator<char> sep{ "," };
			boost::tokenizer<boost::char_separator<char>> tokens(line, sep);
			std::vector<std::string> results(tokens.begin(), tokens.end());

		/*	std::cout << line << "\n";
			for (size_t i = 0; i < results.size(); i++)
				std::cout << results[i] << " ";*/


			std::vector<u64> idata(mDimension);

			if (mDimension != results.size()-1)
			{
				std::cout << "inDimension!= results.size()" << results.size() << std::endl;
				throw std::runtime_error(LOCATION);
			}

			for (size_t i = 0; i < results.size() - 1; i++)
			{
			
				idata[i] = round((stof(results[i]) + 10) * pow(10, 4));
				//std::cout << idata[i] << "\n";
				//idata[i] = stof(results[i]) * pow(10, 6);
			}
			cluster.push_back(stoi(results[results.size() - 1]));
			input.push_back(idata);
		}
	}


	void loadTxtFile(const std::string& fileName, int mDimension, std::vector<std::vector<u64>>& input)
	{
		std::ifstream inFile;
		inFile.open(fileName, std::ios::in);

		if (inFile.is_open() == false)
		{
			std::cout << "failed to open:\n     " << fileName << std::endl;
			throw std::runtime_error(LOCATION);
		}

		std::string line;

		//int iter = 0;
		while (getline(inFile, line))
		{
			boost::tokenizer<boost::char_separator<char>> tokens(line, boost::char_separator<char>());
			std::vector<std::string> results(tokens.begin(), tokens.end());

			/*	std::cout << line << "\n";
				for (size_t i = 0; i < results.size(); i++)
					std::cout << results[i] << " ";*/


			std::vector<u64> idata(mDimension);

			if (mDimension != results.size())
			{
				std::cout << "inDimension!= results.size()" << results.size() << std::endl;
				throw std::runtime_error(LOCATION);
			}

			for (size_t i = 0; i < results.size(); i++)
			{

				//idata[i] = round((stof(results[i]) + 10) * pow(10, 6));
				//std::cout << idata[i] << "\n";
				idata[i] = stoi(results[i]);// *pow(10, 6);
				//std::cout << idata[i] << "\n";
			}
			input.push_back(idata);
		}
	}


	void loadTxtFile(const std::string & fileName, int mDimension, std::vector<std::vector<u64>>& inputA, std::vector<std::vector<u64>>& inputB)
	{
		std::ifstream inFile;
		inFile.open(fileName, std::ios::in);

		if (inFile.is_open() == false)
		{
			std::cout << "failed to open:\n     " << fileName << std::endl;
			throw std::runtime_error(LOCATION);
		}

		std::string line;

		int iter = 0;
		while (getline(inFile, line))
		{
			boost::tokenizer<boost::char_separator<char>> tokens(line, boost::char_separator<char>());
			std::vector<std::string> results(tokens.begin(), tokens.end());

			/*std::cout << line << "\n";
			for (size_t i = 0; i < results.size(); i++)
			std::cout << results[i] << " ";*/


			std::vector<u64> idata(mDimension);

			if (mDimension != results.size())
			{
				std::cout << "inDimension!= results.size()" << results.size() << std::endl;
				throw std::runtime_error(LOCATION);
			}

			for (size_t i = 0; i < results.size(); i++)
				idata[i] = stoi(results[i]);

			if (iter % 2)
				inputA.push_back(idata);
			else
				inputB.push_back(idata);

			iter++;
		}
	}
	void loadTxtFile(const std::string & fileName, int mDimension, std::vector<std::vector<u64>>& inputA, u64 idxParty)
	{
		std::ifstream inFile;
		inFile.open(fileName, std::ios::in);

		if (inFile.is_open() == false)
		{
			std::cout << "failed to open:\n     " << fileName << std::endl;
			throw std::runtime_error(LOCATION);
		}

		std::string line;

		int iter = 0;
		while (getline(inFile, line))
		{
			boost::tokenizer<boost::char_separator<char>> tokens(line, boost::char_separator<char>());
			std::vector<std::string> results(tokens.begin(), tokens.end());

			/*std::cout << line << "\n";
			for (size_t i = 0; i < results.size(); i++)
			std::cout << results[i] << " ";*/


			std::vector<u64> idata(mDimension);

			if (mDimension != results.size())
			{
				std::cout << "inDimension!= results.size()" << results.size() << std::endl;
				throw std::runtime_error(LOCATION);
			}

			for (size_t i = 0; i < results.size(); i++)
				idata[i] = stoi(results[i]);

			if (idxParty == 2)
				inputA.push_back(idata);
			else
			{
				if (iter % 2 == idxParty)
					inputA.push_back(idata);
			}
			iter++;
		}
	}
		
	double computeAccuracy(std::vector<std::vector<Word>>& points, std::vector<std::vector<double>>& myClusters, std::vector<std::vector<double>>& expClusters)
	{
		std::vector<std::vector<u64>> eDists(points.size()); //[i][k]
		u64 inDimension = points[0].size();
		u64 numCorrectCluster = 0;

		//=================================Lable cluster================
		std::vector<u64> myLableMap(myClusters.size());

		std::vector<u64> alreadyUsed;

		for (u64 k1 = 0; k1 < myClusters.size(); k1++) //original cluster
		{
			double minDistCC = std::numeric_limits<double>::max(); u64 minIdxCC = 0;
			for (u64 k = 0; k < expClusters.size(); k++) //for each myClusters[k1]
			{
				double distCC = 0;
				for (u64 d = 0; d < inDimension; d++)
				{
					double diff = (myClusters[k1][d] - expClusters[k][d]); //dist(k1, all k)
					distCC = (distCC + diff*diff);
				}
				
				if (minDistCC > distCC)
				{
					//if(!(std::find(alreadyUsed.begin(), alreadyUsed.end(), k) != alreadyUsed.end()))
					{
						minDistCC = distCC;
						minIdxCC = k; //cluster idx
					}
				}
			}
			myLableMap[k1] = minIdxCC; // map mylable to expcluster
			std::cout << "myLableMap[" << k1 + 1 << "] = " << minIdxCC + 1 << "\n ";
			alreadyUsed.push_back(minIdxCC);
		}


		//compute dist
		for (u64 i = 0; i < points.size(); i++) //original points
		{
			u64 myIdK = 0;
			u64 expIdK = 0;
			double myMinDist = 0;
			double expMinDist = 0;

			for (u64 k = 0; k < expClusters.size(); k++) //original cluster
			{
				double myCurrDist = 0;
				double expCurrDist = 0;

				for (u64 d = 0; d < inDimension; d++)
				{
					double diff = (points[i][d] - expClusters[k][d]);
					expCurrDist = (expCurrDist + diff*diff);

					diff = (points[i][d] - myClusters[k][d]);
					myCurrDist = (myCurrDist + diff*diff);
				}

				if (k == 0)
				{
					myMinDist = myCurrDist;
					myIdK = 0;

					expMinDist = expCurrDist;
					expIdK = 0; //cluster idx

				}
				else
				{
					if (myMinDist > myCurrDist)
					{
						myMinDist = myCurrDist;
						myIdK = k; //cluster idx
					}

					if (expMinDist > expCurrDist)
					{
						expMinDist = expCurrDist;
						expIdK = k; //cluster idx
					}
				}
			}
			if (myLableMap[myIdK] == expIdK)
			{
				numCorrectCluster++;
				//std::cout << myIdK << " vs " << expIdK << "   expIdK\n ";
			}
			else
			{
				//std::cout << myIdK << " vs " << expIdK << "   expIdK\n ";
			}
		}

		double ratio = (double)numCorrectCluster / (double)points.size();
		//std::cout << ratio << " -----------------------\n ";




		return ratio;
	}
	
	double computeAccuracy(std::vector<std::vector<Word>>& points, std::vector<std::vector<Word>>& myClusters, std::vector<std::vector<double>>& expClusters)
	{
		std::vector<std::vector<double>> mydblClusters(myClusters.size());
		for (u64 k = 0; k < myClusters.size(); k++)
		{
			mydblClusters[k].resize(myClusters[k].size());
			for (u64 d = 0; d < myClusters[k].size(); d++)
			{
				mydblClusters[k][d] = myClusters[k][d];
			}
		}
		return computeAccuracy(points, mydblClusters, expClusters);
	}

	std::vector<std::vector<Word>> secureTestClusteringSignExtend(std::vector<std::vector<Word>>& inputA, std::vector<std::vector<Word>>& inputB, u64 inNumCluster, u64 bitlength, std::vector<std::vector<Word>> initCluster)
	{

		int securityParams = 128;
		int inDimension = inputA[0].size();
		int inExMod = bitlength;
		u64 numInteration = 2;
		u64 inMod = pow(2, inExMod);

		Timer timer;
		IOService ios;
		Session ep01(ios, "127.0.0.1", SessionMode::Server);
		Session ep10(ios, "127.0.0.1", SessionMode::Client);
		Channel chl01 = ep01.addChannel();
		Channel chl10 = ep10.addChannel();
		PRNG prng(ZeroBlock);

		//inputA.resize(numberTestA);
		//inputB.resize(numberTestB);
		//for (int i = 0; i < numberTestA; i++)
		//{
		//	inputA[i].resize(inDimension);
		//	for (size_t j = 0; j < inDimension; j++)
		//	{
		//		inputA[i][j] = prng.get<Word>() % inMod;

		//	}
		//}

		//for (int i = 0; i < numberTestB; i++)
		//{
		//	inputB[i].resize(inDimension);
		//	for (size_t j = 0; j < inDimension; j++)
		//	{
		//		inputB[i][j] = prng.get<Word>() % inMod;

		//	}
		//}

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
			<< "T= " << p0.mIteration << "\t plaintextClustering\n";


		timer.setTimePoint("offlineDone");



		std::vector<std::vector<Word>> points(p0.mTotalNumPoints); //[i][d]
		std::vector<std::vector<Word>> myClusters(p0.mNumCluster); //[k][d]

																   //u64 sizeChunk = p0.mMod / (p0.mNumCluster + 1);
																   //
																   //std::vector<u64> expectedCluster(p0.mNumCluster);
																   //for (u64 k = 0; k < p0.mNumCluster; k++)
																   //		expectedCluster[k] = k*sizeChunk;


		for (u64 i = 0; i < p0.mTotalNumPoints; i++) //original points
		{
			points[i].resize(p0.mDimension);

			u64 randIdx = std::rand() % p0.mNumCluster;

			for (u64 d = 0; d < p0.mDimension; d++)
				//points[i][d] = expectedCluster[randIdx] + p0.mPrng.get<Word>() % sizeChunk;;
				points[i][d] = (Word)(p0.mSharePoint[i][d].mArithShare + p1.mSharePoint[i][d].mArithShare);

			//std::cout << points[i][0] << "   points[i][0]\n";

		}


		//compute cluster
		//std::vector<std::vector<u64>> clusterDataLoad;
		//loadTxtFile("I:/kmean-impl/dataset/s1c.txt", inDimension, clusterDataLoad,2);
		for (u64 k = 0; k < p0.mNumCluster; k++) //original cluster
		{
			myClusters[k].resize(p0.mDimension);
			for (u64 d = 0; d < p0.mDimension; d++)
				myClusters[k][d] = (p0.mShareCluster[k][d] + p1.mShareCluster[k][d]);
			std::cout << myClusters[k][0] << "   myClusters[i][0]\n";

		}


		bool stopLoop = false;
		u64 iterLoop = 1;
		while (!stopLoop)
			//for (u64 idxIter = 0; idxIter < numInteration; idxIter++)
		{
			std::vector<std::vector<Word>> newClusters(p0.mNumCluster); //[k][d]
			std::vector<std::vector<u64>> eDists(p0.mTotalNumPoints); //[i][k]
			std::vector<BitVector> vecIdxMin(p0.mTotalNumPoints); //[i][k]
			std::vector<BitVector> vecIdxMinTranspose(p0.mNumCluster); //[k][i]
			std::vector<std::vector<iWord>> nomCluster(p0.mNumCluster);//[k][d]
			std::vector<iWord> denCluster(p0.mNumCluster, 0);//[k]

															 //compute dist
			for (u64 i = 0; i < p0.mTotalNumPoints; i++) //original points
			{
				eDists[i].resize(p0.mTotalNumPoints, 0);
				for (u64 k = 0; k < p0.mNumCluster; k++) //original cluster
				{
					for (u64 d = 0; d < p0.mDimension; d++)
					{
						/*Word diff = signExtend((points[i][d] - myClusters[k][d]), p0.mLenMod);
						eDists[i][k] = signExtend((eDists[i][k] + (iWord)pow(diff, 2)), p0.mLenMod);*/

						i64 diff = (points[i][d] - myClusters[k][d]);
						eDists[i][k] = (eDists[i][k] + diff*diff) ;//% p0.mMod

						//i64 diff = (points[i][d] - myClusters[k][d]);
						//eDists[i][k] = (eDists[i][k] + diff*diff);
					}
				}
			}

			//compute vecMin
			for (u64 i = 0; i < p0.mTotalNumPoints; i++)
			{
				vecIdxMin[i].resize(p0.mNumCluster);
				iWord actualMin = eDists[i][0];
				vecIdxMin[i][0] = 0;
				Word actualMinIdx = 0;
				for (u64 k = 1; k < p0.mNumCluster; k++)
				{
					if (actualMin > eDists[i][k])
					{
						actualMin = eDists[i][k];
						actualMinIdx = k;
					}
					vecIdxMin[i][k] = 0;
				}
				vecIdxMin[i][actualMinIdx] = 1;
				//std::cout << vecIdxMin[i] << " vs " <<actualMinIdx<< "   vecIdxMin[i]\n";
			}

			//TODO: matrix transpose
			for (u64 k = 0; k < p0.mNumCluster; k++)
			{
				vecIdxMinTranspose[k].resize(p0.mTotalNumPoints);
				for (u64 i = 0; i < p0.mTotalNumPoints; i++)
				{
					vecIdxMinTranspose[k][i] = vecIdxMin[i][k];
				}

				//std::cout << vecIdxMinTranspose[k] << "   vecIdxMin[i]\n";
			}

			//compute nom/den
			for (u64 k = 0; k < p0.mNumCluster; k++)
			{
				nomCluster[k].resize(p0.mDimension, 0);
				for (u64 i = 0; i < p0.mTotalNumPoints; i++)
				{
					for (u64 d = 0; d < p0.mDimension; d++)
					{
						nomCluster[k][d] = (nomCluster[k][d] + vecIdxMinTranspose[k][i] * points[i][d]);
						//nomCluster[k][d] = (nomCluster[k][d] + vecIdxMinTranspose[k][i] * points[i][d]);

					}
					denCluster[k] = denCluster[k] + vecIdxMinTranspose[k][i];
				}
			}
			//divide
			for (u64 k = 0; k < p0.mNumCluster; k++)
			{
				newClusters[k].resize(p0.mDimension);
				for (u64 d = 0; d < p0.mDimension; d++)
				{
					nomCluster[k][d] = nomCluster[k][d];

					if (denCluster[k] == 0)
					{
						std::cout << "   denCluster[k]==0=============================================\n";
						newClusters[k][d] = myClusters[k][d];
					}
					else
					{
						newClusters[k][d] = nomCluster[k][d] / denCluster[k];
						std::cout << myClusters[k][d] << " vs " << newClusters[k][d] << " = " << nomCluster[k][d] << " / " << denCluster[k] << "   newClusters[k][d]\n";
					}



				}
			}


			//check stop


			//compute cluster dist
			u64 error = 0;
			std::vector<iWord> clusterDists(p0.mNumCluster, 0); //[k][k]

			for (u64 k = 0; k < p0.mNumCluster; k++) //original cluster
			{
				for (u64 d = 0; d < p0.mDimension; d++)
				{
					iWord diff = ((newClusters[k][d] - myClusters[k][d])) ;
					clusterDists[k] = (clusterDists[k] + diff*diff) ;

					//i64 diff = ((newClusters[k][d] - myClusters[k][d]));
					//clusterDists[k] = (clusterDists[k] + diff*diff);
				}
				error = error + (clusterDists[k]);
			}

			std::cout << "i=" << iterLoop << "e= " << error << "-----------------------------------------------------\n";
			iterLoop++;
			if (error < 100000)
				stopLoop = true;
			else
				for (u64 k = 0; k < p0.mNumCluster; k++) //assign cluster
				{
					for (u64 d = 0; d < p0.mDimension; d++)
					{
						myClusters[k][d] = newClusters[k][d];
					}
				}

		}


		ifstream indata;
		ofstream outdata;
		outdata.open("SecureClusterSign.csv", ios::trunc);

		outdata << "Centroids";

		for (u64 k = 0; k < myClusters.size(); k++) //assign cluster
		{
			for (u64 d = 0; d < inDimension; d++)
			{
				outdata << "," << myClusters[k][d];
			}
			outdata << endl;
		}

		outdata << "Data";
		for (u64 i = 0; i < points.size(); i++) //assign cluster
		{
			for (u64 d = 0; d < inDimension; d++)
			{
				outdata << "," << points[i][d];
			}
			outdata << endl;
		}
		return myClusters;
	}

	std::vector<std::vector<Word>> secureTestClustering(std::vector<std::vector<Word>>& inputA, std::vector<std::vector<Word>>& inputB, u64 inNumCluster, u64 bitlength, std::vector<std::vector<Word>> initCluster)
	{

		int securityParams = 128;
		int inDimension = inputA[0].size();
		int inExMod = bitlength;
		u64 numInteration = 2;
		u64 inMod = pow(2, inExMod);

		Timer timer;
		IOService ios;
		Session ep01(ios, "127.0.0.1", SessionMode::Server);
		Session ep10(ios, "127.0.0.1", SessionMode::Client);
		Channel chl01 = ep01.addChannel();
		Channel chl10 = ep10.addChannel();
		PRNG prng(ZeroBlock);

		//inputA.resize(numberTestA);
		//inputB.resize(numberTestB);
		//for (int i = 0; i < numberTestA; i++)
		//{
		//	inputA[i].resize(inDimension);
		//	for (size_t j = 0; j < inDimension; j++)
		//	{
		//		inputA[i][j] = prng.get<Word>() % inMod;

		//	}
		//}

		//for (int i = 0; i < numberTestB; i++)
		//{
		//	inputB[i].resize(inDimension);
		//	for (size_t j = 0; j < inDimension; j++)
		//	{
		//		inputB[i][j] = prng.get<Word>() % inMod;

		//	}
		//}

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

#if 0
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
			<< "T= " << p0.mIteration << "\t plaintextClustering\n";


		timer.setTimePoint("offlineDone");



		std::vector<std::vector<Word>> points(p0.mTotalNumPoints); //[i][d]
		std::vector<std::vector<Word>> myClusters(p0.mNumCluster); //[k][d]

																   //u64 sizeChunk = p0.mMod / (p0.mNumCluster + 1);
																   //
																   //std::vector<u64> expectedCluster(p0.mNumCluster);
																   //for (u64 k = 0; k < p0.mNumCluster; k++)
																   //		expectedCluster[k] = k*sizeChunk;


		for (u64 i = 0; i < p0.mTotalNumPoints; i++) //original points
		{
			points[i].resize(p0.mDimension);

			u64 randIdx = std::rand() % p0.mNumCluster;

			for (u64 d = 0; d < p0.mDimension; d++)
			{	//points[i][d] = expectedCluster[randIdx] + p0.mPrng.get<Word>() % sizeChunk;;
				points[i][d] = (Word)(p0.mSharePoint[i][d].mArithShare + p1.mSharePoint[i][d].mArithShare);
				std::cout << points[i][d] << ", ";
			}
			std::cout <<  "\t\t  secure_points\n";

		}


		//compute cluster
		//std::vector<std::vector<u64>> clusterDataLoad;
		//loadTxtFile("I:/kmean-impl/dataset/s1c.txt", inDimension, clusterDataLoad,2);
		for (u64 k = 0; k < p0.mNumCluster; k++) //original cluster
		{
			myClusters[k].resize(p0.mDimension);
			for (u64 d = 0; d < p0.mDimension; d++)
			{
				myClusters[k][d] = initCluster[k][d];// (p0.mShareCluster[k][d] + p1.mShareCluster[k][d]);
				std::cout << myClusters[k][d] << ", ";
			}
			std::cout << "\t\t  secure_myClusters\n";

		}


		bool stopLoop = false;
		u64 iterLoop = 1;
		while (!stopLoop)
			//for (u64 idxIter = 0; idxIter < numInteration; idxIter++)
		{
			std::vector<std::vector<Word>> newClusters(p0.mNumCluster); //[k][d]
			std::vector<std::vector<u64>> eDists(p0.mTotalNumPoints); //[i][k]
			std::vector<BitVector> vecIdxMin(p0.mTotalNumPoints); //[i][k]
			std::vector<BitVector> vecIdxMinTranspose(p0.mNumCluster); //[k][i]
			std::vector<std::vector<iWord>> nomCluster(p0.mNumCluster);//[k][d]
			std::vector<iWord> denCluster(p0.mNumCluster, 0);//[k]

															 //compute dist
			for (u64 i = 0; i < p0.mTotalNumPoints; i++) //original points
			{
				eDists[i].resize(p0.mTotalNumPoints, 0);
				for (u64 k = 0; k < p0.mNumCluster; k++) //original cluster
				{
					for (u64 d = 0; d < p0.mDimension; d++)
					{
						//iWord diff = signExtend((points[i][d] - myClusters[k][d]), p0.mLenMod);
						//eDists[i][k] = signExtend((eDists[i][k] + (iWord)pow(diff, 2)), p0.mLenMod);

						auto diff = (points[i][d] - myClusters[k][d]);
						eDists[i][k] = (eDists[i][k] + diff*diff);
					}
				}
			}

			//compute vecMin
			for (u64 i = 0; i < p0.mTotalNumPoints; i++)
			{
				vecIdxMin[i].resize(p0.mNumCluster);
				iWord actualMin = eDists[i][0];
				vecIdxMin[i][0] = 0;
				Word actualMinIdx = 0;
				for (u64 k = 1; k < p0.mNumCluster; k++)
				{
					if (actualMin > eDists[i][k])
					{
						actualMin = eDists[i][k];
						actualMinIdx = k;
					}
					vecIdxMin[i][k] = 0;
				}
				vecIdxMin[i][actualMinIdx] = 1;
				//std::cout << vecIdxMin[i] << " vs " <<actualMinIdx<< "   vecIdxMin[i]\n";
			}

			//TODO: matrix transpose
			for (u64 k = 0; k < p0.mNumCluster; k++)
			{
				vecIdxMinTranspose[k].resize(p0.mTotalNumPoints);
				for (u64 i = 0; i < p0.mTotalNumPoints; i++)
				{
					vecIdxMinTranspose[k][i] = vecIdxMin[i][k];
				}

				//std::cout << vecIdxMinTranspose[k] << "   vecIdxMin[i]\n";
			}

			//compute nom/den
			for (u64 k = 0; k < p0.mNumCluster; k++)
			{
				nomCluster[k].resize(p0.mDimension, 0);
				for (u64 i = 0; i < p0.mTotalNumPoints; i++)
				{
					for (u64 d = 0; d < p0.mDimension; d++)
					{
						//nomCluster[k][d] = signExtend(nomCluster[k][d] + vecIdxMinTranspose[k][i] * points[i][d], p0.mLenMod);
						nomCluster[k][d] = (nomCluster[k][d] + vecIdxMinTranspose[k][i] * points[i][d]);

					}
					denCluster[k] = denCluster[k] + vecIdxMinTranspose[k][i];
				}
			}
			//divide
			for (u64 k = 0; k < p0.mNumCluster; k++)
			{
				newClusters[k].resize(p0.mDimension);
				for (u64 d = 0; d < p0.mDimension; d++)
				{
					//nomCluster[k][d] = nomCluster[k][d] % p0.mMod;

					if (denCluster[k] == 0)
					{
						std::cout << "   denCluster[k]==0=============================================\n";
						newClusters[k][d] = myClusters[k][d];
					}
					else
					{
						newClusters[k][d] = nomCluster[k][d] / denCluster[k];
						std::cout << myClusters[k][d] << " vs " << newClusters[k][d] << " = " << nomCluster[k][d] << " / " << denCluster[k] << "   newClusters[k][d]\n";
					}



				}
			}


			//check stop


			//compute cluster dist
			u64 error = 0;
			std::vector<iWord> clusterDists(p0.mNumCluster, 0); //[k][k]

			for (u64 k = 0; k < p0.mNumCluster; k++) //original cluster
			{
				for (u64 d = 0; d < p0.mDimension; d++)
				{
					//iWord diff = signExtend((newClusters[k1][d] - myClusters[k][d]), p0.mLenMod);
					//clusterDists[k1][k] = signExtend((clusterDists[k1][k] + (iWord)pow(diff, 2)), p0.mLenMod);

					auto diff = ((newClusters[k][d] - myClusters[k][d]));
					//std::cout << myClusters[k][d] << " = " << newClusters[k][d] << " vs " <<diff << "   diff\n";

					clusterDists[k] = (clusterDists[k] + diff*diff);
				}
				//	std::cout << clusterDists[k]<< "   clusterDists[k]\n";
				error = error + (clusterDists[k]);
			}

			std::cout << "i=" << iterLoop << "e= " << error << "-----------------------------------------------------\n";
			iterLoop++;
			if (error < 100000)
				stopLoop = true;
			else
				for (u64 k = 0; k < p0.mNumCluster; k++) //assign cluster
				{
					for (u64 d = 0; d < p0.mDimension; d++)
					{
						myClusters[k][d] = newClusters[k][d];
					}
				}

		}


		ifstream indata;
		ofstream outdata;
		outdata.open("SecureCluster.csv", ios::trunc);

		outdata << "Centroids";

		for (u64 k = 0; k < myClusters.size(); k++) //assign cluster
		{
			for (u64 d = 0; d < inDimension; d++)
			{
				outdata << "," << myClusters[k][d];
			}
			outdata << endl;
		}

		outdata << "Data";
		for (u64 i = 0; i < points.size(); i++) //assign cluster
		{
			for (u64 d = 0; d < inDimension; d++)
			{
				outdata << "," << points[i][d];
			}
			outdata << endl;
		}
		return myClusters;
	}

	std::vector<std::vector<double>> plaintextClustering_old(std::vector<std::vector<Word>>& points, u64 inNumCluster, u64 bitlength, std::vector<std::vector<Word>> initCluster)
	{

		int inDimension = points[0].size();
		int inExMod = bitlength;
		u64 numInteration = 2;
		PRNG prng(ZeroBlock);
		u64 inMod = pow(2, inExMod);

		u64 inTotalPoint = points.size();

		std::vector<std::vector<double>> myClusters(inNumCluster); //[k][d]

																   //compute cluster



		for (u64 k = 0; k < myClusters.size(); k++) //original cluster
		{
			myClusters[k].resize(inDimension);
			for (u64 d = 0; d < inDimension; d++)
			{
				//myClusters[k][d] = clusterDataLoad[k][d];
				//myClusters[k][d] = prng.get<Word>()%inMod;
				myClusters[k][d] = initCluster[k][d];
				std::cout << myClusters[k][d] << ", ";
			}
			std::cout << "\t\t  plaintext_myClusters\n";

		}


		bool stopLoop = false;
		u64 iterLoop = 1;
		while (!stopLoop)
			//for (u64 idxIter = 0; idxIter < numInteration; idxIter++)
		{
			std::vector<std::vector<double>> newClusters(myClusters.size()); //[k][d]
			std::vector<std::vector<Word>> eDists(points.size()); //[i][k]
			std::vector<std::vector<Word>> nomCluster(myClusters.size());//[k][d]
			std::vector<Word> denCluster(myClusters.size(), 0);//[k]


			for (u64 k = 0; k < myClusters.size(); k++)
				nomCluster[k].resize(inDimension, 0);

			//compute dist
			for (u64 i = 0; i < points.size(); i++) //original points
			{
				eDists[i].resize(points.size(), 0);
				for (u64 k = 0; k < myClusters.size(); k++) //original cluster
				{
					for (u64 d = 0; d < inDimension; d++)
					{
						Word diff = (points[i][d] - myClusters[k][d]);
						eDists[i][k] = (eDists[i][k] + diff*diff);
					}
				}


			}

			//compute vecMin
			for (u64 i = 0; i < points.size(); i++)
			{
				Word actualMin = eDists[i][0];
				Word actualMinIdx = 0;
				for (u64 k = 1; k < myClusters.size(); k++)
				{
					if (actualMin > eDists[i][k])
					{
						actualMin = eDists[i][k];
						actualMinIdx = k; //cluster idx
					}
				}

				for (u64 d = 0; d < inDimension; d++)
				{
					nomCluster[actualMinIdx][d] = (nomCluster[actualMinIdx][d] + points[i][d]);
				}
				denCluster[actualMinIdx]++;

			}


			//divide
			for (u64 k = 0; k < myClusters.size(); k++)
			{
				newClusters[k].resize(inDimension);
				for (u64 d = 0; d < inDimension; d++)
				{
					if (denCluster[k] == 0)
					{
						std::cout << "   denCluster[k]==0=============================================\n";
						newClusters[k][d] = myClusters[k][d];
					}
					else
					{
						//newClusters[k][d] = (double)nomCluster[k][d] / (double)denCluster[k];
						newClusters[k][d] = nomCluster[k][d] / denCluster[k];
						std::cout << myClusters[k][d] << " vs " << newClusters[k][d] << " = " << nomCluster[k][d] << " / " << denCluster[k] << "   newClusters[k][d]\n";
					}
				}
			}


			//check stop

			//compute cluster dist
			double error = 0;
			std::vector<double> clusterDists(myClusters.size(), 0); //[k][k]

			for (u64 k = 0; k < myClusters.size(); k++) //original cluster
			{
				for (u64 d = 0; d < inDimension; d++)
				{
					//iWord diff = signExtend((newClusters[k1][d] - myClusters[k][d]), p0.mLenMod);
					//clusterDists[k1][k] = signExtend((clusterDists[k1][k] + (iWord)pow(diff, 2)), p0.mLenMod);

					double diff = ((newClusters[k][d] - myClusters[k][d]));
					//std::cout << myClusters[k][d] << " = " << newClusters[k][d] << " vs " <<diff << "   diff\n";

					clusterDists[k] = (clusterDists[k] + diff*diff);
				}
				//	std::cout << clusterDists[k]<< "   clusterDists[k]\n";
				error = error + (clusterDists[k]);
			}

			std::cout << "i=" << iterLoop << "e= " << error << "-----------------------------------------------------\n";
			iterLoop++;
			if (error < 100000)
				stopLoop = true;
			else
				for (u64 k = 0; k < myClusters.size(); k++) //assign cluster
				{
					for (u64 d = 0; d < inDimension; d++)
					{
						myClusters[k][d] = newClusters[k][d];
					}
				}

		}


		ifstream indata;
		ofstream outdata;
		outdata.open("PlainTextCluster.csv", ios::trunc);

		outdata << "Centroids";

		for (u64 k = 0; k < myClusters.size(); k++) //assign cluster
		{
			for (u64 d = 0; d < inDimension; d++)
			{
				outdata << "," << myClusters[k][d];
			}
			outdata << endl;
		}

		outdata << "Data";
		for (u64 i = 0; i < points.size(); i++) //assign cluster
		{
			for (u64 d = 0; d < inDimension; d++)
			{
				outdata << "," << points[i][d];
			}
			outdata << endl;
		}

		return myClusters;
	}

	std::vector<std::vector<double>> plaintextClustering_old(std::vector<std::vector<Word>>& points, u64 inNumCluster, u64 bitlength)
	{

		int inDimension = points[0].size();
		int inExMod = bitlength;
		u64 numInteration = 2;
		PRNG prng(ZeroBlock);
		u64 inMod = pow(2, inExMod);

		u64 inTotalPoint = points.size();

		std::vector<std::vector<double>> myClusters(inNumCluster); //[k][d]

																   //compute cluster


		for (u64 k = 0; k < myClusters.size(); k++) //original cluster
		{
			myClusters[k].resize(inDimension);
			for (u64 d = 0; d < inDimension; d++)
				//myClusters[k][d] = clusterDataLoad[k][d];
				//myClusters[k][d] = prng.get<Word>()%inMod;
				myClusters[k][d] = points[k][d];

		//	std::cout << myClusters[k][0] << "   myClusters[i][0]\n";

		}


		bool stopLoop = false;
		u64 iterLoop = 1;
		while (!stopLoop)
			//for (u64 idxIter = 0; idxIter < numInteration; idxIter++)
		{
			std::vector<std::vector<double>> newClusters(myClusters.size()); //[k][d]
			std::vector<std::vector<Word>> eDists(points.size()); //[i][k]
			std::vector<std::vector<Word>> nomCluster(myClusters.size());//[k][d]
			std::vector<Word> denCluster(myClusters.size(), 0);//[k]


			for (u64 k = 0; k < myClusters.size(); k++)
				nomCluster[k].resize(inDimension, 0);

			//compute dist
			for (u64 i = 0; i < points.size(); i++) //original points
			{
				eDists[i].resize(points.size(), 0);
				for (u64 k = 0; k < myClusters.size(); k++) //original cluster
				{
					for (u64 d = 0; d < inDimension; d++)
					{
						Word diff = (points[i][d] - myClusters[k][d]);
						eDists[i][k] = (eDists[i][k] + diff*diff);
					}
				}


			}

			//compute vecMin
			for (u64 i = 0; i < points.size(); i++)
			{
				Word actualMin = eDists[i][0];
				Word actualMinIdx = 0;
				for (u64 k = 1; k < myClusters.size(); k++)
				{
					if (actualMin > eDists[i][k])
					{
						actualMin = eDists[i][k];
						actualMinIdx = k; //cluster idx
					}
				}

				for (u64 d = 0; d < inDimension; d++)
				{
					nomCluster[actualMinIdx][d] = (nomCluster[actualMinIdx][d] + points[i][d]);
				}
				denCluster[actualMinIdx]++;

			}


			//divide
			for (u64 k = 0; k < myClusters.size(); k++)
			{
				newClusters[k].resize(inDimension);
				for (u64 d = 0; d < inDimension; d++)
				{
					if (denCluster[k] == 0)
					{
						std::cout << "   denCluster[k]==0=============================================\n";
						newClusters[k][d] = myClusters[k][d];
					}
					else
					{
						//newClusters[k][d] = (double)nomCluster[k][d] / (double)denCluster[k];
						newClusters[k][d] = nomCluster[k][d] / denCluster[k];
						std::cout << myClusters[k][d] << " vs " << newClusters[k][d] << " = " << nomCluster[k][d] << " / " << denCluster[k] << "   newClusters[k][d]\n";
					}
				}
			}


			//check stop

			//compute cluster dist
			double error = 0;
			std::vector<double> clusterDists(myClusters.size(), 0); //[k][k]

			for (u64 k = 0; k < myClusters.size(); k++) //original cluster
			{
				for (u64 d = 0; d < inDimension; d++)
				{
					//iWord diff = signExtend((newClusters[k1][d] - myClusters[k][d]), p0.mLenMod);
					//clusterDists[k1][k] = signExtend((clusterDists[k1][k] + (iWord)pow(diff, 2)), p0.mLenMod);

					double diff = ((newClusters[k][d] - myClusters[k][d]));
					//std::cout << myClusters[k][d] << " = " << newClusters[k][d] << " vs " <<diff << "   diff\n";

					clusterDists[k] = (clusterDists[k] + diff*diff);
				}
				//	std::cout << clusterDists[k]<< "   clusterDists[k]\n";
				error = error + (clusterDists[k]);
			}

			std::cout << "i=" << iterLoop << "e= " << error << "-----------------------------------------------------\n";
			iterLoop++;
			if (error < 100000)
				stopLoop = true;
			else
				for (u64 k = 0; k < myClusters.size(); k++) //assign cluster
				{
					for (u64 d = 0; d < inDimension; d++)
					{
						myClusters[k][d] = newClusters[k][d];
					}
				}

		}


		ifstream indata;
		ofstream outdata;
		outdata.open("PlainTextCluster.csv", ios::trunc);

		outdata << "Centroids";

		for (u64 k = 0; k < myClusters.size(); k++) //assign cluster
		{
			for (u64 d = 0; d < inDimension; d++)
			{
				outdata << "," << myClusters[k][d];
			}
			outdata << endl;
		}

		outdata << "Data";
		for (u64 i = 0; i < points.size(); i++) //assign cluster
		{
			for (u64 d = 0; d < inDimension; d++)
			{
				outdata << "," << points[i][d];
			}
			outdata << endl;
		}

		return myClusters;
	}

	//===========new

	std::vector<std::vector<double>> plaintextClustering(std::vector<std::vector<Word>>& points, u64 inNumCluster, std::vector<std::vector<Word>> initCluster)
	{

		int inDimension = points[0].size();
		u64 numInteration = 2;
		PRNG prng(ZeroBlock);

		u64 inTotalPoint = points.size();

		std::vector<std::vector<double>> myClusters(inNumCluster); //[k][d]
		std::vector<u64> idxPointvsCluster(points.size()); //[k][d]

																   //compute cluster


		for (u64 k = 0; k < myClusters.size(); k++) //original cluster
		{
			myClusters[k].resize(inDimension);
			for (u64 d = 0; d < inDimension; d++)
				//myClusters[k][d] = clusterDataLoad[k][d];
				//myClusters[k][d] = prng.get<Word>()%inMod;
				myClusters[k][d] = initCluster[k][d];

			//std::cout << myClusters[k][0] << "   myClusters[i][0]\n";

		}


		bool stopLoop = false;
		u64 iterLoop = 1;
		//while (!stopLoop)
		for (u64 idxIter = 0; idxIter <15; idxIter++)
		{
			std::vector<std::vector<double>> newClusters(myClusters.size()); //[k][d]
			std::vector<std::vector<double>> eDists(points.size()); //[i][k]
			std::vector<std::vector<double>> nomCluster(myClusters.size());//[k][d]
			std::vector<double> denCluster(myClusters.size(), 0);//[k]


			for (u64 k = 0; k < myClusters.size(); k++)
				nomCluster[k].resize(inDimension, 0);

			//compute dist
			for (u64 i = 0; i < points.size(); i++) //original points
			{
				eDists[i].resize(points.size(), 0);
				for (u64 k = 0; k < myClusters.size(); k++) //original cluster
				{
					for (u64 d = 0; d < inDimension; d++)
					{
						auto diff = (points[i][d] - myClusters[k][d]);
						eDists[i][k] = (eDists[i][k] + diff * diff);
					}
				}


			}

			//compute vecMin
			for (u64 i = 0; i < points.size(); i++)
			{
				Word actualMin = eDists[i][0];
				Word actualMinIdx = 0;
				for (u64 k = 1; k < myClusters.size(); k++)
				{
					if (actualMin > eDists[i][k])
					{
						actualMin = eDists[i][k];
						actualMinIdx = k; //cluster idx
					}
				}

				for (u64 d = 0; d < inDimension; d++)
				{
					nomCluster[actualMinIdx][d] = (nomCluster[actualMinIdx][d] + points[i][d]);
				}
				denCluster[actualMinIdx]+=1.0;
				idxPointvsCluster[i] = actualMinIdx;
			}


			//divide
			for (u64 k = 0; k < myClusters.size(); k++)
			{
				newClusters[k].resize(inDimension);
				for (u64 d = 0; d < inDimension; d++)
				{
					if (denCluster[k] == 0)
					{
						std::cout << "   denCluster[k]==0=============================================\n";
						newClusters[k][d] = myClusters[k][d];
					}
					else
					{
						//newClusters[k][d] = (double)nomCluster[k][d] / (double)denCluster[k];
						newClusters[k][d] = nomCluster[k][d] / (double)denCluster[k];
						//std::cout << std::fixed << std::setprecision(2) << newClusters[k][d] << std::endl;

						std::cout << std::fixed << std::setprecision(2) << myClusters[k][d] << " vs " << newClusters[k][d] << " = " << nomCluster[k][d] << " / " << denCluster[k] << "   newClusters[k][d]\n";
					}
				}
			}


			//check stop

			//compute cluster dist
			double error = 0;
			std::vector<double> clusterDists(myClusters.size(), 0); //[k][k]

			for (u64 k = 0; k < myClusters.size(); k++) //original cluster
			{
				for (u64 d = 0; d < inDimension; d++)
				{
					//iWord diff = signExtend((newClusters[k1][d] - myClusters[k][d]), p0.mLenMod);
					//clusterDists[k1][k] = signExtend((clusterDists[k1][k] + (iWord)pow(diff, 2)), p0.mLenMod);

					double diff = ((newClusters[k][d] - myClusters[k][d]));
					//std::cout << myClusters[k][d] << " = " << newClusters[k][d] << " vs " <<diff << "   diff\n";

					clusterDists[k] = (clusterDists[k] + diff * diff);
				}
				//	std::cout << clusterDists[k]<< "   clusterDists[k]\n";
				error = error + (clusterDists[k]);
			}

			std::cout << "plaintext i=" << iterLoop << "e= " << error << "-----------------------------------------------------\n";
			iterLoop++;
			if (error < 1000)
				stopLoop = true;
			else
				for (u64 k = 0; k < myClusters.size(); k++) //assign cluster
				{
					for (u64 d = 0; d < inDimension; d++)
					{
						myClusters[k][d] = newClusters[k][d];
					}
				}

		}


		ifstream indata;
		ofstream outdata, outdatatxt;
		outdata.open("PlainTextCluster.csv", ios::trunc);
		outdatatxt.open("PlainTextCluster.txt", ios::trunc);

		outdata << "Centroids";

		for (u64 k = 0; k < myClusters.size(); k++) //assign cluster
		{
			for (u64 d = 0; d < inDimension; d++)
			{
				outdata << "," << myClusters[k][d];
				
			}
			outdata << endl;
		}

		outdata << "Data";
		for (u64 i = 0; i < points.size(); i++) //assign cluster
		{
			for (u64 d = 0; d < inDimension; d++)
			{
				outdata << "," << points[i][d];
				outdatatxt <<  points[i][d] << ",";
			}
			outdatatxt << idxPointvsCluster[i];
			outdatatxt << endl;
			outdata << endl;
		}

		return myClusters;
	}


	std::vector<std::vector<Word>> secureClustering(std::vector<std::vector<Word>>& points, u64 inNumCluster, std::vector<std::vector<Word>> initCluster, u64 shift)
	{
		u64 shift10 = pow(10, shift);
		int inDimension = points[0].size();
		u64 numInteration = 2;
		PRNG prng(ZeroBlock);

		u64 inTotalPoint = points.size();

		std::vector<std::vector<Word>> points_shift(points.size());
		std::vector<std::vector<Word>> myClusters(inNumCluster); //[k][d]
		std::vector<u64> idxPointvsCluster(points.size()); //[k][d]

																   //compute cluster
		for (u64 k = 0; k < points.size(); k++) //original cluster
		{
			points_shift[k].resize(inDimension);
			for (u64 d = 0; d < inDimension; d++)
				points_shift[k][d] = points[k][d] * shift10;
		}

		for (u64 k = 0; k < myClusters.size(); k++) //original cluster
		{
			myClusters[k].resize(inDimension);
			for (u64 d = 0; d < inDimension; d++)
				//myClusters[k][d] = clusterDataLoad[k][d];
				//myClusters[k][d] = prng.get<Word>()%inMod;
				myClusters[k][d] = initCluster[k][d]* shift10;

			//std::cout << myClusters[k][0] << "   myClusters[i][0]\n";

		}


		bool stopLoop = false;
		u64 iterLoop = 1;
		//while (!stopLoop)
		for (u64 idxIter = 0; idxIter < 15; idxIter++)
		{
			std::vector<std::vector<Word>> newClusters(myClusters.size()); //[k][d]
			std::vector<std::vector<Word>> eDists(points.size()); //[i][k]
			std::vector<std::vector<Word>> nomCluster(myClusters.size());//[k][d]
			std::vector<Word> denCluster(myClusters.size(), 0);//[k]


			for (u64 k = 0; k < myClusters.size(); k++)
				nomCluster[k].resize(inDimension, 0);

			//compute dist
			for (u64 i = 0; i < points.size(); i++) //original points
			{
				eDists[i].resize(points.size(), 0);
				for (u64 k = 0; k < myClusters.size(); k++) //original cluster
				{
					for (u64 d = 0; d < inDimension; d++)
					{
						auto diff = (points_shift[i][d] - myClusters[k][d]);
						eDists[i][k] = (eDists[i][k] + diff * diff);
					}
				}


			}

			//compute vecMin
			for (u64 i = 0; i < points.size(); i++)
			{
				Word actualMin = eDists[i][0];
				Word actualMinIdx = 0;
				for (u64 k = 1; k < myClusters.size(); k++)
				{
					if (actualMin > eDists[i][k])
					{
						actualMin = eDists[i][k];
						actualMinIdx = k; //cluster idx
					}
				}

				for (u64 d = 0; d < inDimension; d++)
				{
					nomCluster[actualMinIdx][d] = (nomCluster[actualMinIdx][d] + points_shift[i][d]);
				}
				denCluster[actualMinIdx]++;
				idxPointvsCluster[i] = actualMinIdx;
			}


			//divide
			for (u64 k = 0; k < myClusters.size(); k++)
			{
				newClusters[k].resize(inDimension);
				for (u64 d = 0; d < inDimension; d++)
				{
					if (denCluster[k] == 0)
					{
						std::cout << "   denCluster[k]==0=============================================\n";
						newClusters[k][d] = myClusters[k][d];
					}
					else
					{
						newClusters[k][d] = nomCluster[k][d] / denCluster[k];
						std::cout << std::fixed << std::setprecision(2) << myClusters[k][d] << " vs " << newClusters[k][d] << " = " << nomCluster[k][d] << " / " << denCluster[k] << "   newClusters[k][d]\n";
					}
				}
			}


			//check stop

			//compute cluster dist
			double error = 0;
			std::vector<Word> clusterDists(myClusters.size(), 0); //[k][k]

			for (u64 k = 0; k < myClusters.size(); k++) //original cluster
			{
				for (u64 d = 0; d < inDimension; d++)
				{
					//iWord diff = signExtend((newClusters[k1][d] - myClusters[k][d]), p0.mLenMod);
					//clusterDists[k1][k] = signExtend((clusterDists[k1][k] + (iWord)pow(diff, 2)), p0.mLenMod);

					auto diff = ((newClusters[k][d] - myClusters[k][d]));
					//std::cout << myClusters[k][d] << " = " << newClusters[k][d] << " vs " <<diff << "   diff\n";

					clusterDists[k] = (clusterDists[k] + diff * diff);
				}
				//	std::cout << clusterDists[k]<< "   clusterDists[k]\n";
				error = error + (clusterDists[k]);
			}

			std::cout << "secure i=" << iterLoop << "e= " << error << "-----------------------------------------------------\n";
			iterLoop++;
			if (error < 1000)
				stopLoop = true;
			else
				for (u64 k = 0; k < myClusters.size(); k++) //assign cluster
				{
					for (u64 d = 0; d < inDimension; d++)
					{
						myClusters[k][d] = newClusters[k][d];
					}
				}

		}


		ifstream indata;
		ofstream outdata, outdatatxt;
		outdata.open("SecureCluster.csv", ios::trunc);
		outdatatxt.open("SecureCluster.txt", ios::trunc);

		outdata << "Centroids";

		for (u64 k = 0; k < myClusters.size(); k++) //assign cluster
		{
			for (u64 d = 0; d < inDimension; d++)
			{
				outdata << "," << myClusters[k][d];

			}
			outdata << endl;
		}

		outdata << "Data";
		for (u64 i = 0; i < points.size(); i++) //assign cluster
		{
			for (u64 d = 0; d < inDimension; d++)
			{
				outdata << "," << points[i][d];
				outdatatxt << points[i][d] << ",";
			}
			outdatatxt << idxPointvsCluster[i];
			outdatatxt << endl;
			outdata << endl;
		}

		for (u64 k = 0; k < myClusters.size(); k++) //original cluster
		{
			for (u64 d = 0; d < inDimension; d++)
				myClusters[k][d] = myClusters[k][d]/ shift10;
		}

		return myClusters;
	}

#if 0
	double computeAccuracy(std::vector<std::vector<Word>>& points, std::vector<std::vector<double>> output, std::vector<std::vector<double>> expected)
	{

		for (u64 i = 0; i < points.size(); i++) //original points
		{
			eDists[i].resize(points.size(), 0);
			for (u64 k = 0; k < myClusters.size(); k++) //original cluster
			{
				for (u64 d = 0; d < inDimension; d++)
				{
					auto diff = (points[i][d] - myClusters[k][d]);
					eDists[i][k] = (eDists[i][k] + diff * diff);
				}
			}


		}

		return 0;
	}
#endif
}