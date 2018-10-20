#include "DataShare.h"


namespace osuCrypto
{

	DataShare::DataShare()
	{
	}


	DataShare::~DataShare()
	{
	}



	std::vector<Word> DataShare::amortAdaptMULsend(u64 theirIdxPoint, u64 theirIdxDim, std::vector<Word>& b) //b=di-ci
	{

		std::cout << b.size() << " b.size()\n";
		u64 roundUpNumBlks = (b.size()*mLenModinByte + 15) / 16;
		std::vector<u8> sendBuff(mLenMod*roundUpNumBlks * 2 * sizeof(block));


		std::vector<std::array<std::vector<u8>, 2>> allPlaintexts(mLenMod);
		std::vector<std::array<std::vector<block>,2>> allBlkPlaintexts(mLenMod);

		std::vector<Word> m0(b.size(),0); //sum OT m0 messages


		for (u64 l = 0; l < mLenMod; l++)
		{
			allPlaintexts[l][0].resize(b.size()*mLenModinByte); //b.size x OT len x |x|
			allPlaintexts[l][1].resize(b.size()*mLenModinByte);
			allBlkPlaintexts[l][0].resize(roundUpNumBlks); //block
			allBlkPlaintexts[l][1].resize(roundUpNumBlks);
		}



		for (u64 k = 0; k < b.size(); k++)
		{
				for (u64 l = 0; l < mLenMod; l++)
				{
					Word r0 = (mPrng.get<Word>()) % mMod; //OT message
					auto r1= (Word)(b[k]*pow(2, l) + r0) % mMod;

					std::cout << IoStream::lock;
					std::cout << k << "-" << l << ":  "<< r0 << " r0\n";
					std::cout << k << "-" << l<<":  "<< r1 << " r1\n";
					std::cout << IoStream::unlock;

					m0[k]= (m0[k]+r0) % mMod;

					memcpy(allPlaintexts[l][0].data()+ mLenModinByte*k, (u8*)&r0, mLenModinByte); //OT len
					memcpy(allPlaintexts[l][1].data() + mLenModinByte*k, (u8*)&r1, mLenModinByte);
					

					//Word r0Check=0;
					//memcpy((u8*)&r0Check, allPlaintexts[l][0].data() + mLenModinByte*l, mLenModinByte);
					//std::cout << r0 <<" " << mLenModinByte << "\n";
					//std::cout << r0Check << "\n";

				}
		}

		//for (u64 i = 0; i < b.size(); i++)
		//{
		//	Word r0Check = 0;
		//	memcpy((u8*)&r0Check, allPlaintexts[0][0].data() + mLenModinByte*i, mLenModinByte);

		//	std::cout << r0Check << "  r0Check\n";

		//}

		//for (u64 i = 0; i < allPlaintexts[0][0].size(); i += mLenModinByte)
		//{
		//	Word r0Check = 0;
		//	memcpy((u8*)&r0Check, allPlaintexts[0][0].data() + i, mLenModinByte);

		//	std::cout << r0Check << "  rrr0Check\n";

		//}


		u64 iter = 0;
		for (u64 l = 0; l < mLenMod; l++)
		{
			//std::cout << "allPlaintexts[l][0].size(): " << allPlaintexts[l][0].size() << "\n";
			for (u64 i = 0; i < (allPlaintexts[l][0].size()+15)/16; i++)
			{
				allBlkPlaintexts[l][0][i] = toBlock(allPlaintexts[l][0].data()+i*sizeof(block));
				allBlkPlaintexts[l][1][i] = toBlock(allPlaintexts[l][1].data() + i*sizeof(block));
				//std::cout << allBlkPlaintexts[l][0][i] << "  Block\n";
			}


			block* cipher = new block[allBlkPlaintexts[l][0].size()];
			mSharePoint[theirIdxPoint][theirIdxDim].sendAES[l][0].ecbEncBlocks
			(allBlkPlaintexts[l][0].data(), allBlkPlaintexts[l][0].size(), cipher); //r0||r1||r2
			
			std::cout << IoStream::lock;
			std::cout << mSharePoint[theirIdxPoint][theirIdxDim].sendOtKeys[l][0] << " s0 key \n";
			std::cout << allBlkPlaintexts[l][0][0] << " snd allBlkPlaintexts[l][0][0]\n";
			for (size_t ii = 0; ii <allBlkPlaintexts[l][0].size(); ii++)
			{
				std::cout << cipher[ii] << " snd cipher0\n";

			}
			std::cout << IoStream::unlock;

			memcpy(sendBuff.data()+ iter, (u8 *)&cipher[0], allBlkPlaintexts[l][0].size()*sizeof(block));

			block test;
			memcpy(&test, sendBuff.data() + iter, sizeof(block));
			std::cout << IoStream::lock;
			std::cout << test << "  sendBuff.data() test \n";
			std::cout << IoStream::unlock;
			
			iter += roundUpNumBlks * sizeof(block);

			mSharePoint[theirIdxPoint][theirIdxDim].sendAES[l][1].ecbEncBlocks
			(allBlkPlaintexts[l][1].data(), allBlkPlaintexts[l][1].size(), cipher); //c0-r0||c1-r1||c2=r2

			std::cout << IoStream::lock;
			std::cout << mSharePoint[theirIdxPoint][theirIdxDim].sendOtKeys[l][1] << " s1 key \n";
			std::cout << allBlkPlaintexts[l][1][0] << " snd allBlkPlaintexts[l][1][0]\n";
			std::cout << cipher[0] << " snd cipher1\n";
			std::cout << IoStream::unlock;
			memcpy(sendBuff.data() + iter, (u8 *)&cipher[0], allBlkPlaintexts[l][0].size() * sizeof(block));
			iter += roundUpNumBlks * sizeof(block);
		}


		block test;
		memcpy(&test, sendBuff.data(), sizeof(block));
		std::cout << IoStream::lock;
		std::cout << test << "  sendBuff.data() \n";
		std::cout << IoStream::unlock;
		mChl.asyncSend(std::move(sendBuff));



#if 0 //check
		for (u64 l = 0; l < mLenMod; l++)
		{
			
				for (u64 j = 0; j < b.size(); j++)
				{
					Word r0Check = 0;
					memcpy((u8*)&r0Check, allPlaintexts[l][0].data() + mLenModinByte*j, mLenModinByte);
					std::cout << r0Check << "  r0Check\n";
				}


				std::vector<u8> vecCheckk((allBlkPlaintexts[l][0].size()* sizeof(block)));

				for (u64 j = 0; j < allBlkPlaintexts[l][0].size(); j++)
				{
					auto check = ByteArray(allBlkPlaintexts[l][0][j]);
					memcpy(vecCheckk.data()+j* sizeof(block), check, sizeof(block)); //merging all blocks
				}

				for (u64 l = 0; l < b.size(); l++)
				{
					Word r0Check = 0;
					memcpy((u8*)&r0Check, vecCheckk.data() + mLenModinByte*l, mLenModinByte);
					std::cout << r0Check << "  rrr0Check\n";
				}

		}
#endif

		for (u64 k = 0; k < b.size(); k++)
		{
			m0[k] = (0-m0[k] ) % mMod;
		}
		return m0;
	}

	std::vector<Word> DataShare::amortAdaptMULrecv(u64 idxPoint, u64 idxDim, u64 theirbsize)
	{
		std::vector<u8> recvBuff;// (theirbsize*mLenModinByte*mLenMod * 2);
		std::vector<Word> mi(theirbsize, 0); //sum OT m0 messages
		u64 roundUpNumBlks = (theirbsize*mLenModinByte + 15) / 16;

		std::vector<std::vector<u8>> allPlaintexts(mLenMod);
		std::vector<std::array<std::vector<block>, 2>> allBlkCipherexts(mLenMod);
		for (u64 l = 0; l < mLenMod; l++)
		{
			allPlaintexts[l].resize(theirbsize*mLenModinByte); //b.size x OT len x |x|
			allBlkCipherexts[l][0].resize(roundUpNumBlks);
			allBlkCipherexts[l][1].resize(roundUpNumBlks);
		}


		mChl.recv(recvBuff);
		if (recvBuff.size() != (roundUpNumBlks *mLenMod * 2*sizeof(block) ))
		{
			std::cout << "recvBuff.size() != (theirbsize*mLenModinByte + 15) / 16 *mLenMod * 2" << 
				recvBuff.size()<< " vs " << (roundUpNumBlks* mLenMod * 2 * sizeof(block)) << "\n";
			throw std::exception();
		}

		block test;
		memcpy(&test, recvBuff.data() , sizeof(block));
		std::cout << IoStream::lock;
		std::cout << test<< "  recvBuff.data() \n";
		std::cout << IoStream::unlock;


		u64 iter = 0;
		for (u64 l = 0; l < mLenMod; l++)
		{

			memcpy(allBlkCipherexts[l][0].data(), recvBuff.data() + iter, roundUpNumBlks*sizeof(block));
			iter += roundUpNumBlks * sizeof(block);

			memcpy(allBlkCipherexts[l][1].data(), recvBuff.data() + iter, roundUpNumBlks * sizeof(block));
			iter += roundUpNumBlks * sizeof(block);


			block* allBlkPlaintexts = new block[allBlkCipherexts[l][0].size()]; //mi0||mi1||mi_#cluster

			if(l==mLenMod-1)
				std::cout<< mSharePoint[idxPoint][idxDim].mBitShare[l];

			u8 choice = mSharePoint[idxPoint][idxDim].mBitShare[l];
			mSharePoint[idxPoint][idxDim].recvAES[l].ecbDecBlocks
			(allBlkCipherexts[l][choice].data(), allBlkCipherexts[l][choice].size(), allBlkPlaintexts);

			std::cout << IoStream::lock;

			std::cout << "r: k= "<< mSharePoint[idxPoint][idxDim].recvOtKeys[l] << "\t ";
			std::cout << "cr01= " << allBlkCipherexts[l][0][0] << " vs " << allBlkCipherexts[l][1][0] <<"\t";
			std::cout << "rb=" << allBlkPlaintexts[0] << "  vs " << mSharePoint[idxPoint][idxDim].mBitShare[l] << "\n";
			std::cout << IoStream::unlock;

			for (u64 k = 0; k < theirbsize; k++)
			{
				Word r = 0;
				memcpy((u8*)&r, (u8*)&allBlkPlaintexts[0]+k*mLenModinByte, mLenModinByte); //mik

				std::cout << IoStream::lock;
				std::cout << k << "-" << l << ":  " << r << " rb\n";
				std::cout << IoStream::unlock;

				mi[k]= (mi[k]+r) % mMod;
			}
			
		}

		return mi;
	}



	void DataShare::getInitClusters(u64 startIdx, u64 endIdx) {

		//std::cout << startIdx << "\n";
		//std::cout << endIdx << "\n";

		for (u64 i = startIdx; i < endIdx; i++)
		{
			for (u64 j = 0; j < mDimension; j++)
			{
				mCluster[i][j] = mSharedPrng.get<Word>() % mMod; //TODO:choose local cluster or using Locality sensitive hashing
			}
		}

	};

	void DataShare::init(u64 partyIdx, Channel & chl, block seed, u64 securityParam, u64 totalPoints
		, u64 numCluster, u64 idxStartCluster, u64 idxEndCluster
		, std::vector<std::vector<Word>>& data, u64 len, u64 dimension)
	{
		mPartyIdx = partyIdx;
		mChl = chl;
		mPrng.SetSeed(seed ^ toBlock(323452345 * partyIdx));
		mSharedPrng.SetSeed(toBlock(64823974291));
		mPoint = data;
		mMod = pow(2,len);
		mLenMod = len;
		mLenModinByte = (len + 7) / 8;

		mDimension = dimension;
		
		
		mTotalNumPoints = totalPoints;
		mTheirNumPoints = mTotalNumPoints -mPoint.size();

		mSharePoint.resize(mTotalNumPoints);
		for (u64 i = 0; i < mSharePoint.size(); i++)
			mSharePoint[i].resize(mDimension);

		
		mNumCluster = numCluster;
		mCluster.resize(mNumCluster);
		mShareCluster.resize(mNumCluster);
		for (u64 i = 0; i < mShareCluster.size(); i++)
		{
			mCluster[i].resize(mDimension);
			mShareCluster[i].resize(mDimension);
		}
		getInitClusters(idxStartCluster, idxEndCluster);

		//base OT
		mSecurityParam = securityParam;
		numBaseOT = securityParam;
		mBaseChoices.resize(numBaseOT);
		mBaseChoices.randomize(mPrng);
		mSendBaseMsg.resize(numBaseOT);
		mRecvBaseMsg.resize(numBaseOT);

		//OT for keys
		mSendAllOtKeys.resize(mTotalNumPoints*mDimension*mLenMod);
		mRecvAllOtKeys.resize(mTotalNumPoints*mDimension*mLenMod);
		

	}




	
	void DataShare::sendShareInput(u64 startPointIdx, u64 startClusterIdx, u64 endClusterIdx)
	{
		std::vector<u8> sendBuff((mPoint.size()+ endClusterIdx- startClusterIdx+1)*mDimension*mLenModinByte);

		int iter = 0;

		//Data
		for (u64 i = startPointIdx; i < startPointIdx+mPoint.size(); i++)
		{
			for (u64 j = 0; j < mDimension; j++)
			{
				mSharePoint[i][j].mArithShare = mSharedPrng.get<Word>() % mMod; //randome share
				mSharePoint[i][j].mBitShare = mSharePoint[i][j].getBinary(mLenMod); //bit vector

				mChoiceAllBitSharePoints.append(mSharePoint[i][j].mBitShare);

				auto theirShare = (mPoint[i - startPointIdx][j]-mSharePoint[i][j].mArithShare) % mMod;
				memcpy(sendBuff.data() + iter, (u8*)&theirShare, mLenModinByte);
				iter += mLenModinByte;
			}
			//std::cout << i << "\n";
		}

		//Cluster
		for (u64 i = startClusterIdx; i < endClusterIdx; i++)
		{
			for (u64 j = 0; j < mDimension; j++)
			{
				mShareCluster[i][j].mArithShare = mSharedPrng.get<Word>() % mMod; //randome share
				mShareCluster[i][j].mBitShare = mShareCluster[i][j].getBinary(mLenMod); //bit vector

				auto theirShare = (mCluster[i][j] - mShareCluster[i][j].mArithShare) % mMod;
				memcpy(sendBuff.data() + iter, (u8*)&theirShare, mLenModinByte);
				iter += mLenModinByte;
			}
			//std::cout << i << "\n";
		}

		mChl.asyncSend(std::move(sendBuff));


	}

	void DataShare::recvShareInput(u64 startPointIdx, u64 startClusterIdx, u64 endClusterIdx)
	{
		std::vector<u8> recvBuff((mTheirNumPoints + endClusterIdx - startClusterIdx + 1)*mDimension*mLenModinByte);
		mChl.recv(recvBuff);
		int iter = 0;

		for (u64 i = startPointIdx; i < startPointIdx +mTheirNumPoints; i++)
		{
			for (u64 j = 0; j < mDimension; j++)
			{
				memcpy((u8*)&mSharePoint[i][j].mArithShare, recvBuff.data() + iter, mLenModinByte); //get their share
				iter += mLenModinByte;
				mSharePoint[i][j].mBitShare = mSharePoint[i][j].getBinary(mLenMod); //bit vector
			}
		}

		//Cluster
		for (u64 i = startClusterIdx; i < endClusterIdx; i++)
		{
			for (u64 j = 0; j < mDimension; j++)
			{
				memcpy((u8*)&mShareCluster[i][j].mArithShare, recvBuff.data() + iter, mLenModinByte); //get their share
				iter += mLenModinByte;
				mShareCluster[i][j].mBitShare = mShareCluster[i][j].getBinary(mLenMod); //bit vector
			}
			//std::cout << i << "\n";
		}


	}

	void DataShare::setAESkeys() {

		u64 iterSend = 0;
		u64 iterRecv = 0;
		for (u64 i = 0; i < 1; i++)
		{
			for (u64 j = 0; j < 1; j++)
			{
				mSharePoint[i][j].sendOtKeys.resize(mLenMod);
				memcpy(mSharePoint[i][j].sendOtKeys.data(), mSendAllOtKeys.data() + iterSend, mLenMod *sizeof(block)*2); //get their share
				iterSend += mLenMod * sizeof(block) * 2;


				mSharePoint[i][j].sendAES.resize(mLenMod);
				for (u64 l = 0; l < mLenMod; l++)
				{
					mSharePoint[i][j].sendAES[l][0].setKey(mSharePoint[i][j].sendOtKeys[l][0]);
					mSharePoint[i][j].sendAES[l][1].setKey(mSharePoint[i][j].sendOtKeys[l][1]);

				}

				mSharePoint[i][j].recvOtKeys.resize(mLenMod);
				memcpy(mSharePoint[i][j].recvOtKeys.data(), mRecvAllOtKeys.data() + iterRecv, mLenMod * sizeof(block) ); //get their share
				iterRecv += mLenMod * sizeof(block);

				mSharePoint[i][j].recvAES.resize(mLenMod);
				for (u64 k = 0; k < mLenMod; k++)
				{
					mSharePoint[i][j].recvAES[k].setKey(mSharePoint[i][j].recvOtKeys[k]);
				}

			}
		}

	}
	

	void DataShare::Print() {
		
		std::cout<< IoStream::lock;
		std::cout << "===========Party "<< mPartyIdx << " ==============\n";
		std::cout << "d=" << mDimension << "\t mod=" << mMod << "\t mPoint[0][0]=" << mPoint[0][0] << "\n";
		std::cout << "OT base 1: send[0][0]=" << mSendBaseMsg[0][0] << "\t send[0][1]=" << mSendBaseMsg[0][1] << "\n";
		std::cout << "OT base 2: choice[0]=" << mBaseChoices[0] << "\t recv[0]=" << mRecvBaseMsg[0] << "\n";
		
		if (mPartyIdx == 0)
		{
			std::cout << "Share1: mSharePoint[0][0].mArithShare=" << mSharePoint[0][0].mArithShare << " vs " << mSharePoint[0][0].mBitShare<<   "\n";
			std::cout << "Share2: mSharePoint[n][0].mArithShare=" << mSharePoint[mPoint.size()][0].mArithShare << " vs " << mSharePoint[mPoint.size()][0].mBitShare<<  "\n";
			//std::cout << "mTheirSharePointCheck=" << mTheirSharePointCheck << "\n";
		
		}
		else
		{
			std::cout << "Share1: mSharePoint[0][0].mArithShare=" << mSharePoint[0][0].mArithShare << " vs " << mSharePoint[0][0].mBitShare<<  "\n";
			std::cout << "Share2: mSharePoint[n][0].mArithShare=" << mSharePoint[mTheirNumPoints][0].mArithShare << " vs " << mSharePoint[mTheirNumPoints][0].mBitShare<<   "\n";
			//std::cout << "mTheirSharePointCheck=" << mTheirSharePointCheck << "\n";

		}

		std::cout << "-------------\nOT allkey base 1: send[0][0]=" << mSendAllOtKeys[0][0] << "\t send[0][1]=" << mSendAllOtKeys[0][1] << "\n";
		std::cout << "OT allkey base 2: choice[0]=" << mChoiceAllBitSharePoints[0] << "\t recv[0]=" << mRecvAllOtKeys[0] << "\n";



		std::cout << "-------------\nOT key base 1: send[0][0]=" << mSharePoint[0][0].sendOtKeys[0][0] << "\t send[0][1]=" << mSharePoint[0][0].sendOtKeys[0][1] << "\n";
		std::cout << "OT key base 2: choice[0]=" << mSharePoint[0][0].mBitShare[0] << "\t recv[0]=" << mSharePoint[0][0].recvOtKeys[0] << "\n";


		std::cout << IoStream::unlock;

	}

	

	

}