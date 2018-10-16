#include "DataShare.h"


namespace osuCrypto
{

	DataShare::DataShare()
	{
	}


	DataShare::~DataShare()
	{
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
		, std::vector<std::vector<Word>> data, u64 len, u64 dimension)
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

	void DataShare::copyKeyToShare() {

		for (u64 i = 0; i < mTotalNumPoints; i++)
		{
			for (u64 j = 0; j < mDimension; j++)
			{
				//memcpy((u8*)&mSharePoint[i][j].mArithShare, mSendAllOtKeys.data() + iter, mLenModinByte); //get their share
				
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

		std::cout << "OT key base 1: send[0][0]=" << mSendAllOtKeys[0][0] << "\t send[0][1]=" << mSendAllOtKeys[0][1] << "\n";
		std::cout << "OT key base 2: choice[0]=" << mChoiceAllBitSharePoints[0] << "\t recv[0]=" << mRecvAllOtKeys[0] << "\n";


		std::cout << IoStream::unlock;

	}

}