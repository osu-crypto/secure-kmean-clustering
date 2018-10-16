#include "DataShare.h"


namespace osuCrypto
{
	DataShare::DataShare()
	{
	}


	DataShare::~DataShare()
	{
	}
	void DataShare::init(u64 partyIdx, Channel & chl, block seed, std::vector<std::vector<i64>> data, u64 modd, u64 dimension)
	{
		mPartyIdx = partyIdx;
		mChl = chl;
		mPrng.SetSeed(seed ^ toBlock(323452345 * partyIdx));
		mSharedPrng.SetSeed(toBlock(64823974291));
		mData = data;
		mMod = modd;
		mDimension = dimension;
		//OT
		mBaseChoices.resize(numBaseOT);
		mBaseChoices.randomize(mPrng);
		mSendBaseMsg.resize(numBaseOT);
		mRecvBaseMsg.resize(numBaseOT);
	}

	void DataShare::Print() {
		
		std::cout<< IoStream::lock;
		std::cout << "=========================\n";
		std::cout << "d=" << mDimension << "\t mod=" << mMod << "\t mData[0][0]=" << mData[0][0] << "\n";
		std::cout << "OT base 1: send[0][0]=" << mSendBaseMsg[0][0] << "\t send[0][1]=" << mSendBaseMsg[0][1] << "\n";
		std::cout << "OT base 2: choice[0]=" << mBaseChoices[0] << "\t recv[0]=" << mRecvBaseMsg[0]  << "\n";
		std::cout << IoStream::unlock;

	}

}