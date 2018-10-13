#include "DataShare.h"


namespace osuCrypto
{
	DataShare::DataShare()
	{
	}


	DataShare::~DataShare()
	{
	}
	void DataShare::init(u64 partyIdx, Channel & chl, block seed, std::vector<std::vector<i64>> data)
	{
		mPartyIdx = partyIdx;
		mChl = chl;
		mPrng.SetSeed(seed ^ toBlock(323452345 * partyIdx));
		mSharedPrng.SetSeed(toBlock(64823974291));
		mData = data;

		//OT
		mBaseChoices.resize(numBaseOT);
		mBaseChoices.randomize(mPrng);
		sendBaseMsg.resize(numBaseOT);
		recvBaseMsg.resize(numBaseOT);
	}

}