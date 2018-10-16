#pragma once
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Network/Channel.h>
#include <boost/multiprecision/cpp_int.hpp>
#include <cryptoTools/Common/BitVector.h>
#include <libOTe/TwoChooseOne/IknpOtExtReceiver.h>
#include <libOTe/TwoChooseOne/IknpOtExtSender.h>
#include <libOTe/Base/naor-pinkas.h>

namespace osuCrypto
{
	typedef u64 Word;

	class DataShare
	{
	public:
		DataShare();
		~DataShare();

		struct Share
		{
			//Share() = default;
			//Share(const Share&) = default;
			//Share(const i64& w) : mVal(w) {}

			Word mArithShare;
			BitVector mBitShare;
			std::vector<std::array<block, 2>> sendOtKeys;
			std::vector<block> recvOtKeys;

			//Share& operator=(const Share& copy);
			//Share operator+(const Share& rhs) const;
			//Share operator-(const Share& rhs) const;
			//Share& operator-=(const Share& rhs);
			//Share& operator+=(const Share& rhs);
			BitVector getBinary(u64 bitLen)
			{
				return BitVector((u8*)&mArithShare, bitLen);
			}
		};


		u64 mPartyIdx;
		std::vector<std::vector<Word>> mPoint;
		std::vector<std::vector<Share>> mSharePoint;
		
		std::vector<std::vector<Word>> mCluster;
		std::vector<std::vector<Share>> mShareCluster;


		i64 mTheirSharePointCheck;


		Channel mChl;
		PRNG mPrng, mSharedPrng;
		u64 mMod;
		u64 mLenMod;
		u64 mLenModinByte;
		u64 mDimension;
		u64 mTheirNumPoints;
		u64 mTotalNumPoints;
		u64 mNumCluster;
	

		//OT
		u64 mSecurityParam;
		u64 numBaseOT;
		
		BitVector mBaseChoices;
		std::vector<std::array<block, 2>> mSendBaseMsg;
		std::vector<block> mRecvBaseMsg;

		IknpOtExtSender sender;
		IknpOtExtReceiver recv;
		BitVector mChoiceAllBitSharePoints;
		std::vector<std::array<block, 2>> mSendAllOtKeys;
		std::vector<block> mRecvAllOtKeys;




		void getInitClusters(u64 startIdx, u64 endIdx);

		void init(u64 partyIdx, Channel& chl, block seed, u64 securityParam, u64 totalPoints
			, u64 numCluster, u64 idxStartCluster, u64 idxEndCluster, std::vector<std::vector<Word>> data, u64 modd, u64 dimension);

		void sendShareInput(u64 startPointIdx, u64 startClusterIdx, u64 endClusterIdx);
		void recvShareInput(u64 startPointIdx, u64 startClusterIdx, u64 endClusterIdx);

		void copyKeyToShare();


		void Print();

		

	};


	/*inline DataShare::Share& DataShare::Share::operator=(const DataShare::Share& copy)
	{
		mData = copy.mData;
		return *this;
	}

	inline DataShare::Share DataShare::Share::operator+(const DataShare::Share& val) const
	{
		return Share{ mData + val.mData };
	}

	inline DataShare::Share DataShare::Share::operator-(const DataShare::Share& val) const
	{
		return Share{ mData - val.mData };
	}

	inline DataShare::Share& DataShare::Share::operator+=(const DataShare::Share& val)
	{
		mData += val.mData;
		return *this;
	}

	inline DataShare::Share& DataShare::Share::operator-=(const DataShare::Share& val)
	{
		mData -= val.mData;
		return *this;
	}*/
}