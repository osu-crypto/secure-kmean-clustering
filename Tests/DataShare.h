#pragma once
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Network/Channel.h>
#include <boost/multiprecision/cpp_int.hpp>
#include <cryptoTools/Common/BitVector.h>
#include <libOTe/TwoChooseOne/IknpOtExtReceiver.h>
#include <libOTe/TwoChooseOne/IknpOtExtSender.h>
#include <libOTe/Base/naor-pinkas.h>
#include <cryptoTools/Crypto/AES.h> 

namespace osuCrypto
{
//#define stepSizeOT=10;

	typedef u64 Word;
	

	struct Share
	{
		//Share() = default;
		//Share(const Share&) = default;
		//Share(const i64& w) : mVal(w) {}

		Word mArithShare; 
		BitVector mBitShare; 
		std::vector<block> recvOtKeys;
		std::vector<AESDec> recvAES;

		std::vector<std::array<block, 2>> sendOtKeys;//NOTE: for their shares
		std::vector<std::array<AES, 2>> sendAES; 

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

	class DataShare
	{
	public:
		DataShare();
		~DataShare();

		


		u64 mPartyIdx;
		std::vector<std::vector<Word>> mPoint;
		std::vector<std::vector<Share>> mSharePoint; //mSharePoint[i][j] <= point i, dimention j
		std::vector<std::vector<std::vector<Word>>> mProdPoint; //[i][d][k] share p^A[i][d]*c^B[k][d]
		std::vector<std::vector<std::vector<Word>>> prodTemp; //to save d-c for test

		std::vector<std::vector<Word>> mCluster;
		std::vector<std::vector<Word>> mShareCluster; //share cluster
		std::vector<std::vector<Word>> mProdCluster; //share of product C^A*C^B


		i64 mTheirSharePointCheck;


		Channel mChl;
		PRNG mPrng, mSharedPrng;

		u64 mTheirNumPoints;
		u64 mTotalNumPoints;
		u64 mNumCluster;
		u64 mMod;
		u64 mLenMod;
		u64 mLenModinByte;
		u64 mDimension;

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

		BitVector getBinary(u64& value, u64 bitLen)
		{
			return BitVector((u8*)&value, bitLen);
		}

		//compute shares[i]*b where choice bit is the bitvector of shares[i], b is "OT sender message"
		// first concating all b-ri, ri. 
		//then using the enc OT keys corressponding to share[i][j] to encrypt and send them to receiver		
		//compute m0
		std::vector<Word> amortAdaptMULsend(u64 theirIdxPoint, u64 theirIdxDim, std::vector<Word>& b);
		
		//compute mi wiht OT receiver
		std::vector<Word> amortAdaptMULrecv(u64 idxPoint, u64 idxDim, u64 theirbsize);


		//for C^A * C^B as OT sender
		std::vector<std::vector<Word>> amortMULsend(std::vector<std::vector<Word>>& b);
		
		//for C^A * C^B as OT receiver
		std::vector<std::vector<Word>> amortMULrecv(std::vector<std::vector<Word>>& a);


		void getInitClusters(u64 startIdx, u64 endIdx);

		void init(u64 partyIdx, Channel& chl, block seed, u64 securityParam, u64 totalPoints
			, u64 numCluster, u64 idxStartCluster, u64 idxEndCluster, std::vector<std::vector<Word>>& data, u64 modd, u64 dimension);

		void sendShareInput(u64 startPointIdx, u64 startClusterIdx, u64 endClusterIdx);
		void recvShareInput(u64 startPointIdx, u64 startClusterIdx, u64 endClusterIdx);

		//using batch aes with fixed key is faster than ...
		void setAESkeys();



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