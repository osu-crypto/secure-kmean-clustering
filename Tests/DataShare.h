#pragma once
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Network/Channel.h>
#include <boost/multiprecision/cpp_int.hpp>
#include <cryptoTools/Common/BitVector.h>


namespace osuCrypto
{

	class DataShare
	{
	public:
		DataShare();
		~DataShare();

		u64 mPartyIdx;
		std::vector<std::vector<i64>> mData;

		Channel mChl;
		PRNG mPrng, mSharedPrng;
		

		//OT
		u64 numBaseOT = 128;
		BitVector mBaseChoices;
		std::vector<std::array<block, 2>> sendBaseMsg;
		std::vector<block> recvBaseMsg;


		std::vector<std::array<block, 2>> sendOtKeys;
		std::vector<block> recvOtKeys;

		void init(u64 partyIdx, Channel& chl, block seed, std::vector<std::vector<i64>> data);

		struct Share
		{
			Share() = default;
			Share(const Share&) = default;
			Share(const i64& w) : mData(w) {}

			i64 mData;

			Share& operator=(const Share& copy);
			Share operator+(const Share& rhs) const;
			Share operator-(const Share& rhs) const;
			Share& operator-=(const Share& rhs);
			Share& operator+=(const Share& rhs);
		};


	};


	inline DataShare::Share& DataShare::Share::operator=(const DataShare::Share& copy)
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
	}
}