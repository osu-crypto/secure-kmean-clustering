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
#include <Ivory-Runtime/ivory/Runtime/ShGc/ShGcRuntime.h>
#include <Ivory-Runtime/ivory/Circuit/CircuitLibrary.h>
#include <Ivory-Runtime/ivory/Runtime/sInt.h>
#include <Ivory-Runtime/ivory/Runtime/Party.h>
#include <Ivory-Runtime/ivory/Runtime/ShGc/ShGcInt.h>

namespace osuCrypto
{

static const u64 stepamortAdaptMULSize(1 << 8);
static const u64 stepCorrectAllChoice(1 << 2);

	typedef u64 Word;
	typedef i64 iWord;
	

	template<typename T>
	T signExtend(T v, u64 b, bool print = false)
	{
		if (b > sizeof(T) * 8)
			throw RTE_LOC;

		if (b == sizeof(T) * 8)
			return v;

		T loc = (T(1) << (b - 1));
		T sign = v & loc;

		if (sign)
		{
			T mask = T(-1) << (b);
			auto ret = v | mask;
			if (print)
			{

				std::cout << "sign: " << BitVector((u8*)&sign, sizeof(T) * 8) << std::endl;;
				std::cout << "mask: " << BitVector((u8*)&mask, sizeof(T) * 8) << std::endl;;
				std::cout << "v   : " << BitVector((u8*)&v, sizeof(T) * 8) << std::endl;;
				std::cout << "ret : " << BitVector((u8*)&ret, sizeof(T) * 8) << std::endl;;

			}
			return ret;
		}
		else
		{
			T mask = (T(1) << b) - 1;
			auto ret = v & mask;
			if (print)
			{

				std::cout << "sign: " << BitVector((u8*)&loc, sizeof(T) * 8) << std::endl;;
				std::cout << "mask: " << BitVector((u8*)&mask, sizeof(T) * 8) << std::endl;;
				std::cout << "v   : " << BitVector((u8*)&v, sizeof(T) * 8) << std::endl;;
				std::cout << "ret : " << BitVector((u8*)&ret, sizeof(T) * 8) << std::endl;;

			}
			return ret;
		}
	}



	struct Share
	{
		//Share() = default;
		//Share(const Share&) = default;
		//Share(const i64& w) : mVal(w) {}

		
		Word mArithShare; 
		BitVector mBitShare; 
		std::vector<block> recvOtKeys;
		//std::vector<AESDec> recvAES;

		std::vector<std::array<block, 2>> sendOtKeys;//NOTE: for their shares
		//std::vector<std::array<AES, 2>> sendAES;

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

		

		std::vector<std::vector<std::vector<PRNG>>> mRecvPRNG; //[i][d][l]
		std::vector<std::vector<std::vector<std::array<PRNG, 2>>>> mSendPRNG; //[i][d][l][0/1]

		u64 mPartyIdx;
		std::vector<std::vector<Word>> mPoint;
		std::vector<std::vector<Share>> mSharePoint; //mSharePoint[i][d] <= point i, dimention d
		std::vector<std::vector<Word>> mSharePointsPerDim; //[d][i]

		std::vector<std::vector<std::vector<iWord>>> mProdPointPPC; //[i][d][k] share (p^A[i][d]*(p^B[i][d]-c^B[k][d])
		std::vector<std::vector<std::vector<iWord>>> prodTempPC; //save p^B[i][d]-c^B[k][d] for test

		std::vector<std::vector<iWord>> prodTempC; //save all c^B[d][k] for test
		std::vector<std::vector<std::vector<iWord>>> mProdPointPC; //[i][d][k] share (p^B[i][d]*c^A[k][d])

		std::vector<std::vector<Word>> mCluster;
		std::vector<std::vector<Word>> mShareCluster; //[k][d] share cluster
		std::vector<std::vector<Word>> mProdCluster; // //[k][d]share of product C^A*C^B


		std::vector<std::vector<iWord>> mDist; //[i][k]


		std::vector<block> recvOTmsgClusterOffline;
		std::vector<std::array<block, 2>> sendOTmsgsClusterOffline;
		BitVector allChoicesClusterOffline;
		u64 iterOTused;


		i64 mTheirSharePointCheck;


		Channel mChl;
		PRNG mPrng, mSharedPrng;

		u64 mTheirNumPoints;
		u64 mTotalNumPoints;
		u64 mNumCluster;
		u64 mMod;
		u64 mModSquare;
		u64 mLenMod;
		u64 mLenModSquare;
		u64 mLenModinByte;
		u64 mLenModSquareinByte;
		u64 mDimension;
		u64 mIteration;
		u64 stepIdxMin;

		std::vector<iWord> lastNode; //[i][#cluster-1]


		//OT
		u64 mSecurityParam;
		u64 numBaseOT;
		
		BitVector mBaseChoices;
		std::vector<std::array<block, 2>> mSendBaseMsg;
		std::vector<block> mRecvBaseMsg;

		IknpOtExtSender sender;
		IknpOtExtReceiver recv;
		BitVector mChoiceAllBitSharePoints;
		BitVector mChoiceAllBitSharePointsOffline;
		std::vector<std::array<block, 2>> mSendAllOtKeys;
		std::vector<block> mRecvAllOtKeys;

		BitVector getBinary(u64& value, u64 bitLen)
		{
			return BitVector((u8*)&value, bitLen);
		}

		BitVector getBinary(u32& value, u32 bitLen)
		{
			return BitVector((u8*)&value, bitLen);
		}


		ShGcRuntime rt;
		std::array<Party, 2> parties{
			Party(rt, 0),
			Party(rt, 1)
		};

		void getPointPerDimension();

		//compute shares[i]*b where choice bit is the bitvector of shares[i], b is "OT sender message"
		// first concating all b-ri, ri. 
		//then using the enc OT keys corressponding to share[i][j] to encrypt and send them to receiver		
		//compute m0
		std::vector<iWord> amortAdaptMULsend(u64 theirIdxPoint, u64 theirIdxDim, std::vector<iWord>& b);
		
		//compute mi wiht OT receiver
		std::vector<iWord> amortAdaptMULrecv(u64 idxPoint, u64 idxDim, u64 theirbsize);


		

		//for C^A * C^B as OT sender
		std::vector<std::vector<Word>> amortMULsend(std::vector<std::vector<Word>>& b, u64 iterOTstart = 0);
		
		//for C^A * C^B as OT receiver
		std::vector<std::vector<Word>> amortMULrecv(std::vector<std::vector<Word>>& a, u64 iterOTstart = 0);


		void getInitClusters(u64 startIdx, u64 endIdx);

		void init(u64 partyIdx, Channel& chl, block seed, u64 securityParam, u64 totalPoints
			, u64 numCluster, u64 idxStartCluster, u64 idxEndCluster, std::vector<std::vector<Word>>& data
			, u64 modd, u64 dimension, u64 iteration=1);

		void sendShareInput(u64 startPointIdx, u64 startClusterIdx, u64 endClusterIdx);
		void recvShareInput(u64 startPointIdx, u64 startClusterIdx, u64 endClusterIdx);
		void appendAllChoice();
		void correctAllChoiceSender();
		void correctAllChoiceRecv();

		//using batch aes with fixed key is faster than ...
		void setPRNGseeds();

		void computeDist();
		

		//======================min cluster

		//compute (M^A+M^B)*(P^A+P^B)
		BitVector mOffOtChoices; 
		std::vector<std::array<block, 2>> mMinClusterOtSends;
		std::vector<block> mMinClusterOtRecv;

		std::vector<BitVector> mVecGcMinOutput; //save output pairwise min, size=#node of each tree level
		//std::vector<std::vector<Word>> mShareBinArithMulSend; //[i][k], k depends tree level; save share of (b^A \xor b^B)*P^A
		//std::vector<std::vector<Word>> mShareBinArithMulRecv; //[i][k] k depends tree level; save share of (b^A \xor b^B)*P^B
		std::vector<std::vector<Word>> mShareBinArithMul; //[i][k] k depends tree level; save share of (b^A \xor b^B)*P^B
		std::vector<std::vector<iWord>> mShareMin; //[i][k] k depends tree level; save share of (b^A \xor b^B)*P^B

		std::vector<BitVector> mVecIdxMin; //maintain 0000010000000 <-indicate min. size is always = #clusters
		//std::vector<std::vector<BitVector>> mVecIdxMinSend; //[i][k], k depends tree level; save share of (b^A \xor b^B)*P^A
		//std::vector<std::vector<BitVector>> mVecIdxMinRecv; //[i][k] k depends tree level; save share of (b^A \xor b^B)*P^B


		std::vector<BitVector> mVecIdxMinTranspose; //[k][i] //transpose of mVecIdxMin
		
		//compute (b^A \xor b^B)*(P^A+P^B)
		//OT sender m0 = r + b^A*P^A;  m1 = r + (1-b^A)*P^A 
		//Co-OT: deltaOT= (1-2*b^A)*P^A 
		//NOTE: sender output= r-b^AP^A, receiver output=r+b^B*(1-2*b^A)*P^A=r+(b^A \xor b^B)*P^A -b^AP^A
		void amortBinArithMulsend(std::vector<std::vector<iWord>>& outShareSend, std::vector<BitVector>& bitVecs, std::vector<std::vector<iWord>>& arithVecs); //[i][k], upto [k/2] all points
		//compute mi wiht OT receiver
		void amortBinArithMULrecv(std::vector<std::vector<iWord>>& outShareRecv,std::vector<BitVector>& bitVecs);

		//bitVecsIdxMin maintain index of min: input as 1010||1001, output=1010*b||1001*!b
		//stepIdxMin=4 for above example
		void amortBinArithMulGCsend(std::vector<std::vector<iWord>>& outShareSend
			, std::vector<std::vector<BitVector>>& outIdxShareSend
			, std::vector<BitVector>& bitGcMinOutVecs, std::vector<std::vector<iWord>>& arithVecs, std::vector<BitVector>& bitVecsIdxMin, u64 stepIdxMin);
		void amortBinArithMulGCrecv(std::vector<std::vector<iWord>>& outShareRecv
			, std::vector<std::vector<BitVector>>& outIdxShareRecv
			, std::vector<BitVector>& bitGcMinOutVecsk, u64 stepIdxMin);

		void computeBinArithMUL(std::vector<std::vector<iWord>>& outShareSend, std::vector<std::vector<iWord>>& outShareRecv); //compute (b^A \xor b^B)*(P^A+P^B)
		void computeShareMin(std::vector<std::vector<iWord>>& outShareSend, std::vector<std::vector<iWord>>& outShareRecv); //compute (b1^A \xor b1^B)*(P1^A+P1^B)+(b2^A \xor b2^B)*(P2^A+P2^B) where b2=P1<P2, b1=!b2
		void computeShareIdxMin(std::vector<std::vector<BitVector>>& outShareSend, std::vector<std::vector<BitVector>>& outShareRecv); //compute (b1^A \xor b1^B)*(V1^A+P1^B)+(b2^A \xor b2^B)*(P2^A+P2^B) where b2=P1<P2, b1=!b2

		//=================Update Cluster

		std::vector<std::vector<iWord>> mShareNomCluster; //[k][d] share cluster
		std::vector<iWord> mShareDecCluster; //[k] share cluster

		void vecMinTranspose(); //TODO: matrix transpose

		//outShareClustSend[k][d], bitVecs[i], compute b*((P1||P2||...||Pd)||1)
		void amortBinArithClustsend(std::vector<BitVector>& bitVecs, std::vector<std::vector<iWord>>& outShareClustSend, std::vector<iWord>& outDenSend, bool isDen);
		void amortBinArithClustrecv(std::vector<BitVector>& bitVecs, std::vector<std::vector<iWord>>& outShareClustRecv, std::vector<iWord>& outDenRecv, bool isDen);
		void computeShareCluster(std::vector<std::vector<iWord>>& shareNomSend, std::vector<std::vector<iWord>>& shareNomRecv
			, std::vector<iWord>&shareDenSend, std::vector<iWord>&shareDenSRecv);

		//============print
		void Print();
		


	};

}