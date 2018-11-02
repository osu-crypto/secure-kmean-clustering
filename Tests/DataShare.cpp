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
		std::vector<u8> sendBuff(mLenModinByte*b.size()*mLenMod);
		std::vector<Word> m0(b.size(), 0); //sum OT m0 messages
		std::vector<std::array<Word*,2>> maskSendOT(mLenMod); //[l][0/1][k]
		
		for (u64 l = 0; l < mLenMod; l++)
		{
			maskSendOT[l][0] = new Word[b.size()];
			maskSendOT[l][1] = new Word[b.size()];
			mSendPRNG[theirIdxPoint][theirIdxDim][l][0].get<Word>(maskSendOT[l][0], b.size());
			mSendPRNG[theirIdxPoint][theirIdxDim][l][1].get<Word>(maskSendOT[l][1], b.size());

			std::cout << IoStream::lock;
			std::cout << maskSendOT[l][0][0] << " " << maskSendOT[l][1][0] << " PRNG s \n";
			std::cout << maskSendOT[l][0][b.size()-1] << " " << maskSendOT[l][1][b.size() - 1] << " PRNG s \n";
			std::cout << mSendPRNG[theirIdxPoint][theirIdxDim][l][0].getSeed() << " PRNG  getSeed s \n";;
			std::cout <<  mSendPRNG[theirIdxPoint][theirIdxDim][l][1].getSeed() << " PRNG  getSeed s \n";;
			std::cout << IoStream::unlock;
		}


		u64 iter = 0;
		for (u64 k = 0; k < b.size(); k++)
		{
			for (u64 l = 0; l < mLenMod; l++)
			{
				m0[k] = (m0[k] + maskSendOT[l][0][k]) % mMod; //r0= maskSendOT[l][0][k]

				std::cout << IoStream::lock;
				Word r0 = maskSendOT[l][0][k] % mMod; //OT message
				auto delta = (Word)(b[k] * pow(2, l)) % mMod;
				std::cout << k << "-" << l << ":  " << r0 << " vs " << (r0 + delta) % mMod << " r1\n";
				std::cout << IoStream::unlock;

				//mask
				Word mask = (maskSendOT[l][0][k] % mMod + maskSendOT[l][1][k] % mMod + (Word)(b[k] * pow(2, l)) % mMod) % mMod;;
				memcpy(sendBuff.data() + iter, (u8*)&mask, mLenModinByte);
				iter += mLenModinByte;
			}
		}

		//Word test;
		//memcpy(&test, sendBuff.data(), mLenModinByte);
		//std::cout << IoStream::lock;
		//std::cout << test << "  sendBuff.data() \n";
		//std::cout << IoStream::unlock;

		mChl.asyncSend(std::move(sendBuff));


		for (u64 k = 0; k < b.size(); k++)
		{
			m0[k] = (0 - m0[k]) % mMod;
		}
		return m0;
	}

	std::vector<Word> DataShare::amortAdaptMULrecv(u64 idxPoint, u64 idxDim, u64 theirbsize)
	{
		std::vector<u8> recvBuff;// (theirbsize*mLenModinByte*mLenMod * 2);
		std::vector<Word> mi(theirbsize, 0); //sum OT m0 messages

		mChl.recv(recvBuff);
		if (recvBuff.size() != (mLenModinByte*theirbsize*mLenMod))
		{
			std::cout << "recvBuff.size() != (theirbsize*mLenModinByte + 15) / 16 *mLenMod * 2" <<
				recvBuff.size() << " vs " << (mLenModinByte*theirbsize*mLenMod) << "\n";
			throw std::exception();
		}

		//Word test;
		//memcpy(&test, recvBuff.data(), mLenModinByte);
		//std::cout << IoStream::lock;
		//std::cout << test << "  recvBuff.data() \n";
		//std::cout << IoStream::unlock;

		std::vector<Word*> maskRecvOT(mLenMod); //[l][k]
		for (u64 l = 0; l < mLenMod; l++)
		{
			maskRecvOT[l] = new Word[theirbsize];
			mRecvPRNG[idxPoint][idxDim][l].get<Word>(maskRecvOT[l], theirbsize);

			//std::cout << IoStream::lock;
			//std::cout << maskRecvOT[l][0]  << " PRNG r \n";
			//std::cout << maskRecvOT[l][theirbsize - 1] << " PRNG r \n";
			//std::cout << mRecvPRNG[idxPoint][idxDim][l].getSeed() << " PRNG  getSeed r \n";;
			//std::cout << IoStream::unlock;
		}


		u64 iter = 0;
		Word mask = 0;
		for (u64 k = 0; k <theirbsize; k++)
		{
			for (u64 l = 0; l < mLenMod; l++)
			{
				u8 choice = mSharePoint[idxPoint][idxDim].mBitShare[l];
				if (choice)
				{
					memcpy((u8 *)&mask, recvBuff.data() + iter, mLenModinByte);
					mask = (mask - maskRecvOT[l][k]) % mMod;
					mi[k] = (mi[k] + mask) % mMod;

					std::cout << IoStream::lock;
					std::cout << mask << " " << int(choice) << " mask r \n";
					std::cout << IoStream::unlock;

				}
				else
				{
					std::cout << IoStream::lock;
					std::cout << (maskRecvOT[l][k]) % mMod << " " << int(choice) << " mask r \n";
					std::cout << IoStream::unlock;
					mi[k] = (mi[k] + maskRecvOT[l][k]) % mMod;
				}

				iter +=  mLenModinByte;

			}
		}


		return mi;
	}

	std::vector<std::vector<Word>> DataShare::amortMULsend(std::vector<std::vector<Word>>& b)
	{

		std::vector<std::vector<Word>> prodShare(b.size());
		std::vector<u8> sendBuff(b.size()*mDimension*mLenMod*mLenModinByte);


		std::vector<std::array<block, 2>> sendOTmsgs(b.size()*mDimension*mLenMod);
		sender.send(sendOTmsgs, mPrng, mChl); //randome OT

		u64 idx = 0;
		for (u64 i = 0; i < b.size(); i++)
		{
			prodShare[i].resize(mDimension, 0);
			for (u64 d = 0; d < mDimension; d++)
			{
				for (u64 l = 0; l < mLenMod; l++)
				{
					Word r0 = *(u64*)&sendOTmsgs[idx][0] % mMod;
					Word r1 = *(u64*)&sendOTmsgs[idx][1] % mMod;
					Word correction = (Word)(b[i][d] * pow(2, l) + r0 - r1) % mMod; //


					std::cout << IoStream::lock;
					std::cout << i << "-" << d << ":  " << r0 << " vs " << r1 << " \t " << (Word)(b[i][d] * pow(2, l) + r0) % mMod << " c= " << correction << " s\n";
					std::cout << IoStream::unlock;

					//y=b+r0-r1, if choice=0, OTrecv=r0; choice=1, OTrecv=y+r_choice=y+r1=b+r0
					memcpy(sendBuff.data() + idx*mLenModinByte, (u8*)&correction, mLenModinByte);
					prodShare[i][d] = (prodShare[i][d] + r0) % mMod;
					idx++;
				}
				prodShare[i][d] = (0 - prodShare[i][d]) % mMod; //r0=-r0
			}
		}
		mChl.asyncSend(std::move(sendBuff));


		return prodShare;
	}

	std::vector<std::vector<Word>> DataShare::amortMULrecv(std::vector<std::vector<Word>>& a)
	{
		std::vector<u8> recvBuff;
		std::vector<std::vector<Word>> prodShare(a.size());

		BitVector allChoices;
		std::vector<block> recvOTmsg(a.size()*mDimension*mLenMod);

		std::vector<std::vector<BitVector>> aBitVectors(a.size());


		for (u64 i = 0; i < a.size(); i++)
		{
			aBitVectors[i].resize(mDimension);
			for (u64 d = 0; d < mDimension; d++)
			{
				aBitVectors[i][d] = getBinary(a[i][d], mLenMod);
				allChoices.append(aBitVectors[i][d]);
			}
		}
		recv.receive(allChoices, recvOTmsg, mPrng, mChl); //randome OT


		mChl.recv(recvBuff);
		if (recvBuff.size() != a.size()*mDimension*mLenMod*mLenModinByte)
		{
			std::cout << "recvBuff.size() != a.size()*mDimension*mLenMod*mLenModinByte" <<
				recvBuff.size() << " vs " << (a.size()*mDimension*mLenMod*mLenModinByte) << "\n";
			throw std::exception();
		}

		u64 idx = 0;
		Word correction = 0;

		for (u64 i = 0; i < a.size(); i++)
		{
			prodShare[i].resize(mDimension, 0);
			for (u64 d = 0; d < mDimension; d++)
			{
				for (u64 l = 0; l < mLenMod; l++)
				{
					Word rb = *(u64*)&recvOTmsg[idx] % mMod;

					if (aBitVectors[i][d][l] == 1)
					{
						//y=b+r0-r1, if choice=0, OTrecv=r0; choice=1, OTrecv=y+r_choice=y+r1=b+r0
						memcpy((u8*)&correction, recvBuff.data() + idx*mLenModinByte, mLenModinByte);
						rb = (correction + rb) % mMod;
					}
					prodShare[i][d] = (prodShare[i][d] + rb) % mMod;



					std::cout << IoStream::lock;
					std::cout << i << "-" << d << ":  " << rb << " vs " << aBitVectors[i][d][l] << " c= " << correction << " r\n";
					std::cout << IoStream::unlock;

					idx++;
				}
			}
		}

		return prodShare;
	}



	void DataShare::getInitClusters(u64 startIdx, u64 endIdx) {

		//std::cout << startIdx << "\n";
		//std::cout << endIdx << "\n";

		for (u64 i = startIdx; i < endIdx; i++)
		{
			for (u64 d = 0; d < mDimension; d++)
			{
				mCluster[i][d] = mSharedPrng.get<Word>() % mMod; //TODO:choose local cluster or using Locality sensitive hashing

				std::cout << IoStream::lock;
				std::cout << i << "-" << d << ":  " << mCluster[i][d] << " c\n";
				std::cout << IoStream::unlock;
			}
		}

	};

	void DataShare::init(u64 partyIdx, Channel & chl, block seed, u64 securityParam, u64 totalPoints
		, u64 numCluster, u64 idxStartCluster, u64 idxEndCluster
		, std::vector<std::vector<Word>>& data, u64 len, u64 dimension)
	{
		mPartyIdx = partyIdx;
		mChl = chl;
		mPrng.SetSeed(seed ^ toBlock(64823974291 * partyIdx));
		mSharedPrng.SetSeed(seed ^toBlock(64823391 * partyIdx));
		mPoint = data;
		mMod = 1 << len;
		mModSquare = mMod*mMod;
		mLenMod = len;
		mLenModinByte = (len + 7) / 8;

		mDimension = dimension;


		mTotalNumPoints = totalPoints;
		mTheirNumPoints = mTotalNumPoints - mPoint.size();

		mSharePoint.resize(mTotalNumPoints);
		mProdPointPPC.resize(mTotalNumPoints);
		mProdPointPC.resize(mTotalNumPoints);
		prodTempPC.resize(mTotalNumPoints);


		for (u64 i = 0; i < mSharePoint.size(); i++)
		{
			mSharePoint[i].resize(mDimension);
			mProdPointPPC[i].resize(mDimension);
			mProdPointPC[i].resize(mDimension);
			prodTempPC[i].resize(mDimension);

			for (u64 d = 0; d < mDimension; d++)
			{
				prodTempPC[i][d].resize(numCluster);
			}
		}

		prodTempC.resize(mDimension);
		for (u64 d = 0; d < mDimension; d++)
		{
			prodTempC[d].resize(numCluster);
		}

		mNumCluster = numCluster;
		mCluster.resize(mNumCluster);
		mShareCluster.resize(mNumCluster);
		mProdCluster.resize(mNumCluster);

		for (u64 i = 0; i < mShareCluster.size(); i++)
		{
			mCluster[i].resize(mDimension);
			mShareCluster[i].resize(mDimension);
			mProdCluster[i].resize(mDimension);

		}
		getInitClusters(idxStartCluster, idxEndCluster);


		mDist.resize(mTotalNumPoints);
		for (u64 i = 0; i < mTotalNumPoints; i++)
			mDist[i].resize(mNumCluster, 0);

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

		//======================min cluster

		mVecIdxMin.resize(mTotalNumPoints);
		mVecGcMinOutput.resize(mTotalNumPoints);
		//mShareBinArithMulSend.resize(mTotalNumPoints);
		//mShareBinArithMulRecv.resize(mTotalNumPoints);
		mShareBinArithMul.resize(mTotalNumPoints);
		mShareMin.resize(mTotalNumPoints);
		//mVecIdxMinSend.resize(mTotalNumPoints);
		//mVecIdxMinRecv.resize(mTotalNumPoints);

		mVecIdxMinTranspose.resize(mNumCluster);
		for (u64 i = 0; i < mNumCluster; i++)
			mVecIdxMinTranspose[i].resize(mTotalNumPoints);

		//GC
		rt.mDebugFlag = false;
		if (partyIdx)
			rt.init(mChl, mPrng.get<block>(), ShGcRuntime::Garbler, 0);
		else
			rt.init(mChl, mPrng.get<block>(), ShGcRuntime::Evaluator, 1);


		mRecvPRNG.resize(mTotalNumPoints);
		mSendPRNG.resize(mTotalNumPoints);
		for (u64 i = 0; i < mTotalNumPoints; i++)
		{
			mRecvPRNG[i].resize(mDimension);
			mSendPRNG[i].resize(mDimension);
			for (u64 d = 0; d < mDimension; d++)
			{
				mRecvPRNG[i][d].resize(mLenMod);
				mSendPRNG[i][d].resize(mLenMod);
			}
		}

	}





	void DataShare::sendShareInput(u64 startPointIdx, u64 startClusterIdx, u64 endClusterIdx)
	{
		std::vector<u8> sendBuff((mPoint.size() + endClusterIdx - startClusterIdx + 1)*mDimension*mLenModinByte);

		u64 iter = 0;

		//Data
		for (u64 i = startPointIdx; i < startPointIdx + mPoint.size(); i++)
		{
			for (u64 d = 0; d < mDimension; d++)
			{
				mSharePoint[i][d].mArithShare = mSharedPrng.get<Word>() % mMod; //randome share
				mSharePoint[i][d].mBitShare = mSharePoint[i][d].getBinary(mLenMod); //bit vector


				auto theirShare = (mPoint[i - startPointIdx][d] - mSharePoint[i][d].mArithShare) % mMod;
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
				mShareCluster[i][j] = mSharedPrng.get<Word>() % mMod; //randome share

				auto theirShare = (mCluster[i][j] - mShareCluster[i][j]) % mMod;
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
		u64 iter = 0;

		for (u64 i = startPointIdx; i < startPointIdx + mTheirNumPoints; i++)
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
				memcpy((u8*)&mShareCluster[i][j], recvBuff.data() + iter, mLenModinByte); //get their share
				iter += mLenModinByte;
			}
			//std::cout << i << "\n";
		}


	}

	void DataShare::appendAllChoice()
	{
		for (u64 i = 0; i < mTotalNumPoints; i++)
			for (u64 d = 0; d < mDimension; d++)
				mChoiceAllBitSharePoints.append(mSharePoint[i][d].mBitShare);
	};

	void DataShare::setPRNGseeds() {

		u64 iterSend = 0;
		u64 iterRecv = 0;
		for (u64 i = 0; i < mTotalNumPoints; i++)
		{
			for (u64 d = 0; d < mDimension; d++)
			{
				mSharePoint[i][d].sendOtKeys.resize(mLenMod);
				memcpy((u8*)&mSharePoint[i][d].sendOtKeys[0][0], (u8*)&mSendAllOtKeys[0] + iterSend, mLenMod * sizeof(block) * 2); //get their share
				iterSend += mLenMod * sizeof(block) * 2;


				//mSharePoint[i][d].sendAES.resize(mLenMod);
				//mSharePoint[i][d].mSendPRNG.resize(mLenMod);
				for (u64 l = 0; l < mLenMod; l++)
				{
					//mSharePoint[i][d].sendAES[l][0].setKey(mSharePoint[i][d].sendOtKeys[l][0]);
					//mSharePoint[i][d].sendAES[l][1].setKey(mSharePoint[i][d].sendOtKeys[l][1]);

					mSendPRNG[i][d][l][0].SetSeed(mSharePoint[i][d].sendOtKeys[l][0]);
					mSendPRNG[i][d][l][1].SetSeed(mSharePoint[i][d].sendOtKeys[l][1]);

					std::cout << IoStream::lock;
					std::cout << mSharePoint[i][d].sendOtKeys[l][0]
						<< " vs " << mSharePoint[i][d].sendOtKeys[l][1] << " \t s setPRNGseeds\n";
					std::cout << IoStream::unlock;

				}

				mSharePoint[i][d].recvOtKeys.resize(mLenMod);
				memcpy((u8*)&mSharePoint[i][d].recvOtKeys[0], (u8*)&mRecvAllOtKeys[0] + iterRecv, mLenMod * sizeof(block)); //get their share
				iterRecv += mLenMod * sizeof(block);

				//mSharePoint[i][d].recvAES.resize(mLenMod);
				for (u64 l = 0; l < mLenMod; l++)
				{
					//mSharePoint[i][d].recvAES[l].setKey(mSharePoint[i][d].recvOtKeys[l]);
					mRecvPRNG[i][d][l].SetSeed(mSharePoint[i][d].recvOtKeys[l]);

					std::cout << IoStream::lock;
					std::cout << mSharePoint[i][d].recvOtKeys[l] << " \t r setPRNGseeds\n";
					std::cout << IoStream::unlock;
				}

			}
		}

	}

	void DataShare::computeDist()
	{
		//(pa+pb-ca-cb)^2=(pa-ca)^2+(pb-cb)^2-2(pa-ca)(pb-cb)
		for (u64 i = 0; i < mTotalNumPoints; i++)
			for (u64 k = 0; k < mNumCluster; k++)
				for (u64 d = 0; d < mDimension; d++)
				{
					Word diff2 = (mSharePoint[i][d].mArithShare - mShareCluster[k][d]) % mMod;
					Word secondterm = (mProdPointPPC[i][d][k] - mProdPointPC[i][d][k] + mProdCluster[k][d]) % mMod;

					mDist[i][k] = (Word)(mDist[i][k] + pow(diff2, 2) + 2 * secondterm) % mMod;

				}

	}


	void DataShare::amortBinArithMulsend(std::vector<std::vector<Word>>& outShareSend, std::vector<BitVector>& bitVecs, std::vector<std::vector<Word>>& arithVecs)
	{
		outShareSend.resize(mTotalNumPoints);
		//OT concate all bitvector
		BitVector allBitVecs;
		for (size_t i = 0; i < mTotalNumPoints; i++)
			allBitVecs.append(bitVecs[i]);

		std::cout << IoStream::lock;
		std::cout << allBitVecs << "    allBitVecs A\n";
		std::cout << bitVecs[0] << " vs " << bitVecs[bitVecs.size() - 1] << "    bitGcMinOutVecs[] A\n";
		std::cout << IoStream::unlock;

		mMinClusterOtSends.resize(allBitVecs.size());
		sender.send(mMinClusterOtSends, mPrng, mChl); //random OT


		//OT sender m0 = r + b^A*P^A;  m1 = r + (1-b^A)*P^A 
		//Co-OT: deltaOT= (1-2*b^A)*P^A 
		//NOTE: sender output= r-b^AP^A


		std::vector<u8> sendBuff(allBitVecs.size()*mLenModinByte);
		u64 iter = 0;
		for (u64 i = 0; i < mTotalNumPoints; i++) //all points
		{
			outShareSend[i].resize(bitVecs[i].size());
			for (u64 k = 0; k < bitVecs[i].size(); k++)
			{
				Word r0 = *(u64*)&mMinClusterOtSends[i*bitVecs[i].size() + k][0] % mMod;
				Word r1 = *(u64*)&mMinClusterOtSends[i*bitVecs[i].size() + k][1] % mMod;
				Word correction = (Word)((1 - 2 * bitVecs[i][k])*arithVecs[i][k] + r0 - r1) % mMod; //

				outShareSend[i][k] = (bitVecs[i][k] * arithVecs[i][k] - r0) % mMod;
				std::cout << IoStream::lock;
				std::cout << i << "-" << k << ":  " << r0 << " vs " << r1
					<< " \t " << (Word)((1 - 2 * bitVecs[i][k])*arithVecs[i][k] + r0) % mMod
					<< " \t " << outShareSend[i][k]
					<< " c= " << correction << " s\n";
				std::cout << IoStream::unlock;

				//y=b+r0-r1, if choice=0, OTrecv=r0; choice=1, OTrecv=y+r_choice=y+r1=b+r0
				memcpy(sendBuff.data() + iter, (u8*)&correction, mLenModinByte);
				iter += mLenModinByte;
			}
		}
		mChl.asyncSend(std::move(sendBuff));

	}

	void DataShare::amortBinArithMULrecv(std::vector<std::vector<Word>>& outShareRecv, std::vector<BitVector>& bitVecs)
	{
		outShareRecv.resize(mTotalNumPoints);
		//OT concate all bitvector
		BitVector allBitVecs;
		for (size_t i = 0; i < mTotalNumPoints; i++)
			allBitVecs.append(bitVecs[i]);

		std::cout << IoStream::lock;
		std::cout << allBitVecs << "    allBitVecs B\n";
		std::cout << bitVecs[0] << " vs " << bitVecs[bitVecs.size() - 1] << "    bitGcMinOutVecs[] B\n";
		std::cout << IoStream::unlock;

		mMinClusterOtRecv.resize(allBitVecs.size());
		recv.receive(allBitVecs, mMinClusterOtRecv, mPrng, mChl);

		std::vector<u8> recvBuff;
		mChl.recv(recvBuff);
		if (recvBuff.size() != allBitVecs.size()*mLenModinByte)
		{
			std::cout << "recvBuff.size() != allBitVecs.size()*mLenModinByte" <<
				recvBuff.size() << " vs " << (allBitVecs.size()*mLenModinByte) << "\n";
			throw std::exception();
		}

		Word correction = 0;
		u64 iter = 0;

		for (u64 i = 0; i < mTotalNumPoints; i++) //all points
		{
			outShareRecv[i].resize(bitVecs[i].size());
			for (u64 k = 0; k < bitVecs[i].size(); k++)
			{
				outShareRecv[i][k] = *(u64*)&mMinClusterOtRecv[i*bitVecs[i].size() + k] % mMod;

				if (bitVecs[i][k] == 1)
				{
					//y=b+r0-r1, if choice=0, OTrecv=r0; choice=1, OTrecv=y+r_choice=y+r1=b+r0
					memcpy((u8*)&correction, recvBuff.data() + iter, mLenModinByte);
					outShareRecv[i][k] = (correction + outShareRecv[i][k]) % mMod;
				}

				std::cout << IoStream::lock;
				std::cout << i << "-" << k << ":  " << outShareRecv[i][k] << " vs " << bitVecs[i][k] << " c= " << correction << " r\n";
				std::cout << IoStream::unlock;

				iter += mLenModinByte;

			}
		}

	}

	void DataShare::amortBinArithMulGCsend(std::vector<std::vector<Word>>& outShareSend
		, std::vector<std::vector<BitVector>>& outIdxShareSend
		, std::vector<BitVector>& bitGcMinOutVecs, std::vector<std::vector<Word>>& arithVecs, std::vector<BitVector>& bitVecsIdxMin, u64 stepIdxMin)
	{
		outShareSend.resize(mTotalNumPoints);
		outIdxShareSend.resize(mTotalNumPoints);
		//OT concate all bitvector

		BitVector allBitVecs;
		for (size_t i = 0; i < mTotalNumPoints; i++)
			allBitVecs.append(bitGcMinOutVecs[i]);

		std::cout << IoStream::lock;
		std::cout << allBitVecs << "    allBitVecs A\n";
		std::cout << bitGcMinOutVecs[0] << " vs " << bitGcMinOutVecs[bitGcMinOutVecs.size() - 1] << "    bitGcMinOutVecs[] A\n";
		std::cout << IoStream::unlock;

		mMinClusterOtSends.resize(allBitVecs.size());
		sender.send(mMinClusterOtSends, mPrng, mChl); //random OT


		//OT sender m0 = r + b^A*P^A || r \xor b^A&V^A;  m1 = r + (1-b^A)*P^A || r \xor (1 \xor b^A)&V^A
		//Co-OT: deltaOT= (1-2*b^A)*P^A || V^A
		//NOTE: sender output= r-b^AP^A

		BitVector chunk(stepIdxMin);
		std::vector<u8> sendBuff(allBitVecs.size()*(mLenModinByte + chunk.sizeBytes()));
		u64 iter = 0;
		for (u64 i = 0; i < mTotalNumPoints; i++) //all points
		{
			outShareSend[i].resize(bitGcMinOutVecs[i].size());
			outIdxShareSend[i].resize(bitGcMinOutVecs[i].size());
			for (u64 k = 0; k < bitGcMinOutVecs[i].size(); k++)
			{
				u64 stepIdxMinCurrent = std::min(stepIdxMin, mNumCluster - k*stepIdxMin);

				/*std::cout << IoStream::lock;
				std::cout << i << "-" << bitGcMinOutVecs[i].size() << " stepIdxMin: " << l << " " << stepIdxMin << " vs " << stepIdxMinCurrent << " s\n";
				std::cout << IoStream::unlock;*/

				Word r0 = ((u64*)&mMinClusterOtSends[i*bitGcMinOutVecs[i].size() + k][0])[0] % mMod; //first 64 bit
				Word r1 = ((u64*)&mMinClusterOtSends[i*bitGcMinOutVecs[i].size() + k][1])[0] % mMod;
				Word correctionR = (Word)((1 - 2 * bitGcMinOutVecs[i][k])*arithVecs[i][k] + r0 - r1) % mMod; //
				outShareSend[i][k] = (bitGcMinOutVecs[i][k] * arithVecs[i][k] - r0) % mMod;

				BitVector v0 = getBinary(((u64*)&mMinClusterOtSends[i*bitGcMinOutVecs[i].size() + k][0])[1], stepIdxMinCurrent); //second 64 bit
				BitVector v1 = getBinary(((u64*)&mMinClusterOtSends[i*bitGcMinOutVecs[i].size() + k][1])[1], stepIdxMinCurrent); //second 64 bit
				chunk.copy(bitVecsIdxMin[i], k*stepIdxMin, stepIdxMinCurrent);

				outIdxShareSend[i][k] = v0;
				if (bitGcMinOutVecs[i][k])
					outIdxShareSend[i][k] = v0^chunk;

				/*	std::cout << IoStream::lock;
					std::cout << i << ": " << chunk << " vs " << bitVecsIdxMin[i] << " chunk \n";
					std::cout << IoStream::unlock;*/

				BitVector correctionV = v0^v1^chunk;
				BitVector msg0 = v0, msg1 = v0^chunk;

				if (bitGcMinOutVecs[i].size() == 2 && k == 1 && i == 1)
				{
					std::cout << IoStream::lock;
					/*std::cout << i << "-" << l << ":  " << r0 << " vs " << r1
						<< " \t " << (Word)((1 - 2 * bitGcMinOutVecs[i][l])*arithVecs[i][l] + r0) % mMod
						<< " \t " << mShareBinArithMulSend[i][l]
						<< " c= " << correctionR << " rs\n";*/

					std::cout << i << "-" << bitGcMinOutVecs[i].size() << " stepIdxMin: " << k << " " << stepIdxMin << " vs " << stepIdxMinCurrent << " s\n";
					std::cout << i << "-" << k << ":  " //<< v0 << " vs " << v1
						<< " \t " << msg0
						<< " \t " << msg1
						<< " c= " << correctionV << " s= " << outIdxShareSend[i][k]
						<< " b= " << int(bitGcMinOutVecs[i][k]) << " v= " << chunk
						<< " correctionV s\n";

					//std::cout << i << "-" << l << ":  " << bitGcMinOutVecs[i].size() << " bitGcMinOutVecs[i].size()\n";
					std::cout << IoStream::unlock;
				}

				//y=b+r0-r1, if choice=0, OTrecv=r0; choice=1, OTrecv=y+r_choice=y+r1=b+r0
				memcpy(sendBuff.data() + iter, (u8*)&correctionR, mLenModinByte);
				iter += mLenModinByte;
				memcpy(sendBuff.data() + iter, correctionV.data(), chunk.sizeBytes());

				u8* test = new u8(chunk.sizeBytes());

				auto bitTest = BitVector(sendBuff.data() + iter, stepIdxMinCurrent);

				memcpy(&test, sendBuff.data() + iter, chunk.sizeBytes());

				/*std::cout << IoStream::lock;
				std::cout << i << "-" << l << ":  "<< correctionV <<" vs " << bitTest<< " testV s\n";
				std::cout << IoStream::unlock;*/

				iter += chunk.sizeBytes();
			}
		}
		mChl.asyncSend(std::move(sendBuff));
	}

	void DataShare::amortBinArithMulGCrecv(std::vector<std::vector<Word>>& outShareRecv
		, std::vector<std::vector<BitVector>>& outIdxShareRecv
		, std::vector<BitVector>& bitGcMinOutVecs, u64 stepIdxMin)
	{
		outShareRecv.resize(mTotalNumPoints);
		outIdxShareRecv.resize(mTotalNumPoints);
		//OT concate all bitvector
		BitVector allBitVecs;
		for (size_t i = 0; i < mTotalNumPoints; i++)
			allBitVecs.append(bitGcMinOutVecs[i]);

		std::cout << IoStream::lock;
		std::cout << allBitVecs << "    allBitVecs B\n";
		std::cout << bitGcMinOutVecs[0] << " vs " << bitGcMinOutVecs[bitGcMinOutVecs.size() - 1] << "    bitGcMinOutVecs[] B\n";
		std::cout << IoStream::unlock;

		mMinClusterOtRecv.resize(allBitVecs.size());
		recv.receive(allBitVecs, mMinClusterOtRecv, mPrng, mChl);

		BitVector chunk(stepIdxMin);
		std::vector<u8> recvBuff;
		mChl.recv(recvBuff);
		if (recvBuff.size() != allBitVecs.size()*(mLenModinByte + chunk.sizeBytes()))
		{
			std::cout << "recvBuff.size() != allBitVecs.size()*mLenModinByte" <<
				recvBuff.size() << " vs " << (allBitVecs.size()*mLenModinByte) << "\n";
			throw std::exception();
		}

		Word correctionR = 0;
		BitVector correctionV;
		u8* corr = new u8(chunk.sizeBytes());
		u64 iter = 0;

		for (u64 i = 0; i < mTotalNumPoints; i++) //all points
		{
			outShareRecv[i].resize(bitGcMinOutVecs[i].size());
			outIdxShareRecv[i].resize(bitGcMinOutVecs[i].size());

			for (u64 k = 0; k < bitGcMinOutVecs[i].size(); k++)
			{

				u64 stepIdxMinCurrent = std::min(stepIdxMin, mNumCluster - k*stepIdxMin);

				/*std::cout << IoStream::lock;
				std::cout << i << "-" << bitGcMinOutVecs[i].size() << " stepIdxMin: " << l << " " <<stepIdxMin << " vs " << stepIdxMinCurrent << " r\n";
				std::cout << IoStream::unlock;*/

				outShareRecv[i][k] = *(u64*)&mMinClusterOtRecv[i*bitGcMinOutVecs[i].size() + k] % mMod;
				outIdxShareRecv[i][k] = getBinary(((u64*)&mMinClusterOtRecv[i*bitGcMinOutVecs[i].size() + k])[1], stepIdxMinCurrent); //second 64 bit

				if (bitGcMinOutVecs[i][k] == 1)
				{
					//y=b+r0-r1, if choice=0, OTrecv=r0; choice=1, OTrecv=y+r_choice=y+r1=b+r0
					memcpy((u8*)&correctionR, recvBuff.data() + iter, mLenModinByte);
					outShareRecv[i][k] = (correctionR + outShareRecv[i][k]) % mMod;
					iter += mLenModinByte;

					correctionV = BitVector(recvBuff.data() + iter, stepIdxMinCurrent);

					/*std::cout << IoStream::lock;
					std::cout << i << "-" << l << ":  " << correctionV <<  " testV r\n";
					std::cout << IoStream::unlock;*/

					iter += chunk.sizeBytes();
					outIdxShareRecv[i][k] = correctionV^outIdxShareRecv[i][k];
				}
				else
					iter += mLenModinByte + chunk.sizeBytes();

				if (bitGcMinOutVecs[i].size() == 2 && k == 1 && i == 1)
				{
					std::cout << IoStream::lock;
					std::cout << i << "-" << bitGcMinOutVecs[i].size() << " stepIdxMin: " << k << " " << stepIdxMin << " vs " << stepIdxMinCurrent << " r\n";
					//std::cout << i << "-" << l << ":  " << outShareRecv[i][l] << " vs " << bitGcMinOutVecs[i][l] << " c= " << correctionR << " r\n";
					std::cout << i << "-" << k << ":  s=" << outIdxShareRecv[i][k] << " b=" << bitGcMinOutVecs[i][k] << " c= " << correctionV << " cs " << chunk.sizeBytes() << " correctionV r\n";
					std::cout << IoStream::unlock;
				}

			}
		}
	}

	void DataShare::computeBinArithMUL(std::vector<std::vector<Word>>& outShareSend, std::vector<std::vector<Word>>& outShareRecv)
	{
		for (u64 i = 0; i < mTotalNumPoints; i++)
		{
			mShareBinArithMul[i].resize(outShareSend[i].size());
			for (u64 k = 0; k < outShareSend[i].size(); k++)
			{
				mShareBinArithMul[i][k] = (outShareSend[i][k] + outShareRecv[i][k]) % mMod;
			}
		}
	}

	void DataShare::computeShareMin(std::vector<std::vector<Word>>& outShareSend, std::vector<std::vector<Word>>& outShareRecv)
	{
		for (u64 i = 0; i < mTotalNumPoints; i++)
		{

			if (outShareSend[i].size() % 2 == 1)
			{
				std::cout << i << " computeShareMin error";
				throw std::exception();
			}
			mShareMin[i].resize(outShareSend[i].size() / 2);

			for (u64 k = 0; k < mShareMin[i].size(); k++)
			{
				mShareMin[i][k] = ((outShareSend[i][2 * k] + outShareRecv[i][2 * k]) % mMod //(b1^A \xor b1^B)*(P1^A+P1^B)
					+ (outShareSend[i][2 * k + 1] + outShareRecv[i][2 * k + 1]) % mMod) % mMod; //(b2^A \xor b2^B)*(P2^A+P2^B) 
			}
		}
	}

	void DataShare::computeShareIdxMin(std::vector<std::vector<BitVector>>& outShareSend, std::vector<std::vector<BitVector>>& outShareRecv)
	{
		for (u64 i = 0; i < mTotalNumPoints; i++)
		{

			if (outShareSend[i].size() % 2 == 1)
			{
				std::cout << i << " computeShareMin error";
				throw std::exception();
			}

			BitVector temp;
			for (u64 k = 0; k < outShareSend[i].size(); k++)
			{
				temp.append(outShareSend[i][k] ^ outShareRecv[i][k]);
			}
			std::cout << IoStream::lock;
			std::cout << i << ":  " << mNumCluster - temp.size() << " append size() r\n";
			std::cout << IoStream::unlock;

			temp.append(mVecIdxMin[i].data(), mNumCluster - temp.size(), temp.size());
			mVecIdxMin[i].assign(temp);

		}
	}

	void DataShare::vecMinTranspose()
	{
		//TODO: matrix transpose
		for (u64 k = 0; k < mNumCluster; k++)
		{
			for (u64 i = 0; i < mTotalNumPoints; i++)
			{
				mVecIdxMinTranspose[k][i] = mVecIdxMin[i][k];
			}
		}

#if 1
		std::cout << IoStream::lock;
		std::cout << "-------------\vecMinTranspose-------------\n";

		for (u64 i = 0; i < mTotalNumPoints; i++)
		{
			std::cout << mVecIdxMin[i] << "\n";
		}

		std::cout << "\n";
		for (u64 k = 0; k < mNumCluster; k++)
		{
			std::cout << mVecIdxMinTranspose[k] << "\n";
		}
		std::cout << "\n";
		std::cout << IoStream::unlock;
#endif
	}

	void DataShare::amortBinArithClustsend(std::vector<std::vector<Word>>& outNomSend, std::vector<Word>& outDenSend, std::vector<BitVector>& bitVecs)
	{
		outNomSend.resize(mNumCluster);
		outDenSend.resize(mNumCluster);
		//OT concate all bitvector
		BitVector allBitVecs; //[l][i]
		for (size_t i = 0; i < bitVecs.size(); i++)
			allBitVecs.append(bitVecs[i]);

		std::vector<std::array<block, 2>> OtMsgSends(allBitVecs.size());
		sender.send(OtMsgSends, mPrng, mChl); //random OT


		//OT sender m0 = r + b^A*P^A;  m1 = r + (1-b^A)*P^A 
		//Co-OT: deltaOT= (1-2*b^A)*P^A 
		//NOTE: sender output= r-b^AP^A
		std::vector<u8> sendBuff(allBitVecs.size()*(mLenModinByte*mDimension + 1)); //b*((P1 || P2 || ... || Pd) || 1)
		u64 iter = 0;
		for (u64 k = 0; k < mNumCluster; k++) //all points
		{
			outNomSend[k].resize(mDimension, 0);
			for (u64 i = 0; i < bitVecs[k].size(); i++)
			{
				std::vector<std::array<Word, 2>> r(mDimension);
				std::array<u8, 2> rQuo;

				if (mDimension*mLenModinByte + 1 > sizeof(block)) //need more than 128bit OT to do b*((P1 || P2 || ... || Pd) || 1
				{
					PRNG prg0(OtMsgSends[k*bitVecs[k].size() + i][0]);
					PRNG prg1(OtMsgSends[k*bitVecs[k].size() + i][1]);

					for (u64 d = 0; d < mDimension; d++)
					{
						r[d][0] = prg0.get<Word>() % mMod;
						r[d][1] = prg1.get<Word>() % mMod;
					}
					rQuo[0] = prg0.get<Word>() % 2; //to compute \sum b = \sum b*1
					rQuo[1] = prg0.get<Word>() % 2;
				}
				else
				{
					for (u64 d = 0; d < mDimension; d++)
					{

						r[d][0] = *(u64*)&(OtMsgSends[k*bitVecs[k].size() + i][0] >> d*mLenModinByte) % mMod;
						r[d][1] = *(u64*)&(OtMsgSends[k*bitVecs[k].size() + i][1] >> d*mLenModinByte) % mMod;
					}

					rQuo[0] = *(u64*)&(OtMsgSends[k*bitVecs[k].size() + i][0] >> mDimension*mLenModinByte) % 2; //to compute \sum b = \sum b*1
					rQuo[1] = *(u64*)&(OtMsgSends[k*bitVecs[k].size() + i][1] >> mDimension*mLenModinByte) % 2;

				}

				for (u64 d = 0; d < mDimension; d++)
				{
					Word correction = (Word)((1 - 2 * bitVecs[k][i])*mSharePoint[i][d].mArithShare + r[d][0] - r[d][1]) % mMod; //
					Word temp = (bitVecs[k][i] * mSharePoint[i][d].mArithShare - r[d][0]) % mMod;
					outNomSend[k][d] = (outNomSend[k][d] + temp) % mMod;


					std::cout << IoStream::lock;
					std::cout << k << "-" << i << "-" << d << ":  " << r[d][0] << " vs " << r[d][1]
						<< " \t " << (Word)((1 - 2 * bitVecs[k][i])*mSharePoint[i][d].mArithShare + r[d][0]) % mMod
						<< " \t " << temp
						<< " \t " << outNomSend[k][d]
						<< " c= " << correction << " s\n";
					std::cout << IoStream::unlock;

					//y=b+r0-r1, if choice=0, OTrecv=r0; choice=1, OTrecv=y+r_choice=y+r1=b+r0
					memcpy(sendBuff.data() + iter, (u8*)&correction, mLenModinByte);
					iter += mLenModinByte;
				}


				//for \sum b
				u8 correction = (u8)((1 - 2 * bitVecs[k][i]) + rQuo[0] - rQuo[1]) % 2; // 1=1 \xor 0. sender input 1
				u8 temp = (bitVecs[k][i] - rQuo[0]) % 2;
				outDenSend[k] = (outDenSend[k] ^ temp);

				

				//y=b+r0-r1, if choice=0, OTrecv=r0; choice=1, OTrecv=y+r_choice=y+r1=b+r0
				memcpy(sendBuff.data() + iter, (u8*)&correction, 1);
				iter += 1;

			}
		}
		mChl.asyncSend(std::move(sendBuff));
	}

	void DataShare::amortBinArithClustrecv(std::vector<std::vector<Word>>& outNomRecv, std::vector<Word>& outDenRecv, std::vector<BitVector>& bitVecs)
	{
		outNomRecv.resize(mNumCluster);
		outDenRecv.resize(mNumCluster);
		//OT concate all bitvector
		BitVector allBitVecs;
		for (size_t i = 0; i < bitVecs.size(); i++)
			allBitVecs.append(bitVecs[i]);

		std::vector<block> OtMsgRecv(allBitVecs.size());
		recv.receive(allBitVecs, OtMsgRecv, mPrng, mChl);

		std::vector<u8> recvBuff;
		mChl.recv(recvBuff);
		if (recvBuff.size() != allBitVecs.size()*(mLenModinByte*mDimension + 1))
		{
			std::cout << "recvBuff.size() != allBitVecs.size()*mLenModinByte" <<
				recvBuff.size() << " vs " << allBitVecs.size()*(mLenModinByte*mDimension + 1) << "\n";
			throw std::exception();
		}

		std::vector<Word> correction(mDimension,0);
		u64 iter = 0;

		for (u64 k = 0; k < mNumCluster; k++)
		{
			outNomRecv[k].resize(mDimension, 0);
			for (u64 i = 0; i < bitVecs[k].size(); i++) //all points
			{
					std::vector<Word> r(mDimension);
					u8 rQuo(mDimension);

					if (mDimension*mLenModinByte + 1 > sizeof(block)) //need more than 128bit OT to do b*((P1 || P2 || ... || Pd) || 1
					{
						PRNG prgb(OtMsgRecv[k*bitVecs[k].size() + i]);

						for (u64 d = 0; d < mDimension; d++)
							r[d] = prgb.get<Word>() % mMod;
						
						rQuo = prgb.get<Word>() % 2; //to compute \sum b = \sum b*1
					}
					else
					{
						for (u64 d = 0; d < mDimension; d++)
							r[d] = *(u64*)&(OtMsgRecv[k*bitVecs[k].size() + i] >> d*mLenModinByte) % mMod;

						rQuo = *(u64*)&(OtMsgRecv[k*bitVecs[k].size() + i] >> mDimension*mLenModinByte) % 2; //to compute \sum b = \sum b*1

					}



				if (bitVecs[k][i] == 1)
				{

					//y=b+r0-r1, if choice=0, OTrecv=r0; choice=1, OTrecv=y+r_choice=y+r1=b+r0

					for (u64 d = 0; d < mDimension; d++)
					{
						memcpy((u8*)&correction[d], recvBuff.data() + iter, mLenModinByte);
						r[d] = (correction[d] + r[d]) % mMod;
						iter += mLenModinByte;
					}

					u8 correctbit;

					memcpy((u8*)&correctbit, recvBuff.data() + iter, 1);
					rQuo = (correctbit^ rQuo);
					iter += 1;

				}
				else
				{ 
					iter += mDimension*mLenModinByte+1;
				}

				for (u64 d = 0; d < mDimension; d++)
				{
					outNomRecv[k][d] = (outNomRecv[k][d] + r[d]) % mMod;
					outDenRecv[k]= (outDenRecv[k]^ rQuo) ;

				}

				std::cout << IoStream::lock;
				for (u64 d = 0; d < mDimension; d++)
					std::cout << i << "-" << k << ":  " << r[d] << " vs " << bitVecs[k][i] << " c= " << correction[d] << " r\n";
				std::cout << IoStream::unlock;


			}
		}
	}

	void DataShare::Print() {

		std::cout << IoStream::lock;
		std::cout << "===========Party " << mPartyIdx << " ==============\n";
		std::cout << "d=" << mDimension << "\t mod=" << mMod << "\t mPoint[0][0]=" << mPoint[0][0] << "\n";
		std::cout << "OT base 1: send[0][0]=" << mSendBaseMsg[0][0] << "\t send[0][1]=" << mSendBaseMsg[0][1] << "\n";
		std::cout << "OT base 2: choice[0]=" << mBaseChoices[0] << "\t recv[0]=" << mRecvBaseMsg[0] << "\n";

		if (mPartyIdx == 0)
		{
			std::cout << "Share1: mSharePoint[0][0].mArithShare=" << mSharePoint[0][0].mArithShare << " vs " << mSharePoint[0][0].mBitShare << "\n";
			std::cout << "Share2: mSharePoint[n][0].mArithShare=" << mSharePoint[mPoint.size()][0].mArithShare << " vs " << mSharePoint[mPoint.size()][0].mBitShare << "\n";
			//std::cout << "mTheirSharePointCheck=" << mTheirSharePointCheck << "\n";

		}
		else
		{
			std::cout << "Share1: mSharePoint[0][0].mArithShare=" << mSharePoint[0][0].mArithShare << " vs " << mSharePoint[0][0].mBitShare << "\n";
			std::cout << "Share2: mSharePoint[n][0].mArithShare=" << mSharePoint[mTheirNumPoints][0].mArithShare << " vs " << mSharePoint[mTheirNumPoints][0].mBitShare << "\n";
			//std::cout << "mTheirSharePointCheck=" << mTheirSharePointCheck << "\n";

		}

		std::cout << "-------------\nOT allkey base 1: send[0][0]=" << mSendAllOtKeys[0][0] << "\t send[0][1]=" << mSendAllOtKeys[0][1] << "\n";
		std::cout << "OT allkey base 2: choice[0]=" << mChoiceAllBitSharePoints[0] << "\t recv[0]=" << mRecvAllOtKeys[0] << "\n";



		std::cout << "-------------\nOT key base 1: send[0][0]=" << mSharePoint[0][0].sendOtKeys[0][0] << "\t send[0][1]=" << mSharePoint[0][0].sendOtKeys[0][1] << "\n";
		std::cout << "OT key base 2: choice[0]=" << mSharePoint[0][0].mBitShare[0] << "\t recv[0]=" << mSharePoint[0][0].recvOtKeys[0] << "\n";


		std::cout << IoStream::unlock;

	}

	void DataShare::getPointPerDimension()
	{
		for (u64 d = 0; d < mDimension; d++)
		{
			for (u64 i = 0; i < mTotalNumPoints; i++)
				memcpy((u8*)&mSharePointsPerDim[d][i], (u8*)&mSharePoint[i][d].mArithShare, sizeof(Word));

		}
	}





}