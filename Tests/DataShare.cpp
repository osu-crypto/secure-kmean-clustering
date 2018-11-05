#include "DataShare.h"


namespace osuCrypto
{

	DataShare::DataShare()
	{
	}


	DataShare::~DataShare()
	{
	}



	std::vector<iWord> DataShare::amortAdaptMULsend(u64 theirIdxPoint, u64 theirIdxDim, std::vector<iWord>& b) //b=di-ci
	{

		std::cout << b.size() << " b.size()\n";
		std::vector<u8> sendBuff(sizeof(Word)*b.size()*mLenMod);
		std::vector<iWord> m0(b.size(), 0); //sum OT m0 messages
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
				m0[k] = (m0[k] + maskSendOT[l][0][k] % mMod) ; //r0= maskSendOT[l][0][k]

				std::cout << IoStream::lock;
				Word r0 = maskSendOT[l][0][k] % mMod; //OT message
				auto delta = (Word)(b[k] * pow(2, l));
				std::cout << k << "-" << l << ":  " << r0 << " vs " << (r0 + delta) << " r1\n";
				std::cout << IoStream::unlock;

				//mask
				Word mask = (maskSendOT[l][0][k] % mMod + maskSendOT[l][1][k] % mMod + (Word)(b[k] * pow(2, l)));
				memcpy(sendBuff.data() + iter, (u8*)&mask, sizeof(Word));
				iter += mLenModinByte;
			}
		}


#if 0
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
#endif
	

		mChl.asyncSend(std::move(sendBuff));


		for (u64 k = 0; k < b.size(); k++)
		{
			m0[k] = (0 - m0[k]);
		}
		return m0;
	}

	std::vector<iWord> DataShare::amortAdaptMULrecv(u64 idxPoint, u64 idxDim, u64 theirbsize)
	{
		std::vector<u8> recvBuff;// (theirbsize*mLenModinByte*mLenMod * 2);
		std::vector<iWord> mi(theirbsize, 0); //sum OT m0 messages

		mChl.recv(recvBuff);
		if (recvBuff.size() != (mLenMod*theirbsize*sizeof(Word)))
		{
			std::cout << "recvBuff.size() != (theirbsize*mLenModinByte + 15) / 16 *mLenMod * 2" <<
				recvBuff.size() << " vs " << (sizeof(Word)*theirbsize*mLenMod) << "\n";
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
					memcpy((u8 *)&mask, recvBuff.data() + iter, sizeof(Word));
					mask = (mask - maskRecvOT[l][k] % mMod) ;
					mi[k] = (mi[k] + mask);

					std::cout << IoStream::lock;
					std::cout << mask << " " << int(choice) << " mask r \n";
					std::cout << IoStream::unlock;

				}
				else
				{
					std::cout << IoStream::lock;
					std::cout << (maskRecvOT[l][k]) % mMod << " " << int(choice) << " mask r \n";
					std::cout << IoStream::unlock;
					mi[k] = (mi[k] + maskRecvOT[l][k] % mMod);
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
		stepIdxMin = 1;

		mTotalNumPoints = totalPoints;
		mTheirNumPoints = mTotalNumPoints - mPoint.size();

		mSharePoint.resize(mTotalNumPoints);
		mProdPointPPC.resize(mTotalNumPoints);
		mProdPointPC.resize(mTotalNumPoints);
		prodTempPC.resize(mTotalNumPoints);
		lastNode.resize(mTotalNumPoints);

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

		mShareNomCluster.resize(mNumCluster);
		mShareDecCluster.resize(mNumCluster);


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
				mSharePoint[i][d].mArithShare = mSharedPrng.get<Word>() % mPoint[i - startPointIdx][d];//test... mMod; //randome share 
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
				mShareCluster[i][j] = mSharedPrng.get<Word>() % mCluster[i][j];//mMod; //randome share

				auto theirShare = (mCluster[i][j] - mShareCluster[i][j])  % mMod;
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
			{
				mDist[i][k] = 0;
				for (u64 d = 0; d < mDimension; d++)
				{
					iWord diff2 = signExtend((mSharePoint[i][d].mArithShare - mShareCluster[k][d]), mLenMod);
					//iWord secondterm = (mProdPointPPC[i][d][k] - mProdPointPC[i][d][k] + mProdCluster[k][d]);
					//Word d2 = pow(diff2, 2);
					iWord secondterm = signExtend(mProdPointPPC[i][d][k] - mProdPointPC[i][d][k] + mProdCluster[k][d], mLenMod);
					mDist[i][k] = signExtend((mDist[i][k] + (Word)pow(diff2, 2) + 2 * secondterm),mLenMod);

				}
			}
	}


	void DataShare::amortBinArithMulsend(std::vector<std::vector<iWord>>& outShareSend, std::vector<BitVector>& bitVecs, std::vector<std::vector<iWord>>& arithVecs)
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


		std::vector<u8> sendBuff(allBitVecs.size()* sizeof(iWord));
		u64 iter = 0;
		for (u64 i = 0; i < mTotalNumPoints; i++) //all points
		{
			outShareSend[i].resize(bitVecs[i].size());
			for (u64 k = 0; k < bitVecs[i].size(); k++)
			{
				iWord r0 = *(i64*)&mMinClusterOtSends[i*bitVecs[i].size() + k][0] % mMod;
				iWord r1 = *(i64*)&mMinClusterOtSends[i*bitVecs[i].size() + k][1] % mMod;
				iWord correction = ((1 - 2 * bitVecs[i][k])*arithVecs[i][k] + r0 - r1); //

				outShareSend[i][k] = signExtend(bitVecs[i][k] * arithVecs[i][k] - r0,mLenMod) ;
				std::cout << IoStream::lock;
				std::cout << i << "-" << k << ":  " << r0 << " vs " << r1
					<< " \t " << signExtend(((1 - 2 * bitVecs[i][k])*arithVecs[i][k] + r0), mLenMod)
					<< " \t " << outShareSend[i][k]
					<< " c= " << correction << " s\n";
				std::cout << IoStream::unlock;

				//y=b+r0-r1, if choice=0, OTrecv=r0; choice=1, OTrecv=y+r_choice=y+r1=b+r0
				memcpy(sendBuff.data() + iter, (i8*)&correction, sizeof(iWord));
				iter += sizeof(iWord);
			}
		}
		mChl.asyncSend(std::move(sendBuff));

	}

	void DataShare::amortBinArithMULrecv(std::vector<std::vector<iWord>>& outShareRecv, std::vector<BitVector>& bitVecs)
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
		if (recvBuff.size() != allBitVecs.size()* sizeof(iWord))
		{
			std::cout << "recvBuff.size() != allBitVecs.size()*mLenModinByte" <<
				recvBuff.size() << " vs " << (allBitVecs.size()* sizeof(iWord)) << "\n";
			throw std::exception();
		}

		iWord correction = 0;
		u64 iter = 0;

		for (u64 i = 0; i < mTotalNumPoints; i++) //all points
		{
			outShareRecv[i].resize(bitVecs[i].size());
			for (u64 k = 0; k < bitVecs[i].size(); k++)
			{
				outShareRecv[i][k] = *(i64*)&mMinClusterOtRecv[i*bitVecs[i].size() + k] % mMod;

				if (bitVecs[i][k] == 1)
				{
					//y=b+r0-r1, if choice=0, OTrecv=r0; choice=1, OTrecv=y+r_choice=y+r1=b+r0
					memcpy((i8*)&correction, recvBuff.data() + iter, sizeof(iWord));
					outShareRecv[i][k] = signExtend((correction + outShareRecv[i][k]), mLenMod);
				}

				std::cout << IoStream::lock;
				std::cout << i << "-" << k << ":  " << outShareRecv[i][k] << " vs " << bitVecs[i][k] << " c= " << correction << " r\n";
				std::cout << IoStream::unlock;

				iter += sizeof(iWord);

			}
		}

	}

	void DataShare::amortBinArithMulGCsend(std::vector<std::vector<iWord>>& outShareSend
		, std::vector<std::vector<BitVector>>& outIdxShareSend
		, std::vector<BitVector>& bitGcMinOutVecs, std::vector<std::vector<iWord>>& arithVecs, std::vector<BitVector>& bitVecsIdxMin, u64 stepIdxMin)
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
		std::vector<u8> sendBuff(allBitVecs.size()*(sizeof(iWord) + chunk.sizeBytes()));
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

				iWord r0 = ((i64*)&mMinClusterOtSends[i*bitGcMinOutVecs[i].size() + k][0])[0] % mMod; //first 64 bit
				iWord r1 = ((i64*)&mMinClusterOtSends[i*bitGcMinOutVecs[i].size() + k][1])[0] % mMod;
				iWord correctionR =((1 - 2 * bitGcMinOutVecs[i][k])*arithVecs[i][k] + r0 - r1) ; //
				outShareSend[i][k] = signExtend(bitGcMinOutVecs[i][k] * arithVecs[i][k] - r0, mLenMod);

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

				//if (bitGcMinOutVecs[i].size() == 2 && k == 1 && i == 1)
				{
					std::cout << IoStream::lock;
					iWord their1OTrcv = signExtend(((1 - 2 * bitGcMinOutVecs[i][k])*arithVecs[i][k] + r0), mLenMod);

					std::cout << i << "-" << k << ":  " << r0 << " vs " << r1
						<< " \t " << their1OTrcv //OT r1
						<< " \t " << signExtend(correctionR + r1, mLenMod) //OT r1
						<< " \t " << outShareSend[i][k]
						<< " c= " << correctionR << " d=" << arithVecs[i][k]<< " s\n";



					//std::cout << i << "-" << bitGcMinOutVecs[i].size() << " stepIdxMin: " << k << " " << stepIdxMin << " vs " << stepIdxMinCurrent << " s\n";
					//std::cout << i << "-" << k << ":  " //<< v0 << " vs " << v1
					//	<< " \t " << msg0
					//	<< " \t " << msg1
					//	<< " c= " << correctionV << " s= " << outIdxShareSend[i][k]
					//	<< " b= " << int(bitGcMinOutVecs[i][k]) << " v= " << chunk
					//	<< " correctionV s\n";

					//std::cout << i << "-" << l << ":  " << bitGcMinOutVecs[i].size() << " bitGcMinOutVecs[i].size()\n";
					std::cout << IoStream::unlock;
				}

				//y=b+r0-r1, if choice=0, OTrecv=r0; choice=1, OTrecv=y+r_choice=y+r1=b+r0
				memcpy(sendBuff.data() + iter, (i8*)&correctionR, sizeof(iWord));
				iter += sizeof(iWord);
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

	void DataShare::amortBinArithMulGCrecv(std::vector<std::vector<iWord>>& outShareRecv
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
		if (recvBuff.size() != allBitVecs.size()*(sizeof(iWord) + chunk.sizeBytes()))
		{
			std::cout << "recvBuff.size() != allBitVecs.size()*mLenModinByte" <<
				recvBuff.size() << " vs " << (allBitVecs.size()*mLenModinByte) << "\n";
			throw std::exception();
		}

		iWord correctionR = 0;
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

				outShareRecv[i][k] = *(i64*)&mMinClusterOtRecv[i*bitGcMinOutVecs[i].size() + k] % mMod;
				outIdxShareRecv[i][k] = getBinary(((u64*)&mMinClusterOtRecv[i*bitGcMinOutVecs[i].size() + k])[1], stepIdxMinCurrent); //second 64 bit

				if (bitGcMinOutVecs[i][k] == 1)
				{
					//y=b+r0-r1, if choice=0, OTrecv=r0; choice=1, OTrecv=y+r_choice=y+r1=b+r0

					iWord test = outShareRecv[i][k];
					memcpy((i8*)&correctionR, recvBuff.data() + iter, sizeof(iWord));
					outShareRecv[i][k] = signExtend(correctionR + outShareRecv[i][k], mLenMod) ;
					iter += sizeof(iWord);

					correctionV = BitVector(recvBuff.data() + iter, stepIdxMinCurrent);

					/*std::cout << IoStream::lock;
					std::cout << i << "-" << l << ":  " << correctionV <<  " testV r\n";
					std::cout << IoStream::unlock;*/

					iter += chunk.sizeBytes();
					outIdxShareRecv[i][k] = correctionV^outIdxShareRecv[i][k];

					std::cout << IoStream::lock;
					//std::cout << i << "-" << bitGcMinOutVecs[i].size() << " stepIdxMin: " << k << " " << stepIdxMin << " vs " << stepIdxMinCurrent << " r\n";
					std::cout << i << "-" << k << ":  " << test<<" "<< outShareRecv[i][k] << " vs " << bitGcMinOutVecs[i][k] << " c= " << correctionR << " r\n";
					//std::cout << i << "-" << k << ":  s=" << outIdxShareRecv[i][k] << " b=" << bitGcMinOutVecs[i][k] << " c= " << correctionV << " cs " << chunk.sizeBytes() << " correctionV r\n";
					std::cout << IoStream::unlock;

				}
				else
				{	iter += sizeof(iWord) + chunk.sizeBytes();

				//if (bitGcMinOutVecs[i].size() == 2 && k == 1 && i == 1)
				
					std::cout << IoStream::lock;
					//std::cout << i << "-" << bitGcMinOutVecs[i].size() << " stepIdxMin: " << k << " " << stepIdxMin << " vs " << stepIdxMinCurrent << " r\n";
					std::cout << i << "-" << k << ":  " << outShareRecv[i][k] << " vs " << bitGcMinOutVecs[i][k] << " c= " << correctionR << " r\n";
					//std::cout << i << "-" << k << ":  s=" << outIdxShareRecv[i][k] << " b=" << bitGcMinOutVecs[i][k] << " c= " << correctionV << " cs " << chunk.sizeBytes() << " correctionV r\n";
					std::cout << IoStream::unlock;
				}

			}
		}
	}

	void DataShare::computeBinArithMUL(std::vector<std::vector<iWord>>& outShareSend, std::vector<std::vector<iWord>>& outShareRecv)
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

	void DataShare::computeShareMin(std::vector<std::vector<iWord>>& outShareSend, std::vector<std::vector<iWord>>& outShareRecv)
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
				mShareMin[i][k] = signExtend(signExtend((outShareSend[i][2 * k] + outShareRecv[i][2 * k]), mLenMod) //(b1^A \xor b1^B)*(P1^A+P1^B)
					+ signExtend((outShareSend[i][2 * k + 1] + outShareRecv[i][2 * k + 1]), mLenMod), mLenMod); //(b2^A \xor b2^B)*(P2^A+P2^B) 
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
		std::cout << "-------------vecMinTranspose-------------\n";

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

	void DataShare::amortBinArithClustsend(std::vector<BitVector>& bitVecs, std::vector<std::vector<iWord>>& outNomSend, std::vector<iWord>& outDenSend, bool isDen)
	{
		outNomSend.resize(mNumCluster);
		outDenSend.resize(mNumCluster,0);
		//OT concate all bitvector
		BitVector allBitVecs; //[l][i]
		for (size_t i = 0; i < bitVecs.size(); i++)
			allBitVecs.append(bitVecs[i]);

		std::vector<std::array<block, 2>> OtMsgSends(allBitVecs.size());
		sender.send(OtMsgSends, mPrng, mChl); //random OT


		//OT sender m0 = r + b^A*P^A;  m1 = r + (1-b^A)*P^A 
		//Co-OT: deltaOT= (1-2*b^A)*P^A 
		//NOTE: sender output= r-b^AP^A

		std::vector<u8> sendBuff(allBitVecs.size()*(sizeof(iWord)*mDimension + isDen * sizeof(i8))); //b*((P1 || P2 || ... || Pd) || 1)
		
		u64 iter = 0;
		for (u64 k = 0; k < mNumCluster; k++) //all points
		{
			outNomSend[k].resize(mDimension, 0);
			for (u64 i = 0; i < bitVecs[k].size(); i++)
			{
				std::vector<std::array<iWord, 2>> r(mDimension);
				std::array<u8, 2> rQuo;

				if (mDimension*mLenModinByte + 1 > sizeof(block)) //need more than 128bit OT to do b*((P1 || P2 || ... || Pd) || 1
				{
					PRNG prg0(OtMsgSends[k*bitVecs[k].size() + i][0]);
					PRNG prg1(OtMsgSends[k*bitVecs[k].size() + i][1]);

					for (u64 d = 0; d < mDimension; d++)
					{
						r[d][0] = signExtend(prg0.get<iWord>(),mLenMod);
						r[d][1] = signExtend(prg1.get<Word>(), mLenMod);
					}
					if (isDen)
					{
						rQuo[0] = prg0.get<Word>() % 2; //to compute \sum b = \sum b*1
						rQuo[1] = prg1.get<Word>() % 2;
					}
				}
				else
				{
					for (u64 d = 0; d < mDimension; d++)
					{

						r[d][0] = *(i64*)&(OtMsgSends[k*bitVecs[k].size() + i][0] >> d*mLenModinByte) % mMod;
						r[d][1] = *(i64*)&(OtMsgSends[k*bitVecs[k].size() + i][1] >> d*mLenModinByte) % mMod;
					}

					if (isDen)
					{
						rQuo[0] = *(i64*)&(OtMsgSends[k*bitVecs[k].size() + i][0] >> mDimension*mLenModinByte) % 2; //to compute \sum b = \sum b*1
						rQuo[1] = *(i64*)&(OtMsgSends[k*bitVecs[k].size() + i][1] >> mDimension*mLenModinByte) % 2;
					}
				}

				for (u64 d = 0; d < mDimension; d++)
				{
					iWord correction = ((1 - 2 * bitVecs[k][i])*mSharePoint[i][d].mArithShare + r[d][0] - r[d][1]) ; //
					iWord temp = signExtend((bitVecs[k][i] * mSharePoint[i][d].mArithShare - r[d][0]), mLenMod);
					outNomSend[k][d] = signExtend((outNomSend[k][d] + temp), mLenMod);

					iWord their= signExtend(((1 - 2 * bitVecs[k][i])*mSharePoint[i][d].mArithShare + r[d][0]), mLenMod);
					std::cout << IoStream::lock;
					std::cout << k << "-" << i << "-" << d << ":  " << r[d][0] << " vs " << r[d][1]
						<< " \t " << their
						<< " \t " << temp
						<< " \t " << outNomSend[k][d]
						<< " c= " << correction << " s\n";
					std::cout << IoStream::unlock;

					//y=b+r0-r1, if choice=0, OTrecv=r0; choice=1, OTrecv=y+r_choice=y+r1=b+r0
					memcpy(sendBuff.data() + iter, (i8*)&correction, sizeof(iWord));
					iter += sizeof(iWord);
				}


				if (isDen)
				{
					//delta OT with r0, r0+(b^A \xor 1) - (b^A \xor 0) => delt=(b^A \xor 1) - (b^A \xor 0)+r0-r1
					//Receiver get r0 or (delta+r1)= r0+(b^A+b^B) - (b^A \xor 0)  <-- share
					//Sender set (b^A \xor 0) - r0 as share

					i8 correction = (1 + rQuo[0] - rQuo[1]); // 1=1 \xor 0. sender input 1
					if (bitVecs[k][i])
						correction = (-1 + rQuo[0] - rQuo[1]); // 1=1 \xor 0. sender input 1

					i8 myshare = bitVecs[k][i] - rQuo[0];
					outDenSend[k] = outDenSend[k] + myshare;

					std::cout << IoStream::lock;
					std::cout << k << "-" << i << " bitshare s:  " << int(rQuo[0]) << " vs " << int(rQuo[1])
						<< " \t " << int(correction + rQuo[1])
						<< " \t " << int(myshare)
						<< " c= " << int(correction) << " bitshare s\n";
					std::cout << IoStream::unlock;

					//y=b+r0-r1, if choice=0, OTrecv=r0; choice=1, OTrecv=y+r_choice=y+r1=b+r0
					memcpy(sendBuff.data() + iter, (i8*)&correction, sizeof(i8));
					iter += sizeof(i8);
				}

			}
		}
		mChl.asyncSend(std::move(sendBuff));
	}

	void DataShare::amortBinArithClustrecv(std::vector<BitVector>& bitVecs, std::vector<std::vector<iWord>>& outNomRecv, std::vector<iWord>& outDenRecv, bool isDen)
	{
		outNomRecv.resize(mNumCluster);
		outDenRecv.resize(mNumCluster,0);
		//OT concate all bitvector
		BitVector allBitVecs;
		for (size_t i = 0; i < bitVecs.size(); i++)
			allBitVecs.append(bitVecs[i]);

		std::vector<block> OtMsgRecv(allBitVecs.size());
		recv.receive(allBitVecs, OtMsgRecv, mPrng, mChl);

		std::vector<u8> recvBuff;
		mChl.recv(recvBuff);
		if (recvBuff.size() != allBitVecs.size()*(sizeof(iWord)*mDimension + isDen*sizeof(i8)))
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
					std::vector<iWord> r(mDimension);
					i8 rQuo=0;

					if (mDimension*mLenModinByte + 1 > sizeof(block)) //need more than 128bit OT to do b*((P1 || P2 || ... || Pd) || 1
					{
						PRNG prgb(OtMsgRecv[k*bitVecs[k].size() + i]);

						for (u64 d = 0; d < mDimension; d++)
							r[d] = signExtend(prgb.get<Word>(),mLenMod) ;
						
						if (isDen)
							rQuo = prgb.get<Word>() % 2; //to compute \sum b = \sum b*1
					}
					else
					{
						for (u64 d = 0; d < mDimension; d++)
							r[d] = *(i64*)&(OtMsgRecv[k*bitVecs[k].size() + i] >> d*mLenModinByte) % mMod;

						if (isDen)
							rQuo = *(u64*)&(OtMsgRecv[k*bitVecs[k].size() + i] >> mDimension*mLenModinByte) % 2; //to compute \sum b = \sum b*1

					}


				i8 correctbit=0;
				if (bitVecs[k][i] == 1)
				{

					//y=b+r0-r1, if choice=0, OTrecv=r0; choice=1, OTrecv=y+r_choice=y+r1=b+r0

					for (u64 d = 0; d < mDimension; d++)
					{
						memcpy((i8*)&correction[d], recvBuff.data() + iter, sizeof(iWord));
						r[d] = signExtend((correction[d] + r[d]), mLenMod);
						iter += sizeof(iWord);
					}

					
					if (isDen) {
						//delta OT with r0, r0+(b^A \xor 1) - (b^A \xor 0) => delt=(b^A \xor 1) - (b^A \xor 0)+r0-r1
						//Receiver get r0 or (delta+r1)= r0+(b^A+b^B) - (b^A \xor 0)  <-- share
						//Sender set (b^A \xor 0) - r0 as share
						memcpy((i8*)&correctbit, recvBuff.data() + iter, sizeof(i8));
						rQuo = correctbit + rQuo;
						iter += sizeof(i8);
					}
				}
				else
				{ 
					iter += mDimension* sizeof(iWord) + isDen*sizeof(i8);
				}

				for (u64 d = 0; d < mDimension; d++)
					outNomRecv[k][d] = signExtend((outNomRecv[k][d] + r[d]), mLenMod);;

				if (isDen)
				outDenRecv[k] = outDenRecv[k] + rQuo;

				std::cout << IoStream::lock;
				for (u64 d = 0; d < mDimension; d++)
					std::cout << i << "-" << k << ":  " << r[d] << " vs " << bitVecs[k][i] << " c= " << correction[d] << " r\n";
			
				if (isDen)
					std::cout << k << "-" << i << " bitshare r:  " << int(rQuo) << " vs " << bitVecs[k][i] << " c= " << int(correctbit) << " bitshare r \n";
				
				std::cout << IoStream::unlock;


			}
		}
	}

	void DataShare::computeShareCluster(std::vector<std::vector<iWord>>& shareNomSend, std::vector<std::vector<iWord>>& shareNomRecv, std::vector<iWord>&shareDenSend, std::vector<iWord>&shareDenSRecv)
	{
		for (u64 k = 0; k < mNumCluster; k++)
		{
			mShareNomCluster[k].resize(mDimension, 0);
			for (u64 d = 0; d < mDimension; d++)
			{
				mShareNomCluster[k][d] = signExtend(mShareNomCluster[k][d] + shareNomSend[k][d] + shareNomRecv[k][d], mLenMod);
			}
			mShareDecCluster[k]= signExtend( shareDenSend[k]+ shareDenSRecv[k], mLenMod);
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