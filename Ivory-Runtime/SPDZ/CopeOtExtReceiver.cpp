#include "CopeOtExtReceiver.h"
#include "libOTe/Tools/Tools.h"
#include "cryptoTools/Common/Log.h"

#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Crypto/Commit.h"
#include "CopeOtExtDefines.h"

using namespace std;

namespace osuCrypto
{
    void CopeOtExtReceiver::setBaseOts(span<std::array<block, 2>> baseOTs)
    {
        if (baseOTs.size() != gOtExtBaseOtCount)
            throw std::runtime_error(LOCATION);

        for (u64 i = 0; i < gOtExtBaseOtCount; i++)
        {
            mGens[i][0].SetSeed(baseOTs[i][0]);
            mGens[i][1].SetSeed(baseOTs[i][1]);
        }


        mHasBase = true;
    }
    std::unique_ptr<CopeOtExtReceiver> CopeOtExtReceiver::split()
    {
        std::array<std::array<block, 2>, gOtExtBaseOtCount>baseRecvOts;

        for (u64 i = 0; i < mGens.size(); ++i)
        {
            baseRecvOts[i][0] = mGens[i][0].get<block>();
            baseRecvOts[i][1] = mGens[i][1].get<block>();
        }

        std::unique_ptr<CopeOtExtReceiver> ret(new CopeOtExtReceiver());

        ret->setBaseOts(baseRecvOts);

        return std::move(ret);
    }


    void CopeOtExtReceiver::receive(
        span<ZpNumber> inVal,
        span<ZpNumber> share,
        PRNG& prng,
        Channel& chl)
    {

		throw std::runtime_error("NOT Implemented " LOCATION);
        //if (mHasBase == false)
        //    throw std::runtime_error("rt error at " LOCATION);

        //auto fieldSize = inVal[0].mField->bitCount();

        //// we are going to process OTs in blocks of 128 * copeSuperBlkSize messages.
        //u64 numOtExt = inVal.size() * fieldSize;
        //u64 numSuperBlocks = (numOtExt / 128 + copeSuperBlkSize - 1) / copeSuperBlkSize;
        //u64 numBlocks = numSuperBlocks * copeSuperBlkSize;

        //// this will be used as temporary buffers of 128 columns, 
        //// each containing 1024 bits. Once transposed, they will be copied
        //// into the T1, T0 buffers for long term storage.
        //std::array<std::array<block, copeSuperBlkSize>, 128> t0;

        //// the index of the OT that has been completed.
        ////u64 doneIdx = 0;
        //auto* inIter = inVal.data();
        //auto* sIter = share.data();

        //u64 step = std::min<u64>(numSuperBlocks, (u64)copeCommStepSize);
        //std::unique_ptr<ByteStream> uBuff(new ByteStream(step * 128 * copeSuperBlkSize * sizeof(block)));

        //// get an array of blocks that we will fill. 
        //auto uIter = (block*)uBuff->data();
        //auto uEnd = uIter + step * 128 * copeSuperBlkSize;

        //auto& field = *inVal[0].mField;
        //ZpNumber t0Num(field);
        //ZpNumber uNum(field);

        //std::vector<ZpNumber> g;
        //g.reserve(field.bitCount());
        //for (u64 i = 0; i < field.bitCount(); ++i)
        //{
        //    g.emplace_back(field, 2);
        //    g[i].powEq(i);
        //}

        //for (u64 superBlkIdx = 0; superBlkIdx < numSuperBlocks; ++superBlkIdx)
        //{

        //    // this will store the next 128 rows of the matrix u
        //    block* tIter = (block*)t0.data();

        //    std::cout << IoStream::lock;

        //    for (u64 j = 0; j < copeSuperBlkSize; ++j)
        //    {
        //        sIter[j] = 0;
        //    }

        //    for (u64 colIdx = 0; colIdx < 128; ++colIdx)
        //    {
        //        // generate the column indexed by colIdx. This is done with
        //        // AES in counter mode acting as a PRNG. We don'tIter use the normal
        //        // PRNG interface because that would result in a data copy when 
        //        // we move it into the T0,T1 matrices. Instead we do it directly.
        //        mGens[colIdx][0].mAes.ecbEncCounterMode(mGens[colIdx][0].mBlockIdx, copeSuperBlkSize, tIter);
        //        mGens[colIdx][1].mAes.ecbEncCounterMode(mGens[colIdx][1].mBlockIdx, copeSuperBlkSize, uIter);

        //        // increment the counter mode idx.
        //        mGens[colIdx][0].mBlockIdx += copeSuperBlkSize;
        //        mGens[colIdx][1].mBlockIdx += copeSuperBlkSize;

        //        for (u64 i = 0; i < copeSuperBlkSize; ++i)
        //        {
        //            t0Num.fromBytes((u8*)&tIter[i]);
        //            uNum.fromBytes((u8*)&uIter[i]);

        //            uNum -= t0Num;
        //            uNum -= inIter[i];

        //            uNum.toBytes((u8*)&uIter[i]);

        //            std::cout << "t0 [" << colIdx << "][" << i << "] = " << t0Num  << "  (-"<< t0Num  <<")" << std::endl;
        //            //std::cout << "t0x[" << i << "][" << colIdx << "] = " << t0Num + inIter[i] << std::endl;
        //            //std::cout << "t1x[" << i << "][" << colIdx << "] = " << uNum << std::endl;

        //            t0Num *= g[colIdx];
        //            sIter[i] -=  t0Num;
        //        }

        //        uIter += 8;
        //        tIter += 8;
        //    }
        //     
        //    //for (u64 j = 0; j < copeSuperBlkSize; ++j)
        //    //{
        //    //    sIter[j] = -sIter[j];
        //    //}

        //    inIter += 8;
        //    sIter += 8;

        //    std::cout << IoStream::unlock;

        //    if (uIter == uEnd)
        //    {
        //        // send over u buffer
        //        chl.asyncSend(std::move(uBuff));

        //        u64 step = std::min<u64>(numSuperBlocks - superBlkIdx - 1, (u64)copeCommStepSize);

        //        if (step)
        //        {
        //            uBuff.reset(new ByteStream(step * 128 * copeSuperBlkSize * sizeof(block)));

        //            uIter = (block*)uBuff->data();
        //            uEnd = uIter + step * 128 * copeSuperBlkSize;
        //        }
        //    }

        //}



        static_assert(gOtExtBaseOtCount == 128, "expecting 128");
    }

}
