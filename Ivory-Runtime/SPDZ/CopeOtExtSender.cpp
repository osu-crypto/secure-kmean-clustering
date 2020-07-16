#include "CopeOtExtSender.h"

#include "CopeOtExtDefines.h"
#include "cryptoTools/Crypto/Commit.h"
#include "libOTe/Tools/Tools.h"
#include "Math/ZpField.h"

#include "cryptoTools/Common/Log.h"
#include "cryptoTools/Network/Channel.h"

namespace osuCrypto
{

    std::unique_ptr<CopeOtExtSender> CopeOtExtSender::split()
    {

        std::unique_ptr<CopeOtExtSender> ret(new CopeOtExtSender());

        std::array<block, gOtExtBaseOtCount> baseRecvOts;

        for (u64 i = 0; i < mGens.size(); ++i)
        {
            baseRecvOts[i] = mGens[i].get<block>();
        }

        ret->setBaseOts(baseRecvOts, mBaseChoiceBits);

        return std::move(ret);
    }

    void CopeOtExtSender::setBaseOts(span<block> baseRecvOts, const BitVector & choices)
    {
        if (baseRecvOts.size() != gOtExtBaseOtCount || choices.size() != gOtExtBaseOtCount)
            throw std::runtime_error("not supported/implemented");


        mBaseChoiceBits = choices;
        for (u64 i = 0; i < gOtExtBaseOtCount; i++)
        {
            mGens[i].SetSeed(baseRecvOts[i]);
        }
    }

    void CopeOtExtSender::send(
        span<ZpNumber> messages,
        Channel& chl)
    {
        auto fieldSize = messages[0].mField->bitCount();

        // round up
        u64 numOtExt = roundUpTo(messages.size() * fieldSize, 128);
        u64 numSuperBlocks = (numOtExt / 128 + copeSuperBlkSize - 1) / copeSuperBlkSize;
        //u64 numBlocks = numSuperBlocks * copeSuperBlkSize;

        // a uNum that will be used to transpose the sender's matrix
        std::array<block, copeSuperBlkSize> t;
        std::vector<std::array<block, copeSuperBlkSize>> u(128 * copeCommStepSize);

        //std::array<block, 128> choiceMask;
        block delta = *(block*)mBaseChoiceBits.data();

        //for (u64 i = 0; i < 128; ++i)
        //{
        //    if (mBaseChoiceBits[i]) choiceMask[i] = AllOneBlock;
        //    else choiceMask[i] = ZeroBlock;
        //}


        auto* mIter = messages.data();

        block * uIter = (block*)u.data() + copeSuperBlkSize * 128 * copeCommStepSize;
        block * uEnd = uIter;

        ZpField field;
        field.setParameters(ZpParam128);

        std::vector<ZpNumber> g;
        //qq.reserve(copeSuperBlkSize * field.bitCount());
        //for (u64 i = 0; i < copeSuperBlkSize * field.bitCount(); ++i)
        //    qq.emplace_back(field);

        std::cout << IoStream::lock;
        g.reserve(field.bitCount());
        for (u64 i = 0; i < field.bitCount(); ++i)
        {
            g.emplace_back(field, 2);
            g[i].powEq(i);
            std::cout << "g[" << i << "] " << g[i] << std::endl;
        }

        std::cout << IoStream::unlock;

        std::array<ZpNumber, copeSuperBlkSize> q
         {
            ZpNumber(field),ZpNumber(field),ZpNumber(field),ZpNumber(field),
            ZpNumber(field), ZpNumber(field), ZpNumber(field), ZpNumber(field)
        };

        ZpNumber uNum(field);

        for (u64 superBlkIdx = 0; superBlkIdx < numSuperBlocks; ++superBlkIdx)
        {

            if (uIter == uEnd)
            {
                u64 step = std::min<u64>(numSuperBlocks - superBlkIdx, (u64)copeCommStepSize);
                chl.recv((u8*)u.data(), step * copeSuperBlkSize * 128 * sizeof(block));
                uIter = (block*)u.data();
            }

            for (u64 j = 0; j < copeSuperBlkSize; ++j)
            {
                //qq[j] = 0;
                mIter[j] = 0;
            }
            std::cout << IoStream::lock;

            // transpose 128 columns at at time. Each column will be 128 * copeSuperBlkSize = 1024 bits long.
            for (u64 colIdx = 0; colIdx < 128; ++colIdx)
            {
                // generate the columns using AES-NI in counter mode.
                mGens[colIdx].mAes.ecbEncCounterMode(mGens[colIdx].mBlockIdx, copeSuperBlkSize, t.data());
                mGens[colIdx].mBlockIdx += copeSuperBlkSize;

                for (u64 i = 0; i < copeSuperBlkSize; ++i)
                {
                    q[i].fromBytes((u8*)&t[i]);
                }

                if (this->mBaseChoiceBits[colIdx])
                {
                    for (u64 i = 0; i < copeSuperBlkSize; ++i)
                    {
                        uNum.fromBytes((u8*)&uIter[i]);
                        q[i] -= uNum;
                    }
                }



                for (u64 i = 0; i < copeSuperBlkSize; ++i)
                {
                    //std::cout <<  (mBaseChoiceBits[colIdx]? "t0x" : "t0 ") <<"[" << i << "][" << colIdx << "] = " << q[i] <<"   " << mBaseChoiceBits[colIdx] << "\n\n"<<std::endl;
                    std::cout << "q[" << colIdx << "][" << i << "] = " << q[i] << std::endl;
                    q[i] *= g[colIdx];

                    mIter[i] += q[i];
                }

                uIter += 8;
            }
            std::cout << IoStream::unlock;

            mIter += 8;

        }


        static_assert(gOtExtBaseOtCount == 128, "expecting 128");
    }


}
