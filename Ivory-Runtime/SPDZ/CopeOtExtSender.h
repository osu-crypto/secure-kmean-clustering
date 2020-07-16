#pragma once
#include "libOTe/TwoChooseOne/OTExtInterface.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "Math/ZpField.h"


namespace osuCrypto
{

    class CopeOtExtSender
    {

    public:
        //CopeOtExtSender();
        //~CopeOtExtSender();



        std::array<PRNG, gOtExtBaseOtCount> mGens;
        BitVector mBaseChoiceBits;

        bool hasBaseOts() const
        {
            return mBaseChoiceBits.size() > 0;
        }

        std::unique_ptr<CopeOtExtSender> split();

        void setBaseOts(
            span<block> baseRecvOts,
            const BitVector& choices);


        void send(
            span<ZpNumber> messages,
            Channel& chl);

    };

}
