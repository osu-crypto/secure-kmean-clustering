#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use. 
#include "libOTe/TwoChooseOne/OTExtInterface.h"
#include "cryptoTools/Network/Channel.h"
#include <array>
#include "cryptoTools/Crypto/PRNG.h"
#include "Math/ZpField.h"

namespace osuCrypto
{

    class CopeOtExtReceiver
    {
    public:
        CopeOtExtReceiver()
            :mHasBase(false)
        {}

        bool hasBaseOts() const 
        {
            return mHasBase;
        }

        bool mHasBase;
        std::array<std::array<PRNG, 2>, gOtExtBaseOtCount> mGens;

        void setBaseOts(
            span<std::array<block, 2>> baseSendOts);
        std::unique_ptr<CopeOtExtReceiver> split() ;


        void receive(
            span<ZpNumber> messages,
            span<ZpNumber> share,
            PRNG& prng,
            Channel& chl);

    };

}
