#include "Party.h"


namespace osuCrypto
{


    Party::Party(Runtime & runtime, u64 partyIdx)
        : mRuntime(runtime)
        , mPartyIdx(partyIdx)
    { }

    template<>
    sInt Party::input<sInt>(const sInt::ValueType& value, BitCount bitCount)
    {
        return mRuntime.sIntInput(value, bitCount);
    }

    template<>
    sInt Party::input<sInt>(BitCount bitCount)
    {
        return mRuntime.sIntInput(bitCount, mPartyIdx);
    }
}