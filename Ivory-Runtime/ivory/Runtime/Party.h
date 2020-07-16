#pragma once
#include "ivory/Runtime/Runtime.h"
#include "cryptoTools/Common/Defines.h"
#include <future>
#include "ivory/Runtime/sInt.h"
namespace osuCrypto
{

    class Party
    {
    public:
        Party(Runtime& runtime, u64 partyIdx);

        template<typename T>
        T input(const typename T::ValueType&, BitCount bitCount);

        template<typename T>
        T input(BitCount bitCount);

        //template<typename T>
        //sInt sIntInput(sInt::ValueType& v, BitCount bitCount = sizeof(sInt::ValueType) * 8)
        //{
        //    mRuntime.sIntInput(v, bitCount);
        //}

        //sInt sIntInput(BitCount bitCount);

        template<typename T>
        void reveal(const T&);

        u64 getPartyIdx() { return mPartyIdx; }

        bool isLocalParty() { return mPartyIdx == mRuntime.getPartyIdx(); }

        Runtime& getRuntime()
        {
            return mRuntime;
        }

    private:
        Runtime& mRuntime;
        u64 mPartyIdx;
    };


    template<>
    sInt Party::input<sInt>(const sInt::ValueType& value, BitCount bitCount);
    template<>
    sInt Party::input<sInt>(BitCount bitCount);

    //template<typename T>
    //T Party::input(typename const T::ValueType& value, BitCount bitCount)
    //{
    //    //return mRuntime.sInt(value, bitCount, mPartyIdx);
    //    return T;
    //}


    //template<typename T>
    //T Party::input(u64 bitCount)
    //{
    //    T ret(mRuntime, bitCount);
    //    mRuntime.scheduleInput(ret.mData.get(), mPartyIdx);
    //    return ret;
    //}

    template<typename T>
    inline void Party::reveal(const T& var)
    {
        // cast the const away...
        auto& v = *(T*)&var;
        std::array<u64, 1> p{ mPartyIdx };
        v.reveal(p);

        //if (isLocalParty())
        //{
        //    v.mValFut.reset(new std::future<BitVector>());
        //    mRuntime.scheduleOutput(v.mData.get(), *v.mValFut.get());
        //}
        //else
        //{
        //    mRuntime.scheduleOutput(v.mData.get(), mPartyIdx);
        //}
    }



}
