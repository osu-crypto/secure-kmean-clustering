#pragma once
#include "ivory/Runtime/sInt.h"


namespace osuCrypto
{

    class PublicInt
        : public sIntBase
    {
    public:
        sInt::ValueType mValue = 0;
        u64 mBitCount = 0;

		PublicInt()  {}
		PublicInt(sInt::ValueType v, u64 bits) : mValue(v), mBitCount(bits) {}
        ~PublicInt() override {}

        void copy(sIntBasePtr& c)override;
        sIntBasePtr copy()override;
        u64 bitCount()override;
        Runtime& getRuntime()override;
		//i64 signExtend(i64 v, u64 bitIdx);

        sIntBasePtr add(sIntBasePtr& a, sIntBasePtr& b)override;
        sIntBasePtr subtract(sIntBasePtr& a, sIntBasePtr& b)override;
        sIntBasePtr multiply(sIntBasePtr& a, sIntBasePtr& b)override;
        sIntBasePtr divide(sIntBasePtr& a, sIntBasePtr& b)override;

		sIntBasePtr negate()override;
		sIntBasePtr abs()override;

        sIntBasePtr gteq(sIntBasePtr& a, sIntBasePtr& b)override;
        sIntBasePtr gt(sIntBasePtr& a, sIntBasePtr& b)override;

        sIntBasePtr bitwiseInvert()override;
        sIntBasePtr bitwiseAnd(sIntBasePtr& a, sIntBasePtr& b)override;
        sIntBasePtr bitwiseOr(sIntBasePtr& a, sIntBasePtr& b)override;

		sIntBasePtr ifelse(sIntBasePtr& a, sIntBasePtr& ifTrue, sIntBasePtr& ifFalse)override;
		sIntBasePtr ifequal(sIntBasePtr& ifTrue, sIntBasePtr& ifFalse)override;

        void reveal(u64 partyIdx)override { throw std::runtime_error(" cant reveal public value" LOCATION); }
        void reveal(span<u64> partyIdxs)override { throw std::runtime_error(" cant reveal public value" LOCATION); }
        ValueType getValue()override { return mValue; }
    };

}
