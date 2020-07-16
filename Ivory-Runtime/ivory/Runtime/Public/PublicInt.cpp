#include "PublicInt.h"

//#include ""

namespace osuCrypto
{
    namespace Public
    {
        i64 signExtend(i64 v, u64 bitIdx)
        {
            u8 bit = (v >> bitIdx) & 1;
            u64 topMask = bit * (u64(-1) << (64 - bitIdx));
            u64 botMask = ~topMask;

            return (v & botMask) | topMask;
        }
    }

    void PublicInt::copy(sIntBasePtr & c)
    {
        auto& cc = static_cast<PublicInt&>(*c.get());
        mValue = Public::signExtend(cc.mValue, mBitCount);
    }

    sIntBasePtr PublicInt::copy()
    {
        auto ret = new PublicInt(mValue, mBitCount);
        return sIntBasePtr(ret);
    }

    u64 PublicInt::bitCount()
    {
        return mBitCount;
    }
    Runtime & PublicInt::getRuntime()
    {
        throw std::runtime_error( "PublicInt has no runtime" LOCATION);
    }
    sIntBasePtr PublicInt::add(sIntBasePtr & a, sIntBasePtr & b)
    {
        auto bb = static_cast<PublicInt*>(b.get());
        if (bb == nullptr)
        {   // b is not public data, let b decide how to add a which is public.
            return b->add(a, b);
        }
        else {
            auto ret = new PublicInt();
            ret->mBitCount = std::max(mBitCount, bb->mBitCount);
            ret->mValue = Public::signExtend(mValue + bb->mValue, ret->mBitCount);
            return sIntBasePtr(ret);
        }
    }


	sIntBasePtr PublicInt::ifequal(sIntBasePtr & a, sIntBasePtr & b)
	{
		auto bb = static_cast<PublicInt*>(b.get());
		if (bb == nullptr)
		{   // b is not public data, let b decide how to gt a which is public.
			return b->ifequal(a, b);
		}
		else {
			auto ret = new PublicInt();
			ret->mBitCount = 1;
			ret->mValue = Public::signExtend(mValue > bb->mValue, ret->mBitCount);
			return sIntBasePtr(ret);
		}
	}


    sIntBasePtr PublicInt::subtract(sIntBasePtr & a, sIntBasePtr & b)
    {
        auto bb = static_cast<PublicInt*>(b.get());
        if (bb == nullptr)
        {   // b is not public data, let b decide how to subtract a which is public.
            return b->subtract(a, b);
        }
        else {
            auto ret = new PublicInt();
            ret->mBitCount = std::max(mBitCount, bb->mBitCount);
            ret->mValue = Public::signExtend(mValue - bb->mValue, ret->mBitCount);
            return sIntBasePtr(ret);
        }
    }
    sIntBasePtr PublicInt::multiply(sIntBasePtr & a, sIntBasePtr & b)
    {
        auto bb = static_cast<PublicInt*>(b.get());
        if (bb == nullptr)
        {   // b is not public data, let b decide how to multiply a which is public.
            return b->multiply(a, b);
        }
        else {
            auto ret = new PublicInt();
            ret->mBitCount = std::max(mBitCount, bb->mBitCount);
            ret->mValue = Public::signExtend(mValue * bb->mValue, ret->mBitCount);
            return sIntBasePtr(ret);
        }
    }
    sIntBasePtr PublicInt::divide(sIntBasePtr & a, sIntBasePtr & b)
    {
        auto bb = static_cast<PublicInt*>(b.get());
        if (bb == nullptr)
        {   // b is not public data, let b decide how to divide a which is public.
            return b->divide(a, b);
        }
        else {
            auto ret = new PublicInt();
            ret->mBitCount = std::max(mBitCount, bb->mBitCount);
            ret->mValue = Public::signExtend(mValue / bb->mValue, ret->mBitCount);
            return sIntBasePtr(ret);
        }
    }
    sIntBasePtr PublicInt::negate()
    {
        auto ret = new PublicInt();
        ret->mBitCount = mBitCount;
        ret->mValue = Public::signExtend(-mValue, ret->mBitCount);
        return sIntBasePtr(ret);
    }

	sIntBasePtr PublicInt::abs()
	{
		auto ret = new PublicInt();
		ret->mBitCount = mBitCount;
		ret->mValue = Public::signExtend(-mValue, ret->mBitCount);
		return sIntBasePtr(ret);
	}

    sIntBasePtr PublicInt::gteq(sIntBasePtr & a, sIntBasePtr & b)
    {
        auto bb = static_cast<PublicInt*>(b.get());
        if (bb == nullptr)
        {   // b is not public data, let b decide how to gteq a which is public.
            return b->gteq(a, b);
        }
        else {
            auto ret = new PublicInt();
            ret->mBitCount = 1;
            ret->mValue = Public::signExtend(mValue >= bb->mValue, ret->mBitCount);
            return sIntBasePtr(ret);
        }
    }
    sIntBasePtr PublicInt::gt(sIntBasePtr & a, sIntBasePtr & b)
    {
        auto bb = static_cast<PublicInt*>(b.get());
        if (bb == nullptr)
        {   // b is not public data, let b decide how to gt a which is public.
            return b->gteq(a, b);
        }
        else {
            auto ret = new PublicInt();
            ret->mBitCount = 1;
            ret->mValue = Public::signExtend(mValue > bb->mValue, ret->mBitCount);
            return sIntBasePtr(ret);
        }
    }
    sIntBasePtr PublicInt::bitwiseInvert()
    {
        auto ret = new PublicInt();
        ret->mBitCount = mBitCount;
        ret->mValue = Public::signExtend(~mValue, ret->mBitCount);
        return sIntBasePtr(ret);
    }
    sIntBasePtr PublicInt::bitwiseAnd(sIntBasePtr & a, sIntBasePtr & b)
    {
        auto bb = static_cast<PublicInt*>(b.get());
        if (bb == nullptr)
        {   // b is not public data, let b decide how to bitwiseAnd a which is public.
            return b->gteq(a, b);
        }
        else {
            auto ret = new PublicInt();
            ret->mBitCount = std::max(mBitCount, bb->mBitCount);;
            ret->mValue = Public::signExtend(mValue & bb->mValue, ret->mBitCount);
            return sIntBasePtr(ret);
        }
    }
    sIntBasePtr PublicInt::bitwiseOr(sIntBasePtr & a, sIntBasePtr & b)
    {
        auto bb = static_cast<PublicInt*>(b.get());
        if (bb == nullptr)
        {   // b is not public data, let b decide how to bitwiseOr a which is public.
            return b->gteq(a, b);
        }
        else {
            auto ret = new PublicInt();
            ret->mBitCount = std::max(mBitCount, bb->mBitCount);;
            ret->mValue = Public::signExtend(mValue | bb->mValue, ret->mBitCount);
            return sIntBasePtr(ret);
        }
    }
    sIntBasePtr PublicInt::ifelse(sIntBasePtr & a, sIntBasePtr & ifTrue, sIntBasePtr & ifFalse)
    {

        return mValue ? ifTrue->copy() : ifFalse->copy();
        //auto tt = static_cast<PublicInt*>(ifTrue.get());
        //auto ff = static_cast<PublicInt*>(ifFalse.get());
        //if (tt == nullptr)
        //{   // tt is not public data, let tt decide how to ifelse a which is public.
        //    return tt->gteq(a, b);
        //}
        //else {
        //    auto ret = new PublicInt();
        //    ret->mBitCount = std::max(mBitCount, bb->mBitCount);;
        //    ret->mValue = Public::signExtend(mValue | bb->mValue, ret->mBitCount);
        //    return sIntBasePtr(ret);
        //}
    }
}
