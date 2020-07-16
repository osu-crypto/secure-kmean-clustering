#include "sInt.h"
#include <ivory/Runtime/Runtime.h>
namespace osuCrypto
{

    sInt::sInt(const i64 & val)
        : mData(Runtime::getPublicInt(val, 64))
    { }

    sInt::sInt(const i32 & val)
        : mData(Runtime::getPublicInt(val, 32))
    { }

    sInt::sInt(const i16 & val)
        : mData(Runtime::getPublicInt(val, 16))
    { }

    sInt::sInt(const i8 & val)
        : mData(Runtime::getPublicInt(val, 8))
    { }

    sInt::~sInt()
    { }

    sInt& sInt::operator=(const sInt & c)
    {
        sIntBasePtr& s = (sIntBasePtr&)c.mData;
        mData->copy(s);
        return *this;
    }

    sInt & sInt::operator=(sInt && mv)
    {
        mData = std::move(mv.mData);
        return *this;
    }

	/*void sInt::bitwiseInvert11()
	{
		return mData->bitwiseInvert();
	}*/

    sInt sInt::operator~()
    {
        return mData->bitwiseInvert();
    }

    sInt sInt::operator+(const sInt& in2) const
    {
        return mData->add((sIntBasePtr&)mData, (sIntBasePtr&)in2.mData);
    }

    sInt sInt::operator-(const sInt & in2) const
    {
        return mData->subtract((sIntBasePtr&)mData, (sIntBasePtr&)in2.mData);
    }

    sInt sInt::operator>=(const sInt & in2)
    {
        return mData->gteq((sIntBasePtr&)mData, (sIntBasePtr&)in2.mData);
    }

    sInt sInt::operator>(const sInt &in2)
    {
        return mData->gt((sIntBasePtr&)mData, (sIntBasePtr&)in2.mData);
    }

    sInt sInt::operator<=(const sInt &in2)
    {
        return in2.mData->gteq((sIntBasePtr&)in2.mData, (sIntBasePtr&)mData);
    }

    sInt sInt::operator<(const sInt & in2)
    {
        return in2.mData->gt((sIntBasePtr&)in2.mData, mData);
    }

    sInt sInt::operator&(const sInt &in2)
    {
        return mData->bitwiseAnd((sIntBasePtr&)mData, (sIntBasePtr&)in2.mData);
    }

    sInt sInt::ifelse(const sInt & ifTrue, const sInt & ifFalse)
    {
        return mData->ifelse((sIntBasePtr&)mData, (sIntBasePtr&)ifTrue.mData, (sIntBasePtr&)ifFalse.mData);
    }


	sInt sInt::ifequal(const sInt & in2)
	{
		return mData->ifequal((sIntBasePtr&)in2.mData, (sIntBasePtr&)mData);
	}

	sInt sInt::abs()
	{
		return mData->abs();
	}

    sInt& sInt::operator+=(const sInt& in2)
    {
        mData = mData->add((sIntBasePtr&)mData, (sIntBasePtr&)in2.mData);
        return *this;
    }

    sInt sInt::operator*(const sInt& in2) const
    {
        return mData->multiply((sIntBasePtr&)mData, (sIntBasePtr&)in2.mData);
    }

    sInt sInt::operator/(const sInt & in2) const
    {
        return mData->divide((sIntBasePtr&)mData, (sIntBasePtr&)in2.mData);
    }

    sInt::ValueType sInt::getValue()
    {
        return mData->getValue();
    }

    void sInt::reveal(span<u64> partyIdxs)
    {
        mData->reveal(partyIdxs);
    }

}