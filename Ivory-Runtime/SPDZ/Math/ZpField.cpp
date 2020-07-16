#include "ZpField.h"

namespace osuCrypto
{



    ZpNumber::ZpNumber(const ZpNumber & num)
        : mVal(nullptr)
        , mField(num.mField)
    {
        init();
        *this = num;
    }

    ZpNumber::ZpNumber(ZpNumber && num)
        : mVal(num.mVal)
        , mField(num.mField)
    {
        num.mVal = nullptr;
    }

    ZpNumber::ZpNumber(
        ZpField & curve)
        :
        mVal(nullptr),
        mField(&curve)
    {
        init();
    }

    ZpNumber::ZpNumber(
        ZpField & curve,
        const ZpNumber& copy)
        :
        mVal(nullptr),
        mField(&curve)
    {
        init();
        *this = copy;
    }

    ZpNumber::ZpNumber(ZpField & curve, PRNG & prng)
        :
        mVal(nullptr),
        mField(&curve)
    {
        init();
        randomize(prng);
    }

    ZpNumber::ZpNumber(
        ZpField & curve,
        i32  val)
        :
        mVal(nullptr),
        mField(&curve)
    {
        init();
        *this = val;
    }

    ZpNumber::~ZpNumber()
    {
        if (mVal)
            mirkill(mVal);
    }

    ZpNumber& ZpNumber::operator=(const ZpNumber& c)
    {
        copy(c.mVal, mVal);
        return *this;
    }

    ZpNumber& ZpNumber::operator=(big c)
    {
        copy(c, mVal);
        return *this;
    }

    ZpNumber& ZpNumber::operator=(int i)
    {
        if (i == 0)
            zero(mVal);
        else
        {
            convert(mField->mMiracl, i, mVal);
            nres(mField->mMiracl, mVal, mVal);
        }
        return *this;
    }
    ZpNumber& ZpNumber::operator++()
    {
        nres_modadd(mField->mMiracl, mVal, mField->mOne->mVal, mVal);
        //incr(mField->mMiracl, mVal, 1, mVal);
        return *this;
    }
    ZpNumber& ZpNumber::operator--()
    {
        *this -= *mField->mOne;
        //nres_modsub(mField->mMiracl, mVal, mField->mOne->mVal, mVal);
        //decr(mField->mMiracl, mVal, 1, mVal);
        //reduce();
        return *this;
    }

    ZpNumber& ZpNumber::operator+=(int i)
    {
        ZpNumber inc(*mField, i);

        *this += inc;
        //nres_modadd(mField->mMiracl, mVal, inc.mVal, mVal);
        //add(mField->mMiracl, mVal, inc.mVal, mVal);
        //reduce();

        return *this;
    }

    ZpNumber& ZpNumber::operator-=(int i)
    {
        ZpNumber dec(*mField, i);
        nres_modsub(mField->mMiracl, mVal, dec.mVal, mVal);
        //nres_modsub()
        //subtract(mField->mMiracl, mVal, dec.mVal, mVal);
        //reduce();

        return *this;
    }

    ZpNumber& ZpNumber::operator+=(const ZpNumber& b)
    {
        nres_modadd(mField->mMiracl, mVal, b.mVal, mVal);
        //add(mField->mMiracl, mVal, b.mVal, mVal);
        //reduce();

        return *this;
    }

    ZpNumber& ZpNumber::operator-=(const ZpNumber& b)
    {
        nres_modsub(mField->mMiracl, mVal, b.mVal, mVal);
        //subtract(mField->mMiracl, mVal, b.mVal, mVal);
        //reduce();
        return *this;
    }

    ZpNumber& ZpNumber::operator*=(const ZpNumber& b)
    {
        nres_modmult(mField->mMiracl, mVal, b.mVal, mVal);
        //multiply(mField->mMiracl, mVal, b.mVal, mVal);
        //reduce();

        return *this;
    }

    ZpNumber& ZpNumber::operator*=(int i)
    {
        nres_premult(mField->mMiracl, mVal, i, mVal);
        //premult(mField->mMiracl, mVal, i, mVal);
        //reduce();

        return *this;
    }

    ZpNumber& ZpNumber::operator/=(const ZpNumber& b)
    {
        nres_moddiv(mField->mMiracl, mVal, b.mVal, mVal);
        //divide(mField->mMiracl, mVal, mField->getFieldPrime().mVal, mVal);
        return *this;
    }

    ZpNumber& ZpNumber::operator/=(int i)
    {
        ZpNumber div(*mField, i);

        *this /= div;
        return *this;
    }

    ZpNumber& ZpNumber::negate()
    {
        nres_negate(mField->mMiracl, mVal, mVal);
        //insign(-1, mVal);
        //reduce();
        return *this;
    }

    ZpNumber & ZpNumber::powEq(int p)
    {
        //ZpNumber v(*mField, pow);
        *this = pow(p);
        //big v= mirvar(mField->mMiracl, 0);
        //convert(mField->mMiracl, pow, v);
        //nres_powmod(mField->mMiracl, mVal, v, mVal);
        return *this;
    }

    ZpNumber ZpNumber::pow(int pow)
    {
        ZpNumber ret(*mField);
        big v = mirvar(mField->mMiracl, 0);
        convert(mField->mMiracl, pow, v);
        nres_powmod(mField->mMiracl, mVal, v, ret.mVal);

        return ret;
    }


    bool ZpNumber::operator==(const ZpNumber & cmp) const
    {
        return (mr_compare(mVal, cmp.mVal) == 0);
    }

    bool ZpNumber::operator==(const int & cmp)const
    {
        return cmp == *this;
    }

    bool ZpNumber::operator!=(const ZpNumber & cmp)const
    {
        return !(*this == cmp);
    }

    bool ZpNumber::operator!=(const int & cmp)const
    {
        return !(*this == cmp);
    }

    bool ZpNumber::operator>=(const ZpNumber & cmp)const
    {
        redc(mField->mMiracl, mVal, mVal);
        redc(mField->mMiracl, cmp.mVal, cmp.mVal);
        auto  r = (mr_compare(mVal, cmp.mVal) >= 0);
        nres(mField->mMiracl, mVal, mVal);
        nres(mField->mMiracl, cmp.mVal, cmp.mVal);
        return r;
    }

    bool ZpNumber::operator>=(const int & cmp)const
    {
        ZpNumber c(*mField, cmp);
        return (*this >= c);
    }

    bool ZpNumber::operator<=(const ZpNumber & cmp)const
    {
        return cmp >= *this;
    }

    bool ZpNumber::operator<=(const int & cmp)const
    {
        ZpNumber c(*mField, cmp);
        return (*this <= c);
    }

    bool ZpNumber::operator>(const ZpNumber & cmp)const
    {
        return !(cmp >= *this);
    }

    bool ZpNumber::operator>(const int & cmp)const
    {
        ZpNumber c(*mField, cmp);
        return !(c >= *this);
    }

    bool ZpNumber::operator<(const ZpNumber & cmp)const
    {
        return !(cmp <= *this);
    }

    bool ZpNumber::operator<(const int & cmp)const
    {
        ZpNumber c(*mField, cmp);
        return !(c <= *this);
    }

    BOOL ZpNumber::iszero() const
    {
        if (size(mVal) == 0) return TRUE;
        return FALSE;
    }

    bool operator==(const int & cmp1, const ZpNumber & cmp2)
    {
        ZpNumber cmp(*cmp2.mField, cmp1);

        return (cmp == cmp2);
    }

    ZpNumber operator-(const ZpNumber& b)
    {
        ZpNumber x = b;
        x.negate();
        return x;
    }

    ZpNumber operator+(const ZpNumber& b, int i)
    {
        ZpNumber abi = b;
        abi += i;
        return abi;
    }
    ZpNumber operator+(int i, const ZpNumber& b)
    {
        ZpNumber aib = b;
        aib += i;
        return aib;
    }
    ZpNumber operator+(const ZpNumber& b1, const ZpNumber& b2)
    {
        ZpNumber abb = b1;
        abb += b2;
        return abb;
    }

    ZpNumber operator-(const ZpNumber& b, int i)
    {
        ZpNumber mbi = b;
        mbi -= i;
        return mbi;
    }
    ZpNumber operator-(int i, const ZpNumber& b)
    {
        ZpNumber mib(*b.mField, i);
        mib -= b;
        return mib;
    }
    ZpNumber operator-(const ZpNumber& b1, const ZpNumber& b2)
    {
        ZpNumber mbb = b1;
        mbb -= b2;
        return mbb;
    }

    ZpNumber operator*(const ZpNumber& b, int i)
    {
        ZpNumber xbb = b;
        xbb *= i;
        return xbb;
    }
    ZpNumber operator*(int i, const ZpNumber& b)
    {
        ZpNumber xbb = b;
        xbb *= i;
        return xbb;
    }
    ZpNumber operator*(const ZpNumber& b1, const ZpNumber& b2)
    {
        ZpNumber xbb = b1;
        xbb *= b2;
        return xbb;
    }

    ZpNumber operator/(const ZpNumber& b1, int i)
    {
        ZpNumber z = b1;
        z /= i;
        return z;
    }

    ZpNumber operator/(int i, const ZpNumber& b2)
    {
        ZpNumber z(*b2.mField, i);
        z /= b2;
        return z;
    }
    ZpNumber operator/(const ZpNumber& b1, const ZpNumber& b2)
    {
        ZpNumber z = b1;
        z /= b2;
        return z;
    }

    std::ostream & operator<<(std::ostream & out, const ZpNumber & val)
    {
        redc(val.mField->mMiracl, val.mVal, val.mVal);
        cotstr(val.mField->mMiracl, val.mVal, val.mField->mMiracl->IOBUFF);
        out << val.mField->mMiracl->IOBUFF;
        nres(val.mField->mMiracl, val.mVal, val.mVal);

        return out;
    }

    u64 ZpNumber::sizeBytes() const
    {
        return (mField->mBitCount + 7) / 8;
    }

    void ZpNumber::toBits(u8 * dest) const
    {
        ZpNumber temp(*mField);
        redc(mField->mMiracl, mVal, temp.mVal);
        temp.toBytes(dest);

        for (u64 i = 0; i < sizeBytes() / 2; ++i)
        {
            std::swap(dest[i], dest[sizeBytes() - 1 - i]);
        }
    }

    void ZpNumber::toBytes(u8 * dest) const
    {
        big_to_bytes(mField->mMiracl, (int)sizeBytes(), mVal, (char*)dest, true);
    }

    void ZpNumber::fromBits(u8 * src)
    {
        u8* temp = new u8[sizeBytes()];

        for (u64 i = 0; i < sizeBytes(); ++i)
        {
            temp[i] = src[sizeBytes() - 1 - i];
        }

        bytes_to_big(mField->mMiracl, (int)sizeBytes(), (char*)temp, mVal);
        nres(mField->mMiracl, mVal, mVal);
    }

    void ZpNumber::fromBytes(u8 * src)
    {
        bytes_to_big(mField->mMiracl, (int)sizeBytes(), (char*)src, mVal);
    }

    void ZpNumber::fromHex(char * src)
    {
        auto oldBase = mField->mMiracl->IOBASE;
        mField->mMiracl->IOBASE = 16;

        cinstr(mField->mMiracl, mVal, src);

        mField->mMiracl->IOBASE = oldBase;
    }

    void ZpNumber::fromDec(char * src)
    {
        auto oldBase = mField->mMiracl->IOBASE;
        mField->mMiracl->IOBASE = 10;

        cinstr(mField->mMiracl, mVal, src);

        mField->mMiracl->IOBASE = oldBase;
    }

    void ZpNumber::randomize(PRNG & prng)
    {

        int m;
        mr_small r;

        auto w = mField->getFieldPrime().mVal;
        auto mr_mip = mField->mMiracl;

        m = 0;
        zero(mVal);

        do
        { /* create big rand piece by piece */
            m++;
            mVal->len = m;
            r = prng.get<u64>();

            if (mField->mMiracl->base == 0)
            {
                mVal->w[m - 1] = r;
            }
            else
            {
                mVal->w[m - 1] = MR_REMAIN(r, mField->mMiracl->base);
            }

        } while (mr_compare(mVal, w) < 0);

        mr_lzero(mVal);
        divide(_MIPP_ mVal, w, w);

        while (mr_compare(mVal, mField->getFieldPrime().mVal) > 0)
        {
            std::cout << "bad rand" << std::endl;
            throw std::runtime_error("");
        }
    }

    void ZpNumber::randomize(const block & seed)
    {
        PRNG prng(seed);
        randomize(prng);
    }

    void ZpNumber::init()
    {
        mVal = mirvar(mField->mMiracl, 0);

    }

    big ZpNumber::data()
    {
        //return &mData;
        return mVal;
    }

    //void ZpNumber::reduce()
    //{

    //    if (exsign(mVal) == -1)
    //    {
    //        //std::cout << "neg                  " << *this << std::endl;


    //        add(mField->mMiracl, mVal, mField->getFieldPrime().mVal, mVal);
    //        //*this += mField->getOrder();

    //        if (exsign(mVal) == -1)
    //        {
    //            std::cout << "neg reduce error " << *this << std::endl;
    //            std::cout << "                  " << mField->getFieldPrime() << std::endl;
    //            throw std::runtime_error(LOCATION);
    //        }
    //    }

    //    if (*this >= mField->getFieldPrime())
    //    {
    //        // only computes the remainder. since the params are
    //        //
    //        //    divide(mVal, mod, mod)
    //        //
    //        // mVal holds  the remainder
    //        //bool  n = 0;
    //        //if (exsign(mVal) == -1)
    //        //{
    //        //    std::cout << *this << " -> ";
    //        //    n = 1;
    //        //}

    //        divide(mField->mMiracl,
    //            mVal,
    //            mField->getFieldPrime().mVal,
    //            mField->getFieldPrime().mVal);

    //        //if (n)
    //        //{
    //        //    std::cout << *this << std::endl;
    //        //}
    //    }
    //}

    ZpField::ZpField(const ZpParam & params)
    {
        setParameters(params);
    }

    ZpField::ZpField()
    {
    }


    ZpField::~ZpField()
    {
    }

    void ZpField::setParameters(const ZpParam & params)
    {
        if (mMiracl) mirexit(mMiracl);

        mBitCount = params.bitCount;
        mMiracl = mirsys(params.bitCount * 2, 2);

        mMiracl->IOBASE = 16;

        mFieldPrime.reset(new ZpNumber(*this));
        mFieldPrime->fromHex((char*)params.p);
        prepare_monty(mMiracl, getFieldPrime().mVal);

        mOne.reset(new ZpNumber(*this));
        *mOne = 1;
    }

    const ZpNumber & ZpField::getFieldPrime() const
    {
        return *mFieldPrime;
    }

    u64 ZpField::bitCount()
    {
        return mBitCount;
    }


}