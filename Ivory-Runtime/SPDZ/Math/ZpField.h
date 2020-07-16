#pragma once

#include "miracl/include/miracl.h"
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Crypto/PRNG.h"


namespace osuCrypto
{
    struct ZpParam
    {
        u32 bitCount;
        // prime
        const char* p;
    };


    const ZpParam ZpParam5_INSECURE
    {
        5,
        "17",
    };



    const ZpParam ZpParam128
    {
        128,
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF61",
    };


    class ZpField;

    class ZpNumber
    {
    public:
        ZpNumber(const ZpNumber& num);
        ZpNumber(ZpNumber&& num);
        ZpNumber(ZpField& field);
        ZpNumber(ZpField& field, const ZpNumber& num);
        ZpNumber(ZpField& field, PRNG& prng);
        ZpNumber(ZpField& field, i32 val);

        ~ZpNumber();

        ZpNumber& operator=(const ZpNumber& c);
        ZpNumber& operator=(big c);
        ZpNumber& operator=(int i);


        ZpNumber& operator++();
        ZpNumber& operator--();
        ZpNumber& operator+=(int i);
        ZpNumber& operator-=(int i);
        ZpNumber& operator+=(const ZpNumber& b);
        ZpNumber& operator-=(const ZpNumber& b);
        ZpNumber& operator*=(const ZpNumber& b);
        ZpNumber& operator*=(int i);
        ZpNumber& operator/=(const ZpNumber& b);
        ZpNumber& operator/=(int i);
        ZpNumber& negate();

        ZpNumber& powEq(int pow);
        ZpNumber pow(int pow);

        //ZpNumber& powEq(ZpNumber pow);
        //ZpNumber pow(ZpNumber pow);


        bool operator==(const ZpNumber& cmp) const;
        bool operator==(const int& cmp)const;
        friend bool operator==(const int& cmp1, const ZpNumber& cmp2);
        bool operator!=(const ZpNumber& cmp)const;
        bool operator!=(const int& cmp)const;
        friend bool operator!=(const int& cmp1, const ZpNumber& cmp2);

        bool operator>=(const ZpNumber& cmp)const;
        bool operator>=(const int& cmp)const;

        bool operator<=(const ZpNumber& cmp)const;
        bool operator<=(const int& cmp)const;

        bool operator>(const ZpNumber& cmp)const;
        bool operator>(const int& cmp)const;

        bool operator<(const ZpNumber& cmp)const;
        bool operator<(const int& cmp)const;


        BOOL iszero() const;


        friend ZpNumber operator-(const ZpNumber&);
        friend ZpNumber operator+(const ZpNumber&, int);
        friend ZpNumber operator+(int, const ZpNumber&);
        friend ZpNumber operator+(const ZpNumber&, const ZpNumber&);

        friend ZpNumber operator-(const ZpNumber&, int);
        friend ZpNumber operator-(int, const ZpNumber&);
        friend ZpNumber operator-(const ZpNumber&, const ZpNumber&);

        friend ZpNumber operator*(const ZpNumber&, int);
        friend ZpNumber operator*(int, const ZpNumber&);
        friend ZpNumber operator*(const ZpNumber&, const ZpNumber&);

        friend ZpNumber operator/(const ZpNumber&, int);
        friend ZpNumber operator/(int, const ZpNumber&);
        friend ZpNumber operator/(const ZpNumber&, const ZpNumber&);

        u64 sizeBytes() const;
        void toBits(u8* dest) const;
        void toBytes(u8* dest) const;
        void fromBits(u8* src);
        void fromBytes(u8* src);
        void fromHex(char* src);
        void fromDec(char* src);

        void randomize(PRNG& prng);
        void randomize(const block& seed);


    private:

        void init();
        //void reduce();

        big data();
    public:
        //struct bigtype mData;
        big mVal;
        ZpField* mField;
         
        friend std::ostream& operator<<(std::ostream& out, const ZpNumber& val);
    };
    std::ostream& operator<<(std::ostream& out, const ZpNumber& val);


    class ZpField
    {
        friend ZpNumber;
        friend std::ostream& operator<<(std::ostream& out, const ZpNumber& val);

    public:
        ZpField(const ZpParam& params);
        ZpField();
        ~ZpField();

        void setParameters(const ZpParam& params);

        const ZpNumber& getFieldPrime() const;

        u64 bitCount();

    private:
        u64 mBitCount;

        std::unique_ptr<ZpNumber>  mFieldPrime, mOne;

        miracl* mMiracl;
    };

}
