#ifndef sInt_H  // header guard
#define sInt_H

#pragma once
//#include "Runtime/CrtModulal.h"

#include "ivory/Circuit/Circuit.h"


namespace osuCrypto
{
    struct BitCount
    {
        u64 mBitCount;
        BitCount(const u64& b) : mBitCount(b) {}
    };



    class Runtime;
    class sIntBase;
    typedef uPtr<sIntBase> sIntBasePtr;
    class sIntBase
    {
    public:

        virtual ~sIntBase() {}

        typedef i64 ValueType;

        enum class Op
        {
            Add,
            Subtract,
            Multiply,
            Divide,
            LT,
            GTEq,
            Mod,
            And,
            Or,
            Not,
            BitwiseAnd,
            BitWiseOr,
            BitwiseNot,
            IfElse
        };

        virtual void copy(sIntBasePtr& b) = 0;
        virtual sIntBasePtr copy() = 0;
        virtual u64 bitCount() = 0;
        virtual Runtime& getRuntime() = 0;

        virtual sIntBasePtr add(sIntBasePtr& a, sIntBasePtr& b) = 0;
        virtual sIntBasePtr subtract(sIntBasePtr& a, sIntBasePtr& b) = 0;
        virtual sIntBasePtr multiply(sIntBasePtr& a, sIntBasePtr& b) = 0;
        virtual sIntBasePtr divide(sIntBasePtr& a, sIntBasePtr& b) = 0;

		virtual sIntBasePtr negate() = 0;
		virtual sIntBasePtr abs() = 0;

        virtual sIntBasePtr gteq(sIntBasePtr& a, sIntBasePtr& b) = 0;
        virtual sIntBasePtr gt(sIntBasePtr& a, sIntBasePtr& b) = 0;

        virtual sIntBasePtr bitwiseInvert() = 0;
        virtual sIntBasePtr bitwiseAnd(sIntBasePtr& a, sIntBasePtr& b) = 0;
        virtual sIntBasePtr bitwiseOr(sIntBasePtr& a, sIntBasePtr& b) = 0;

		virtual sIntBasePtr ifelse(sIntBasePtr& selectBit, sIntBasePtr& ifTrue, sIntBasePtr& ifFalse) = 0;
		virtual sIntBasePtr ifequal( sIntBasePtr& ifTrue, sIntBasePtr& ifFalse) = 0;

        virtual void reveal(u64 partyIdx) = 0;
        virtual void reveal(span<u64> partyIdxs) = 0;
        virtual ValueType getValue() = 0;
    };



    class sInt
    {
    public:
        typedef sIntBase::ValueType ValueType;

        //sInt(Runtime& rt, const BitCount& bitCount);

        sInt() = default;
        sInt(const sInt&) = default;
        sInt(sInt&&) = default;
        sInt(sIntBasePtr&& data) : mData(std::move(data)) {}

        sInt(const i64& val);
        sInt(const i32& val);
        sInt(const i16& val);
        sInt(const i8& val);

        ~sInt();

        sInt& operator=(const sInt&);
        sInt& operator=(sInt&&);

		//void bitwiseInvert11();

        sInt operator~();

        sInt operator+(const sInt&) const;
        sInt operator-(const sInt&) const;
        sInt operator*(const sInt&) const;
        sInt operator/(const sInt&) const;


        //sInt operator+(const i64&);
        //sInt operator-(const i64&);
        //sInt operator*(const i64&);
        //sInt operator/(const i64&);
        //friend sInt operator+(const sInt&, const i64&);
        //friend sInt operator-(const sInt&, const i64&);
        //friend sInt operator*(const sInt&, const i64&);
        //friend sInt operator/(const sInt&, const i64&);

        sInt& operator+=(const sInt&);
        //sInt operator-=(const sInt&);
        //sInt operator*=(const sInt&);
        //sInt operator/=(const sInt&);

        sInt operator>=(const sInt&);
        sInt operator>(const sInt&);
        sInt operator<=(const sInt&);
        sInt operator<(const sInt&);


        sInt operator&(const sInt&);

		sInt ifelse(const sInt&, const sInt&);
		sInt ifequal(const sInt&);

		sInt abs();


        ValueType getValue();


        void reveal(span<u64> partyIdxs);

        //BitVector valueToBV(const ValueType& val);
        //ValueType valueFromBV(const BitVector& val);
        


        sIntBasePtr mData;
        //Runtime& mRuntime;
        //GUI mGUI;
        //u64 mBitCount;
        //std::unique_ptr<RuntimeData> mData;
        //std::unique_ptr<std::future<BitVector>> mValFut;
        //BitVector mVal;
    };


}
#endif