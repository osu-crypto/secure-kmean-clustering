#include "CircuitLibrary.h"
#include "Gate.h"
#include <string>
namespace osuCrypto
{
    CircuitLibrary::CircuitLibrary()
    {
    }


    CircuitLibrary::~CircuitLibrary()
    {
    }

    BetaCircuit * osuCrypto::CircuitLibrary::int_int_add(u64 aSize, u64 bSize, u64 cSize)
    {
        auto key = "add" + std::to_string(aSize) + "x" + std::to_string(bSize) + "x" + std::to_string(cSize);

        auto iter = mCirMap.find(key);

        if (iter == mCirMap.end())
        {
            auto* cd = new BetaCircuit;

            BetaBundle a(aSize);
            BetaBundle b(bSize);
            BetaBundle c(cSize);
            BetaBundle t(3);

            cd->addInputBundle(a);
            cd->addInputBundle(b);

            cd->addOutputBundle(c);

            cd->addTempWireBundle(t);

            int_int_add_build(*cd, a, b, c, t);

            iter = mCirMap.insert(std::make_pair(key, cd)).first;
        }

        return iter->second;
    }





    BetaCircuit * CircuitLibrary::uint_uint_add(u64 aSize, u64 bSize, u64 cSize)
    {
        auto key = "uintAdd" + std::to_string(aSize) + "x" + std::to_string(bSize) + "x" + std::to_string(cSize);

        auto iter = mCirMap.find(key);

        if (iter == mCirMap.end())
        {
            auto* cd = new BetaCircuit;

            BetaBundle a(aSize);
            BetaBundle b(bSize);
            BetaBundle c(cSize);
            BetaBundle t(3);

            cd->addInputBundle(a);
            cd->addInputBundle(b);

            cd->addOutputBundle(c);

            cd->addTempWireBundle(t);

            uint_uint_add_build(*cd, a, b, c, t);

            iter = mCirMap.insert(std::make_pair(key, cd)).first;
        }

        return iter->second;
    }

    BetaCircuit * CircuitLibrary::int_intConst_add(
        u64 aSize,
        u64 bSize,
        i64 bVal,
        u64 cSize)
    {
        auto key = "add" + std::to_string(aSize) + "xConst" + std::to_string(bSize) + "v" + std::to_string(bVal) + "x" + std::to_string(cSize);

        auto iter = mCirMap.find(key);

        if (iter == mCirMap.end())
        {
            auto* cd = new BetaCircuit;

            BetaBundle a(aSize);
            BetaBundle b(bSize);
            BetaBundle c(cSize);
            BetaBundle t(3);

            cd->addInputBundle(a);

            BitVector bb((u8*)&bVal, bSize);
            cd->addConstBundle(b, bb);

            cd->addOutputBundle(c);

            cd->addTempWireBundle(t);

            int_int_add_build(*cd, a, b, c, t);

            iter = mCirMap.insert(std::make_pair(key, cd)).first;
        }

        return iter->second;
    }

    BetaCircuit * CircuitLibrary::int_int_subtract(u64 aSize, u64 bSize, u64 cSize)
    {
        auto key = "subtract" + std::to_string(aSize) + "x" + std::to_string(bSize) + "x" + std::to_string(cSize);

        auto iter = mCirMap.find(key);

        if (iter == mCirMap.end())
        {
            auto* cd = new BetaCircuit;

            BetaBundle a(aSize);
            BetaBundle b(bSize);
            BetaBundle c(cSize);
            BetaBundle t(3);

            cd->addInputBundle(a);
            cd->addInputBundle(b);

            cd->addOutputBundle(c);

            cd->addTempWireBundle(t);

            int_int_subtract_build(*cd, a, b, c, t);

            iter = mCirMap.insert(std::make_pair(key, cd)).first;
        }

        return iter->second;
    }

    BetaCircuit * CircuitLibrary::uint_uint_subtract(u64 aSize, u64 bSize, u64 cSize)
    {

        auto key = "uintSubtract" + std::to_string(aSize) + "x" + std::to_string(bSize) + "x" + std::to_string(cSize);

        auto iter = mCirMap.find(key);

        if (iter == mCirMap.end())
        {
            auto* cd = new BetaCircuit;

            BetaBundle a(aSize);
            BetaBundle b(bSize);
            BetaBundle c(cSize);
            BetaBundle t(3);

            cd->addInputBundle(a);
            cd->addInputBundle(b);

            cd->addOutputBundle(c);

            cd->addTempWireBundle(t);

            uint_uint_subtract_build(*cd, a, b, c, t);

            iter = mCirMap.insert(std::make_pair(key, cd)).first;
        }

        return iter->second;
    }

    BetaCircuit * CircuitLibrary::int_intConst_subtract(u64 aSize, u64 bSize, i64 bVal, u64 cSize)
    {
        auto key = "subtract" + std::to_string(aSize) + "xConst" + std::to_string(bSize) + "v" + std::to_string(bVal) + "x" + std::to_string(cSize);

        auto iter = mCirMap.find(key);

        if (iter == mCirMap.end())
        {
            auto* cd = new BetaCircuit;

            BetaBundle a(aSize);
            BetaBundle b(bSize);
            BetaBundle c(cSize);
            BetaBundle t(3);

            cd->addInputBundle(a);

            BitVector bb((u8*)&bVal, bSize);
            cd->addConstBundle(b, bb);

            cd->addOutputBundle(c);

            cd->addTempWireBundle(t);

            int_int_subtract_build(*cd, a, b, c, t);

            iter = mCirMap.insert(std::make_pair(key, cd)).first;
        }

        return iter->second;
    }

    BetaCircuit * CircuitLibrary::int_int_mult(u64 aSize, u64 bSize, u64 cSize)
    {
        auto key = "mult" + std::to_string(aSize) + "x" + std::to_string(bSize) + "x" + std::to_string(cSize);

        auto iter = mCirMap.find(key);

        if (iter == mCirMap.end())
        {
            auto* cd = new BetaCircuit;

            BetaBundle a(aSize);
            BetaBundle b(bSize);
            BetaBundle c(cSize);

            cd->addInputBundle(a);
            cd->addInputBundle(b);

            cd->addOutputBundle(c);

            int_int_mult_build(*cd, a, b, c);

            iter = mCirMap.insert(std::make_pair(key, cd)).first;
        }

        return iter->second;

    }

    BetaCircuit * CircuitLibrary::int_int_div(u64 aSize, u64 bSize, u64 cSize)
    {

        auto key = "div" + std::to_string(aSize) + "x" + std::to_string(bSize) + "x" + std::to_string(cSize);

        auto iter = mCirMap.find(key);

        if (iter == mCirMap.end())
        {
            auto* cd = new BetaCircuit;

            BetaBundle a(aSize);
            BetaBundle b(bSize);
            BetaBundle q(cSize);
            BetaBundle r(0);

            cd->addInputBundle(a);
            cd->addInputBundle(b);

            cd->addOutputBundle(q);
            //cd->addOutputBundle(r);

            int_int_div_rem_build(*cd, a, b, q, r);

            iter = mCirMap.insert(std::make_pair(key, cd)).first;
        }

        return iter->second;
    }

    BetaCircuit * CircuitLibrary::int_bitInvert(u64 aSize)
    {
        auto key = "bitInvert" + std::to_string(aSize);

        auto iter = mCirMap.find(key);

        if (iter == mCirMap.end())
        {
            auto* cd = new BetaCircuit;

            BetaBundle a(aSize);
            BetaBundle c(aSize);

            cd->addInputBundle(a);
            cd->addOutputBundle(c);

            int_bitInvert_build(*cd, a, c);

            iter = mCirMap.insert(std::make_pair(key, cd)).first;
        }

        return iter->second;
    }

    BetaCircuit * CircuitLibrary::int_int_bitwiseAnd(u64 aSize, u64 bSize, u64 cSize)
    {
        auto key = "bitwiseAnd" + std::to_string(aSize) + "x" + std::to_string(bSize) + "x" + std::to_string(cSize);

        auto iter = mCirMap.find(key);

        if (iter == mCirMap.end())
        {
            auto* cd = new BetaCircuit;

            BetaBundle a(aSize);
            BetaBundle b(bSize);
            BetaBundle c(cSize);

            cd->addInputBundle(a);
            cd->addInputBundle(b);

            cd->addOutputBundle(c);

            int_int_bitwiseAnd_build(*cd, a, b, c);

            iter = mCirMap.insert(std::make_pair(key, cd)).first;
        }

        return iter->second;
    }

    BetaCircuit * CircuitLibrary::int_int_bitwiseOr(u64 aSize, u64 bSize, u64 cSize)
    {
        auto key = "bitwiseOr" + std::to_string(aSize) + "x" + std::to_string(bSize) + "x" + std::to_string(cSize);

        auto iter = mCirMap.find(key);

        if (iter == mCirMap.end())
        {
            auto* cd = new BetaCircuit;

            BetaBundle a(aSize);
            BetaBundle b(bSize);
            BetaBundle c(cSize);

            cd->addInputBundle(a);
            cd->addInputBundle(b);

            cd->addOutputBundle(c);

            int_int_bitwiseOr_build(*cd, a, b, c);

            iter = mCirMap.insert(std::make_pair(key, cd)).first;
        }

        return iter->second;
    }

    BetaCircuit * CircuitLibrary::int_int_lt(u64 aSize, u64 bSize)
    {
        auto key = "lessThan" + std::to_string(aSize) + "x" + std::to_string(bSize);

        auto iter = mCirMap.find(key);

        if (iter == mCirMap.end())
        {
            auto* cd = new BetaCircuit;

            BetaBundle a(aSize);
            BetaBundle b(bSize);
            BetaBundle c(1);

            cd->addInputBundle(a);
            cd->addInputBundle(b);
            cd->addOutputBundle(c);

            int_int_lt_build(*cd, a, b, c);

            iter = mCirMap.insert(std::make_pair(key, cd)).first;
        }

        return iter->second;
    }


	BetaCircuit* CircuitLibrary::int_int_equal(u64 aSize, u64 bSize)
	{
		auto key = "lessThan" + std::to_string(aSize) + "x" + std::to_string(bSize);

		auto iter = mCirMap.find(key);

		if (iter == mCirMap.end())
		{
			auto* cd = new BetaCircuit;

			BetaBundle a(aSize);
			BetaBundle b(bSize);
			BetaBundle c(1);

			cd->addInputBundle(a);
			cd->addInputBundle(b);
			cd->addOutputBundle(c);

			int_int_equal_build(*cd, a, b, c);

			iter = mCirMap.insert(std::make_pair(key, cd)).first;
		}

		return iter->second;
	}

    BetaCircuit * CircuitLibrary::int_int_gteq(u64 aSize, u64 bSize)
    {
        auto key = "greatThanEq" + std::to_string(aSize) + "x" + std::to_string(bSize);

        auto iter = mCirMap.find(key);

        if (iter == mCirMap.end())
        {
            auto* cd = new BetaCircuit;

            BetaBundle a(aSize);
            BetaBundle b(bSize);
            BetaBundle c(1);

            cd->addInputBundle(a);
            cd->addInputBundle(b);
            cd->addOutputBundle(c);

            int_int_gteq_build(*cd, a, b, c);

            iter = mCirMap.insert(std::make_pair(key, cd)).first;
        }

        return iter->second;
    }

    BetaCircuit * CircuitLibrary::uint_uint_lt(u64 aSize, u64 bSize)
    {
        auto key = "uintLessThan" + std::to_string(aSize) + "x" + std::to_string(bSize);
        auto iter = mCirMap.find(key);

        if (iter == mCirMap.end())
        {
            auto* cd = new BetaCircuit;

            BetaBundle a(aSize);
            BetaBundle b(bSize);
            BetaBundle c(1);

            cd->addInputBundle(a);
            cd->addInputBundle(b);
            cd->addOutputBundle(c);

            uint_uint_lt_build(*cd, a, b, c);

            iter = mCirMap.insert(std::make_pair(key, cd)).first;
        }

        return iter->second;
    }

    BetaCircuit * CircuitLibrary::uint_uint_gteq(u64 aSize, u64 bSize)
    {
        auto key = "uintGreatThanEq" + std::to_string(aSize) + "x" + std::to_string(bSize);
        auto iter = mCirMap.find(key);

        if (iter == mCirMap.end())
        {
            auto* cd = new BetaCircuit;

            BetaBundle a(aSize);
            BetaBundle b(bSize);
            BetaBundle c(1);

            cd->addInputBundle(a);
            cd->addInputBundle(b);
            cd->addOutputBundle(c);

            uint_uint_gteq_build(*cd, a, b, c);

            iter = mCirMap.insert(std::make_pair(key, cd)).first;
        }

        return iter->second;
    }

    BetaCircuit * CircuitLibrary::int_int_multiplex(u64 aSize)
    {

        auto key = "multiplex" + std::to_string(aSize);

        auto iter = mCirMap.find(key);

        if (iter == mCirMap.end())
        {
            auto* cd = new BetaCircuit;

            BetaBundle a(aSize);
            BetaBundle b(aSize);
            BetaBundle c(1);
            BetaBundle d(aSize);
            BetaBundle t(3);

            cd->addInputBundle(a);
            cd->addInputBundle(b);
            cd->addInputBundle(c);
            cd->addOutputBundle(d);
            cd->addTempWireBundle(t);

            int_int_multiplex_build(*cd, a, b, c, d, t);

            iter = mCirMap.insert(std::make_pair(key, cd)).first;
        }

        return iter->second;
    }

    BetaCircuit * CircuitLibrary::int_removeSign(u64 aSize)
    {
        auto key = "removeSign" + std::to_string(aSize);
        auto iter = mCirMap.find(key);
        if (iter == mCirMap.end())
        {
            auto* cd = new BetaCircuit;

            BetaBundle a(aSize);
            BetaBundle c(aSize);
            BetaBundle temp(3);

            cd->addInputBundle(a);
            cd->addOutputBundle(c);
            cd->addTempWireBundle(temp);

            int_removeSign_build(*cd, a, c, temp);

            iter = mCirMap.insert(std::make_pair(key, cd)).first;
        }

        return iter->second;
    }

    BetaCircuit * CircuitLibrary::int_addSign(u64 aSize)
    {
        auto key = "addSign" + std::to_string(aSize);
        auto iter = mCirMap.find(key);
        if (iter == mCirMap.end())
        {
            auto* cd = new BetaCircuit;

            BetaBundle a(aSize);
            BetaBundle c(aSize);
            BetaBundle sign(1);
            BetaBundle temp(3);

            cd->addInputBundle(a);
            cd->addInputBundle(sign);
            cd->addOutputBundle(c);
            cd->addTempWireBundle(temp);

            int_addSign_build(*cd, a, sign, c, temp);

            iter = mCirMap.insert(std::make_pair(key, cd)).first;
        }

        return iter->second;
    }

    BetaCircuit * CircuitLibrary::int_negate(u64 aSize)
    {
        auto key = "negate" + std::to_string(aSize);
        auto iter = mCirMap.find(key);
        if (iter == mCirMap.end())
        {
            auto* cd = new BetaCircuit;

            BetaBundle a(aSize);
            BetaBundle c(aSize);
            BetaBundle temp(3);

            cd->addInputBundle(a);
            cd->addOutputBundle(c);
            cd->addTempWireBundle(temp);

            int_negate_build(*cd, a, c, temp);

            iter = mCirMap.insert(std::make_pair(key, cd)).first;
        }

        return iter->second;
    }


    void CircuitLibrary::int_int_add_build(
        BetaCircuit& cd,
        BetaBundle & a1,
        BetaBundle & a2,
        BetaBundle & sum,
        BetaBundle & temps)
    {

        if (temps.mWires.size() < 3)
            throw std::runtime_error(LOCATION);

        if (sum.mWires.size() > std::max<u64>(a1.mWires.size(), a2.mWires.size()) + 1)
            throw std::runtime_error(LOCATION);

        BetaWire& carry = temps.mWires[0];
        BetaWire& aXorC = temps.mWires[1];
        BetaWire& temp = temps.mWires[2];

        if (!areDistint(a2, sum) || !areDistint(a1, sum))
            throw std::runtime_error("must be distinct" LOCATION);

        u64 a1Size = a1.mWires.size();
        u64 a2Size = a2.mWires.size();
        u64 minSize = sum.mWires.size();

        // sum is computed as a1[i] ^ a2[i] ^ carry[i-1]
        // carry[i] is computed as
        //
        //  carry[i-1] -*--*--------------------*
        //              |  |                    |
        //              |  >= xor ---*          >= xor --- carry[i]
        //              |  |         |          |
        //  a2[i] ------|--*         >== and ---*
        //              |            |
        //              >==== xor ---*
        //              |            
        //  a1[i] ------*

        // half adder
        cd.addGate(a1.mWires[0], a2.mWires[0], GateType::Xor, sum.mWires[0]);

        // now do the full adder while we have inputs from both a1,a2
        u64 i = 1;
        if (minSize > 1)
        {

            // compute the carry from the 0 bits (special case)
            cd.addGate(a1.mWires[i - 1], a2.mWires[i - 1], GateType::And, carry);

            u64 a1Idx = std::min<u64>(i, a1Size - 1);
            u64 a2Idx = std::min<u64>(i, a2Size - 1);

            // compute the sum
            cd.addGate(a1.mWires[a1Idx], carry, GateType::Xor, aXorC);
            cd.addGate(a2.mWires[a2Idx], aXorC, GateType::Xor, sum.mWires[i]);

            // general case.
            for (i = 2; i < minSize; ++i)
            {
                // compute the previous carry
                cd.addGate(a2.mWires[a2Idx], carry, GateType::Xor, temp);
                cd.addGate(temp, aXorC, GateType::And, temp);
                cd.addGate(temp, carry, GateType::Xor, carry);


                a1Idx = std::min<u64>(i, a1Size - 1);
                a2Idx = std::min<u64>(i, a2Size - 1);

                cd.addGate(a1.mWires[a1Idx], carry, GateType::Xor, aXorC);
                cd.addGate(a2.mWires[a2Idx], aXorC, GateType::Xor, sum.mWires[i]);
            }
        }

    }

    void CircuitLibrary::uint_uint_add_build(
        BetaCircuit & cd,
        BetaBundle & a1,
        BetaBundle & a2,
        BetaBundle & sum,
        BetaBundle & temps)
    {
        if (sum.mWires.size() > std::max<u64>(a1.mWires.size(), a2.mWires.size()) + 1)
            throw std::runtime_error(LOCATION);

        BetaBundle extra(2);
        cd.addConstBundle(extra, BitVector(2));

        BetaBundle aa1 = a1;
        BetaBundle aa2 = a2;

        aa1.mWires.push_back(extra.mWires[0]);
        aa2.mWires.push_back(extra.mWires[1]);

        int_int_add_build(cd, aa1, aa2, sum, temps);
    }

    void CircuitLibrary::int_int_subtract_build(
        BetaCircuit & cd,
        BetaBundle & a1,
        BetaBundle & a2,
        BetaBundle & diff,
        BetaBundle & temps)
    {
        if (diff.mWires.size() > std::max<u64>(a1.mWires.size(), a2.mWires.size()) + 1)
            throw std::runtime_error(LOCATION);


        if (!areDistint(a2, diff) || !areDistint(a1, diff))
            throw std::runtime_error("must be distinct " LOCATION);

        u64 a1Size = a1.mWires.size();
        u64 a2Size = a2.mWires.size();
        u64 minSize = diff.mWires.size();

        BetaWire borrow = temps.mWires[0];
        BetaWire aXorBorrow = temps.mWires[1];
        BetaWire temp = temps.mWires[2];
        std::vector<BetaWire>& d = diff.mWires;

        // we are computing a1 - a2 = diff
        // diff is computed as a1[i] ^ a2[i] ^ borrow[i-1]
        // borrow[i] is computed as
        //
        //  a1[i] ------*--*-------------------*
        //              |  |                   |
        //              |  >= xor ---*         >= xor --- borrow[i]
        //              |  |         |         |
        //  a2[i] ------|--*          >= or ---*
        //              |            |
        //              >==== xor ---*
        //              |  
        // borrow[i-1] -*

        u64 i = 0;
        if (minSize)
        {
            cd.addGate(a1.mWires[0], a2.mWires[0], GateType::Xor, diff.mWires[0]);
            ++i;

            if (minSize > 1)
            {
                cd.addGate(a1.mWires[0], a2.mWires[0], GateType::na_And, borrow);

                u64 a1Idx = std::min<u64>(1, a1Size - 1);
                u64 a2Idx = std::min<u64>(1, a2Size - 1);

                // second bit is the xor of borrow and input;
                cd.addGate(borrow, a1.mWires[a1Idx], GateType::Xor, aXorBorrow);
                cd.addGate(aXorBorrow, a2.mWires[a2Idx], GateType::Xor, d[1]);
                ++i;

                for (; i < minSize; ++i)
                {
                    // compute the borrow of the previous bit which itself has a borrow in.
                    cd.addGate(a1.mWires[a1Idx], a2.mWires[a2Idx], GateType::Xor, temp);
                    cd.addGate(aXorBorrow, temp, GateType::Or, temp);
                    cd.addGate(temp, a1.mWires[a1Idx], GateType::Xor, borrow);

                    a1Idx = std::min<u64>(i, a1Size - 1);
                    a2Idx = std::min<u64>(i, a2Size - 1);

                    // compute the difference as the xor of the input and prev borrow.
                    cd.addGate(borrow, a1.mWires[a1Idx], GateType::Xor, aXorBorrow);
                    cd.addGate(aXorBorrow, a2.mWires[a2Idx], GateType::Xor, d[i]);
                }
            }
        }
    }

    void CircuitLibrary::uint_uint_subtract_build(
        BetaCircuit & cd,
        BetaBundle & a1,
        BetaBundle & a2,
        BetaBundle & diff,
        BetaBundle & temps)
    {

        if (diff.mWires.size() > std::max<u64>(a1.mWires.size(), a2.mWires.size()) + 1)
            throw std::runtime_error(LOCATION);

        BetaBundle extra(2);
        cd.addConstBundle(extra, BitVector(2));

        BetaBundle aa1 = a1;
        BetaBundle aa2 = a2;

        aa1.mWires.push_back(extra.mWires[0]);
        aa2.mWires.push_back(extra.mWires[1]);

        int_int_subtract_build(cd, aa1, aa2, diff, temps);
    }

    void CircuitLibrary::int_int_mult_build(
        BetaCircuit & cd,
        BetaBundle & a,
        BetaBundle & b,
        BetaBundle & c)
    {

        if (c.mWires.size() > a.mWires.size() + b.mWires.size())
            throw std::runtime_error(LOCATION);

        if (a.mWires.size() < b.mWires.size())
        {
            int_int_mult_build(cd, b, a, c);
            return;
        }

        u64 numRows = c.mWires.size();


        // rows will hold
        // {  b[0] * a ,
        //    b[1] * a ,
        //    ...      ,
        //    b[n] * a }
        // where row i contains min(c.mWires.size() - i, a.mWires.size())
        std::vector<BetaBundle> rows(numRows);


        // first, we compute the AND between the two inputs.
        for (u64 i = 0; i < rows.size(); ++i)
        {

            // this will hold the b[i] * a
            rows[i].mWires.resize(std::min(static_cast<size_t>(c.mWires.size() - i), static_cast<size_t>(a.mWires.size())));

            // initialize some unused wires, these will
            // hold intermediate sums.
            cd.addTempWireBundle(rows[i]);

            if (i == 0)
            {
                // later, we will sum together all the 
                // rows, and this row at idx 0 will be 
                // the running total, so we want it to be 
                // the wires that represent the product c.
                rows[0].mWires[0] = c.mWires[0];
            }

            if (rows.size() == 1)
            {
                for (u64 j = 1; j < rows[0].mWires.size(); ++j)
                {
                    rows[0].mWires[j] = c.mWires[j];
                }
            }

            if (a.mWires.size() == 1)
            {
                rows[i].mWires[0] = c.mWires[i];
            }

            const BetaWire& bi = b.mWires[std::min(static_cast<size_t>(i), static_cast<size_t>(b.mWires.size() - 1))];

            u64 prev = cd.mNonXorGateCount;
            // compute the AND between b[i] * a[j].
            for (u64 j = 0; j < rows[i].mWires.size(); ++j)
            {
                cd.addGate(
                    bi,
                    a.mWires[j],
                    GateType::And,
                    rows[i].mWires[j]);
            }

            //std::cout << "and[" << i << "] " << cd.mNonXorGateCount <<"  (+"<< (cd.mNonXorGateCount - prev) <<")" << std::endl;
        }

#define SERIAL
#ifdef SERIAL
        if (rows.size() > 1)
        {

            BetaBundle additonTemp(3), temp2(rows[1].mWires.size());
            cd.addTempWireBundle(additonTemp);
            cd.addTempWireBundle(temp2);
            //cd.addPrint("+");
            //cd.addPrint(rows[0]);
            //cd.addPrint("\n");

            rows[0].mWires.erase(rows[0].mWires.begin());

            // starting with rows[0] + rows[1], sum the rows together
            // note that, after each sum, we will have computed one more
            // bit of the final product.
            for (u64 i = 1; i < rows.size(); i++)
            {
                BetaBundle sum(std::min(static_cast<size_t>(rows[i].mWires.size() + 1), static_cast<size_t>(c.mWires.size() - i)));


                //cd.addPrint("+");
                //cd.addPrint(std::string(i, ' '));
                //cd.addPrint(rows[i]);
                //cd.addPrint("\n-----------------------------------------------------------------" + std::to_string(i) + " / " + std::to_string(b.mWires.size())+"  ");
                //cd.addPrint(b.mWires[std::min(i, b.mWires.size() - 1)]);
                //cd.addPrint("\n " + std::string(i, ' '));

                cd.addTempWireBundle(sum);

                sum.mWires[0] = c.mWires[i];

                if (i == rows.size() - 1)
                {
                    for (u64 j = 1; j < sum.mWires.size(); ++j)
                    {
                        sum.mWires[j] = c.mWires[i + j];
                    }
                }

                u64 prev = cd.mNonXorGateCount;

                int_int_add_build(cd, rows[i - 1], rows[i], sum, additonTemp);

                //std::cout << "add[" << i << "] " << cd.mNonXorGateCount << "  (+" << (cd.mNonXorGateCount - prev) << ")" << std::endl;

                //cd.addPrint(sum);
                //cd.addPrint("\n ");
                //cd.addPrint(c);
                //cd.addPrint("\n");

                rows[i].mWires.clear();
                rows[i].mWires.insert(rows[i].mWires.begin(), sum.mWires.begin() + 1, sum.mWires.end());
            }
        }


        //cd.addPrint("=");
        //cd.addPrint(c);
        //cd.addPrint("\n\n");
#else
        this code has not been tested and surely contains errors

            // while the serial code above should work, it is more sequential. 
            // as such, then using the 'leveled' presentation, fewer operations
            // can be pipelined. 

            u64 k = 1, p = 1;
        while (rows.size() > 1)
        {
            std::vector<BetaBundle> newTerms;


            for (u64 i = 0; i < rows.size(); i += 2)
            {
                BetaBundle additonTemp(3);
                cd.addTempWireBundle(additonTemp);

                newTerms.emplace_back(rows[i + 1].mWires.size());
                auto& prod = newTerms.back();
                cd.addTempWireBundle(prod);

                if (i == 0)
                {
                    for (u64 j = 0; j < k; ++j)
                    {
                        prod.mWires[j] = c.mWires[p++];
                    }

                    k *= 2;
                }

                auto sizeDiff = rows[i].mWires.size() - rows[i + 1].mWires.size();

                std::vector<BetaWire> bottomBits(
                    rows[i].mWires.begin(),
                    rows[i].mWires.begin() + sizeDiff);

                rows[i].mWires.erase(
                    rows[i].mWires.begin(),
                    rows[i].mWires.begin() + sizeDiff);

                int_int_add_build(cd, rows[i], rows[i + 1], prod, additonTemp);

                prod.mWires.insert(prod.mWires.begin(), bottomBits.begin(), bottomBits.end());
            }

            rows = std::move(newTerms);
        }

#endif
        cd.levelize();
    }
    void CircuitLibrary::int_int_div_rem_build(
        BetaCircuit & cd,
        BetaBundle & signedA1,
        BetaBundle & signedA2,
        BetaBundle & quotient,
        BetaBundle & rem
        //,BetaBundle & divByZero,
        //bool checkDivByZero
    )
    {
        if (quotient.mWires.size() != signedA1.mWires.size())
            throw std::runtime_error(LOCATION);

        // we are computing a1 / a2 = quot  with optional remainder rem
        BetaBundle
            a1Sign(1),
            a2Sign(1),
            sign(1),
            temp(3),
            a1(signedA1.mWires.size()),
            a2(signedA2.mWires.size());

        a1Sign.mWires[0] = signedA1.mWires.back();
        a2Sign.mWires[0] = signedA2.mWires.back();

        cd.addTempWireBundle(sign);
        cd.addTempWireBundle(temp);
        cd.addTempWireBundle(a1);
        cd.addTempWireBundle(a2);

        cd.addGate(a1Sign.mWires.back(), a2Sign.mWires.back(), GateType::Xor, sign.mWires[0]);

        //std::cout << "start      " << cd.mNonXorGateCount << std::endl;

        // a1 = abs(signedA1)
        int_removeSign_build(cd, signedA1, a1, temp);
        //std::cout << "removeSign " << cd.mNonXorGateCount << std::endl;
        int_removeSign_build(cd, signedA2, a2, temp);
        //std::cout << "removeSign " << cd.mNonXorGateCount << std::endl;


        //cd.addPrint(quotient);
        //cd.addPrint("\n");


        BetaBundle remainder(rem.mWires.size());
        cd.addTempWireBundle(remainder);

        uint_uint_div_rem_build(cd, a1, a2, quotient, remainder);

        //cd.addPrint("add quo sign ");
        //cd.addPrint(sign);
        //cd.addPrint("   ");
        //cd.addPrint(quotient);


        int_addSign_build(cd, quotient, sign, quotient, temp);
        //std::cout << "addSign    " << cd.mNonXorGateCount << std::endl;
        //cd.addPrint(" ->  ");
        //cd.addPrint(quotient);

        //cd.addPrint("\n\n");

        if (rem.mWires.size())
        {
            int_addSign_build(cd, remainder, a1Sign, rem, temp);
            //std::cout << "addSign    " << cd.mNonXorGateCount << std::endl;
        }
        //cd.print(" = ", remainder);

    }

    void CircuitLibrary::uint_uint_div_rem_build(
        BetaCircuit & cd,
        BetaBundle & a1,
        BetaBundle & a2,
        BetaBundle & quotient,
        BetaBundle & rem)
    {
        BetaBundle
            doSubtract(1),
            temp(3),
            ssub(a1.mWires.size());

        cd.addTempWireBundle(ssub);
        cd.addTempWireBundle(temp);


        u64 shifts = quotient.mWires.size() - 1;


        BetaBundle xtra(shifts + 1);
        cd.addTempWireBundle(xtra);


        BetaBundle remainder, remTemp;
        //cd.addPrint("====================================\na1 = ");
        //cd.addPrint(a1);
        //cd.addPrint("\na2 = ");
        //cd.addPrint(a2);
        //cd.addPrint("\n");

        for (i64 i = shifts; i >= 0; --i)
        {
            remainder.mWires.insert(remainder.mWires.begin(), a1.mWires[i]);
            remTemp.mWires.push_back(xtra.mWires.back());
            xtra.mWires.pop_back();

            //partialrem.push_back(remainder);
            //auto doSubtract = remainder >= a2;
            doSubtract.mWires[0] = quotient.mWires[i];
            u64 prev = cd.mNonXorGateCount;

            uint_uint_gteq_build(cd, remainder, a2, doSubtract);


            //std::cout << "iter[" << i << "]  geq  " << cd.mNonXorGateCount << "  (+" << (cd.mNonXorGateCount - prev) << ")  " << remTemp.mWires.size() << std::endl;

            //cd.addPrint("rem[" + std::to_string(i) + "] = ");
            //cd.addPrint(remainder);
            //cd.addPrint("\n");
            //cd.addPrint(remainder);
            //cd.addPrint(" >= ");
            //cd.addPrint(a2);
            //cd.addPrint(" =: ");
            //cd.addPrint(doSubtract);
            //cd.addPrint("\n");



            //prev = cd.mNonXorGateCount;

            BetaBundle sub;
            sub.mWires.insert(sub.mWires.begin(), ssub.mWires.begin(), ssub.mWires.begin() + std::min(a2.mWires.size(), remainder.mWires.size()));

            //for (auto& wire : a2.mWires)
            for (u64 j = 0; j < sub.mWires.size(); ++j)
                cd.addGate(a2.mWires[j], doSubtract.mWires[0], GateType::And, sub.mWires[j]);



            //cd.addPrint(" ( rem[" + std::to_string(i) + "] = ");
            //cd.addPrint(remainder);
            //cd.addPrint(") - (sub[" + std::to_string(i) + "] = ");
            //cd.addPrint(sub);


            //if (cd.mDivPrint)
            //{

            //    cd.addPrint(remainder);
            //    cd.addPrint(" - ");
            //    cd.addPrint(a2);
            //    cd.addPrint("\n");
            //}
            //remainder = remainder - sub;
            //std::cout << "iter[" << i << "]'   " << cd.mNonXorGateCount << "  " << remTemp.mWires.size() << std::endl;

            //prev = cd.mNonXorGateCount;

            uint_uint_subtract_build(cd, remainder, sub, remTemp, temp);


            //std::cout << "iter[" << i << "]  sub  " << cd.mNonXorGateCount << "  (+" << (cd.mNonXorGateCount-prev)<<")  "<< remTemp .mWires.size()<< std::endl;


            std::swap(remTemp.mWires, remainder.mWires);

            //if (cd.mDivPrint)
            //{

                //cd.addPrint(") =: ");
                //cd.addPrint(remainder);
                //cd.addPrint("     quo " );
                //cd.addPrint(quotient);
                //cd.addPrint("\n\n");
            //}


        }
    }

    void CircuitLibrary::int_int_lt_build(
        BetaCircuit & cd,
        BetaBundle & a1,
        BetaBundle & a2,
        BetaBundle & out)
    {

        TODO("optimize this, we dont need the full subtraction result, only the sign");

        auto bits = std::max(a1.mWires.size(), a2.mWires.size());
        BetaBundle diff(bits + 1), temp(3);
        cd.addTempWireBundle(temp);

        for (u64 i = 0; i < diff.mWires.size(); ++i)
        {
            diff.mWires[i] = out.mWires[0];
        }

        int_int_subtract_build(cd, a1, a2, diff, temp);

    }

	void CircuitLibrary::int_int_equal_build(
		BetaCircuit & cd,
		BetaBundle & a1,
		BetaBundle & a2,
		BetaBundle & out)
	{

		TODO("optimize this, we dont need the full subtraction result, only the sign");

		auto bits = std::max(a1.mWires.size(), a2.mWires.size());
		BetaBundle diff(bits + 1), temp(3);
		cd.addTempWireBundle(temp);

		for (u64 i = 0; i < diff.mWires.size(); ++i)
		{
			diff.mWires[i] = out.mWires[0];
		}

		int_removeSign_build(cd, a1, a1, temp);
		int_removeSign_build(cd, a2, a2, temp);
		int_int_subtract_build(cd, a1, a2, diff, temp);

	}


    void CircuitLibrary::int_int_gteq_build(
        BetaCircuit & cd,
        BetaBundle & a1,
        BetaBundle & a2,
        BetaBundle & out)
    {
        int_int_lt_build(cd, a1, a2, out);

        // invert the output
        GateType gt = GateType((~(u8)cd.mGates.back().mType) & 15);
        cd.mGates.back().setType(gt);
    }

    void CircuitLibrary::uint_uint_lt_build(
        BetaCircuit & cd,
        BetaBundle & a1,
        BetaBundle & a2,
        BetaBundle & out)
    {

        TODO("optimize this, we dont need the full subtraction result, only the sign");

        auto bits = std::max(a1.mWires.size(), a2.mWires.size());
        BetaBundle diff(bits + 1), temp(3);
        cd.addTempWireBundle(temp);

        for (u64 i = 0; i < diff.mWires.size(); ++i)
        {
            diff.mWires[i] = out.mWires[0];
        }

        uint_uint_subtract_build(cd, a1, a2, diff, temp);

    }

    void CircuitLibrary::uint_uint_gteq_build(
        BetaCircuit & cd,
        BetaBundle & a1,
        BetaBundle & a2,
        BetaBundle & out)
    {
        uint_uint_lt_build(cd, a1, a2, out);

        // invert the output
        cd.addInvert(out.mWires[0]);
    }


    void CircuitLibrary::int_removeSign_build(
        BetaCircuit & cd,
        BetaBundle & a1,
        BetaBundle & ret,
        BetaBundle & temp)
    {

        BetaBundle sign(1);
        sign.mWires[0] = a1.mWires.back();

        //auto ret = -a1;
        int_negate_build(cd, a1, ret, temp);

        int_int_multiplex_build(cd, ret, a1, sign, ret, temp);
    }

    void CircuitLibrary::int_addSign_build(
        BetaCircuit & cd,
        BetaBundle & a1,
        BetaBundle & sign,
        BetaBundle & ret,
        BetaBundle & temp)
    {
        //auto ret = -a1;
        //cd.addPrint("\nadd sign ");
        //cd.addPrint(sign);
        //cd.addPrint("  (");
        //cd.addPrint(a1);

        BetaBundle neg(a1.mWires.size());
        cd.addTempWireBundle(neg);

        int_negate_build(cd, a1, neg, temp);

        //cd.addPrint(", ");
        //cd.addPrint(neg);
        //cd.addPrint(")  -> ");

        int_int_multiplex_build(cd, neg, a1, sign, ret, temp);

        //cd.addPrint(ret);
        //cd.addPrint("\n");
    }

    void CircuitLibrary::int_bitInvert_build(
        BetaCircuit & cd,
        BetaBundle & a1,
        BetaBundle & out)
    {
        cd.addCopy(a1, out);

        for (u64 i = 0; i < out.mWires.size(); ++i)
        {
            cd.addInvert(out.mWires[i]);
        }
    }

    void CircuitLibrary::int_negate_build(
        BetaCircuit & cd,
        BetaBundle & a1,
        BetaBundle & out,
        BetaBundle & temp)
    {
        //if(areDistint(a1, out) == false)
        //    throw std::runtime_error(LOCATION);
        // for two's complement, negation is done as out = ~a1 + 1
        BetaBundle invert(a1.mWires.size());
        cd.addTempWireBundle(invert);

        int_bitInvert_build(cd, a1, invert);

        //cd.addPrint("   a1 ");
        //cd.addPrint(a1);
        //cd.addPrint("\n ~a1 ");
        //cd.addPrint(invert);

        BetaBundle one(2);
        BitVector oo(2);
        oo[0] = 1;
        cd.addConstBundle(one, oo);


        int_int_add_build(cd, invert, one, out, temp);
        //cd.addPrint("   ~a1+1 ");
        //cd.addPrint(out);
        //cd.addPrint(" ");
    }

    void CircuitLibrary::int_int_bitwiseAnd_build(
        BetaCircuit & cd,
        BetaBundle & a1,
        BetaBundle & a2,
        BetaBundle & out)
    {
        if (a1.mWires.size() != a2.mWires.size())throw std::runtime_error(LOCATION);
        if (out.mWires.size() > a1.mWires.size())throw std::runtime_error(LOCATION);

        for (u64 j = 0; j < out.mWires.size(); ++j)
        {
            cd.addGate(
                a1.mWires[j],
                a2.mWires[j],
                GateType::And,
                out.mWires[j]);
        }

    }

    void CircuitLibrary::int_int_bitwiseOr_build(BetaCircuit & cd, BetaBundle & a1, BetaBundle & a2, BetaBundle & out)
    {
        if (a1.mWires.size() != a2.mWires.size())throw std::runtime_error(LOCATION);
        if (out.mWires.size() > a1.mWires.size())throw std::runtime_error(LOCATION);

        for (u64 j = 0; j < out.mWires.size(); ++j)
        {
            cd.addGate(
                a1.mWires[j],
                a2.mWires[j],
                GateType::Or,
                out.mWires[j]);
        }
    }


    void CircuitLibrary::int_int_multiplex_build(
        BetaCircuit & cd,
        BetaBundle & a1,
        BetaBundle & a2,
        BetaBundle & choice,
        BetaBundle & out,
        BetaBundle & temp)
    {
        // multiplex them together as (a ^ b) & s ^ a
        for (u64 i = 0; i < out.mWires.size(); ++i)
        {
            cd.addGate(a2.mWires[i], a1.mWires[i], GateType::Xor, temp.mWires[0]);
            //cd.addPrint("a^b  [" + std::to_string(i) + "] = ");
            //cd.addPrint(temp.mWires[0]);
            //cd.addPrint("\n");

            cd.addGate(temp.mWires[0], choice.mWires[0], GateType::And, temp.mWires[0]);

            //cd.addPrint("a^b&s[" + std::to_string(i) + "] = ");
            //cd.addPrint(temp.mWires[0]);
            //cd.addPrint("\n");

            cd.addGate(a2.mWires[i], temp.mWires[0], GateType::Xor, out.mWires[i]);
        }
    }
   
	
	

	
	bool CircuitLibrary::areDistint(BetaBundle & a1, BetaBundle & a2)
    {
        for (u64 i = 0; i < a1.mWires.size(); ++i)
        {
            if (std::find(a2.mWires.begin(), a2.mWires.end(), a1.mWires[i]) != a2.mWires.end())
                return false;
        }
        return true;
    }
}