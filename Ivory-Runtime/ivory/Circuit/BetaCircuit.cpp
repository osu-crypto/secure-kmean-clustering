#include "BetaCircuit.h"
#include <vector>
#include <unordered_map>
#include "cryptoTools/Common/BitVector.h"
namespace osuCrypto
{

    BetaCircuit::BetaCircuit()
        :mNonXorGateCount(0),
        mWireCount(0)
    {
    }



    BetaCircuit::~BetaCircuit()
    {
    }

    void BetaCircuit::addTempWireBundle(BetaBundle & in)
    {
        for (u64 i = 0; i < in.mWires.size(); ++i)
        {
            in.mWires[i] = mWireCount++;
        }

        mWireFlags.resize(mWireCount, BetaWireFlag::Wire);
    }

    void BetaCircuit::addInputBundle(BetaBundle & in)
    {
        for (u64 i = 0; i < in.mWires.size(); ++i)
        {
            in.mWires[i] = mWireCount++;
        }
        mWireFlags.resize(mWireCount, BetaWireFlag::Wire);

        mInputs.push_back(in);
    }


    void BetaCircuit::addOutputBundle(BetaBundle & out)
    {
        for (u64 i = 0; i < out.mWires.size(); ++i)
        {
            out.mWires[i] = mWireCount++;
        }
        mWireFlags.resize(mWireCount, BetaWireFlag::Wire);

        mOutputs.push_back(out);
    }

    void BetaCircuit::addConstBundle(BetaBundle & in, const BitVector& val)
    {
        mWireFlags.resize(mWireCount + in.mWires.size(), BetaWireFlag::Wire);

        for (u64 i = 0; i < in.mWires.size(); ++i)
        {
            in.mWires[i] = mWireCount++;
            mWireFlags[in.mWires[i]] = val[i] ? BetaWireFlag::One : BetaWireFlag::Zero;
        }
    }


    GateType invertInputWire(u64 wirePosition, const GateType& oldGateType)
    {
        if (wirePosition == 0)
        {
            // swap bit 0/1 and 2/3
            auto s = u8(oldGateType);

            return GateType(
                (s & 1) << 1 | // bit 0 -> bit 1
                (s & 2) >> 1 | // bit 1 -> bit 0
                (s & 4) << 1 | // bit 3 -> bit 4
                (s & 8) >> 1); // bit 4 -> bit 3
        }
        else if (wirePosition == 1)
        {
            // swap bit (0,1)/(2,3)
            auto s = u8(oldGateType);

            return GateType(
                (s & 3) << 2 |  // bits (0,1) -> bits (2,3)
                (s & 12) >> 2); // bits (2,3) -> bits (0,1)
        }
        else
            throw std::runtime_error("");
    }

    void BetaCircuit::addGate(
        BetaWire aIdx,
        BetaWire bIdx,
        GateType gt,
        BetaWire out)
    {
        if (gt == GateType::a ||
            gt == GateType::b ||
            gt == GateType::na ||
            gt == GateType::nb ||
            gt == GateType::One ||
            gt == GateType::Zero)
            throw std::runtime_error("");


        auto
            constA = isConst(aIdx),
            constB = isConst(bIdx);


        if (constA || constB)
        {
            if (constA && constB)
            {
                u8 val = GateEval(gt, constVal(aIdx) != 0, constVal(bIdx) != 0);
                addConst(out, val);
            }
            else
            {
                u8 subgate;
                const BetaWire* wireIdx;

                if (constB)
                {
                    wireIdx = &aIdx;
                    subgate = u8(gt) >> (2 * constVal(bIdx)) & 3;
                }
                else
                {
                    wireIdx = &bIdx;
                    u8 g = static_cast<u8>(gt);

                    auto val = constVal(aIdx);
                    subgate = val
                        ? ((g & 2) >> 1) | ((g & 8) >> 2)
                        : (g & 1) | ((g & 4) >> 1);
                }

                switch (subgate)
                {
                case 0:
                    addConst(out, 0);
                    break;
                case 1:
                    addCopy(*wireIdx, out);
                    addInvert(out);
                    break;
                case 2:
                    addCopy(*wireIdx, out);
                    break;
                case 3:
                    addConst(out, 1);
                    break;
                default:
                    throw std::runtime_error(LOCATION);
                    break;
                }
            }
        }
        else
        {

            if (isInvert(aIdx)) gt = invertInputWire(0, gt);
            if (isInvert(bIdx)) gt = invertInputWire(1, gt);

            if (gt != GateType::Xor && gt != GateType::Nxor) ++mNonXorGateCount;
            mGates.emplace_back(aIdx, bIdx, gt, out);

            mWireFlags[out] = BetaWireFlag::Wire;
        }
    }

    void BetaCircuit::addConst(BetaWire  wire, u8 val)
    {
        mWireFlags[wire] = val ? BetaWireFlag::One : BetaWireFlag::Zero;
    }

    void BetaCircuit::addInvert(BetaWire wire)
    {
        switch (mWireFlags[wire])
        {
        case BetaWireFlag::Zero:
            mWireFlags[wire] = BetaWireFlag::One;
            break;
        case BetaWireFlag::One:
            mWireFlags[wire] = BetaWireFlag::Zero;
            break;
        case BetaWireFlag::Wire:
            mWireFlags[wire] = BetaWireFlag::InvWire;
            break;
        case BetaWireFlag::InvWire:
            mWireFlags[wire] = BetaWireFlag::Wire;
            break;
        default:
            throw std::runtime_error(LOCATION);
            break;
        }
    }

    void BetaCircuit::addCopy(BetaWire src, BetaWire dest)
    {
        // copy 1 wire label starting at src to dest
        // memcpy(dest, src, sizeof(block));
        mGates.emplace_back(src, 1, GateType::a, dest);
        mWireFlags[dest] = mWireFlags[src];
    }

    void BetaCircuit::addCopy(BetaBundle & src, BetaBundle & dest)
    {
        auto d = dest.mWires.begin();
        auto dd = dest.mWires.end();
        auto s = src.mWires.begin();
        auto i = src.mWires.begin();


        while (d != dest.mWires.end())
        {
            ++i;
            mWireFlags[*d] = mWireFlags[*s];

            u64 rem = (dd - d);
            u64 len = 1;
            while (len < rem && *i == *(i - 1) + 1)
            {
                ++i;
                mWireFlags[*(d + len)] = mWireFlags[*(s + len)];
                ++len;
            }

            mGates.emplace_back(*s, u32(len), GateType::a, *d);
            d += len;
            s += len;
        }

    }

    bool BetaCircuit::isConst(BetaWire wire)
    {
        return mWireFlags[wire] == BetaWireFlag::One || mWireFlags[wire] == BetaWireFlag::Zero;
    }

    bool BetaCircuit::isInvert(BetaWire wire)
    {
        return mWireFlags[wire] == BetaWireFlag::InvWire;
    }

    u8 BetaCircuit::constVal(BetaWire wire)
    {
        if (mWireFlags[wire] == BetaWireFlag::Wire)
            throw std::runtime_error(LOCATION);

        return mWireFlags[wire] == BetaWireFlag::One ? 1 : 0;
    }

    void BetaCircuit::addPrint(BetaBundle in)
    {
        for (auto& i : in.mWires)
        {
            addPrint(i);
        }
    }

    void osuCrypto::BetaCircuit::addPrint(BetaWire wire)
    {
        mPrints.emplace_back(mGates.size(), wire, "", isInvert(wire));
    }

    void osuCrypto::BetaCircuit::addPrint(std::string str)
    {
        mPrints.emplace_back(mGates.size(), -1, str, false);
    }
    void BetaCircuit::evaluate(span<BitVector> input, span<BitVector> output, bool print)
    {
        std::vector<u8> mem(mWireCount);

        if (input.size() != mInputs.size())
        {
            throw std::runtime_error(LOCATION);
        }

        for (u64 i = 0; i < input.size(); ++i)
        {
            if (input[i].size() != mInputs[i].mWires.size())
                throw std::runtime_error(LOCATION);

            for (u64 j = 0; j < input[i].size(); ++j)
            {
                mem[mInputs[i].mWires[j]] = input[i][j];
            }
        }
        auto iter = mPrints.begin();

        for (u64 i = 0; i < mGates.size(); ++i)
        {
            while (print && iter != mPrints.end() && std::get<0>(*iter) == i)
            {
                auto wireIdx = std::get<1>(*iter);
                auto str = std::get<2>(*iter);
                auto invert = std::get<3>(*iter);

                if (wireIdx != -1)
                    std::cout << (u64)(mem[wireIdx] ^ (invert ? 1 : 0));
                if (str.size())
                    std::cout << str;

                ++iter;
            }

            if (mGates[i].mType == GateType::a)
            {
                u64 src = mGates[i].mInput[0];
                u64 len = mGates[i].mInput[1];
                u64 dest = mGates[i].mOutput;

                memcpy(&*(mem.begin() + dest), &*(mem.begin() + src), len);

            }
            else
            {
                if (mGates[i].mType == GateType::a ||
                    mGates[i].mType == GateType::b ||
                    mGates[i].mType == GateType::na ||
                    mGates[i].mType == GateType::nb ||
                    mGates[i].mType == GateType::One ||
                    mGates[i].mType == GateType::Zero)
                    throw std::runtime_error(LOCATION);

                u64 idx0 = mGates[i].mInput[0];
                u64 idx1 = mGates[i].mInput[1];
                u64 idx2 = mGates[i].mOutput;

                u8 a = mem[idx0];
                u8 b = mem[idx1];

                mem[idx2] = GateEval(mGates[i].mType, (bool)a, (bool)b);

            }
        }
        while (print && iter != mPrints.end())
        {
            auto wireIdx = std::get<1>(*iter);
            auto str = std::get<2>(*iter);
            auto invert = std::get<3>(*iter);

            if (wireIdx != -1)
                std::cout << (u64)(mem[wireIdx] ^ (invert ? 1 : 0));
            if (str.size())
                std::cout << str;

            ++iter;
        }


        if (output.size() != mOutputs.size())
        {
            throw std::runtime_error(LOCATION);
        }

        for (u64 i = 0; i < output.size(); ++i)
        {
            if (output[i].size() != mOutputs[i].mWires.size())
                throw std::runtime_error(LOCATION);

            for (u64 j = 0; j < output[i].size(); ++j)
            {
                output[i][j] = mem[mOutputs[i].mWires[j]] ^ (isInvert(mOutputs[i].mWires[j])? 1 : 0);
            }
        }
    }

    void BetaCircuit::levelize()
    {
        mLevelGates.clear();
        mLevelGates.emplace_back();


        std::unordered_map<u64, u64> levelMap;


        for (u64 i = 0; i < mGates.size(); ++i)
        {
            u64 level = 0;


            static_assert(sizeof(BetaWire) == sizeof(u32), "");

            auto idx = mGates[i].mInput[0];
            auto iter = levelMap.find(idx);

            if (iter != levelMap.end())
            {
                level = iter->second + 1;
            }

            idx = mGates[i].mInput[1];
            iter = levelMap.find(idx);

            if (iter != levelMap.end())
            {
                level = std::max(iter->second + 1, level);
            }

            idx = mGates[i].mOutput;
            levelMap[idx] = level;


            if (level == mLevelGates.size())
                mLevelGates.emplace_back();

            if (mGates[i].mType == GateType::Xor || mGates[i].mType == GateType::Nxor)
            {
                mLevelGates[level].mXorGates.push_back(mGates[i]);
            }
            else
            {
                mLevelGates[level].mAndGates.push_back(mGates[i]);
            }
        }
    }
}