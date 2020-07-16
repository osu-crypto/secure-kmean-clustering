#include "ShGcRuntime_tests.h"
#include "ivory/Runtime/Party.h"
#include "ivory/Runtime/sInt.h"
#include "ivory/Runtime/ShGc/ShGcRuntime.h"
#include <functional>
#include "cryptoTools/Network/IOService.h"
#include "cryptoTools/Network/Session.h"
#include "cryptoTools/Common/Log.h"

#include "Common.h"

using namespace osuCrypto;



void ShGcRuntime_publicGateGarble_Test()
{
    PRNG prng(ZeroBlock);
    block xorOffset = prng.get<block>();
    std::array<block, 2> a, b, garbleIn, in;
    a[0] = prng.get<block>();
    a[1] = a[0] ^ xorOffset;
    b[0] = prng.get<block>();
    b[1] = b[0] ^ xorOffset;


    for (auto gt : { GateType::And,GateType::Nand, GateType::na_And, GateType::na_Or, GateType::nb_And, GateType::nb_Or, GateType::Nor, GateType::Nxor, GateType::Xor, GateType::Or })
    {
        for (auto constA : { true, false })
        {
            for (auto valA : { true, false })
            {
                for (auto constB : { true, false })
                {
                    if (constA == false && constB == false) continue;

                    for (auto valB : { true, false })
                    {
                        in[0] = constA ? ShGcRuntime::mPublicLabels[valA] : a[valA];
                        in[1] = constB ? ShGcRuntime::mPublicLabels[valB] : b[valB];
                        garbleIn[0] = constA ? ShGcRuntime::mPublicLabels[valA] : a[0];
                        garbleIn[1] = constB ? ShGcRuntime::mPublicLabels[valB] : b[0];

                        block expGarbleC, expEvalC;
                        auto evalC = ShGcRuntime::evaluateConstGate(constA, constB, in, gt);
                        auto garbleC = ShGcRuntime::garbleConstGate(constA, constB, garbleIn, gt, xorOffset);

                        if (constA && constB)
                        {
                            auto valC = GateEval(gt, valA, valB);
                            expEvalC = expGarbleC = ShGcRuntime::mPublicLabels[valC];
                        }
                        else
                        {
                            u8 subgate;

                            if (constB)
                            {
                                expEvalC = in[0];
                                expGarbleC = garbleIn[0];
                                subgate = u8(gt) >> (2 * valB) & 3;
                            }
                            else
                            {
                                expEvalC = in[1];
                                expGarbleC = garbleIn[1];
                                u8 g = static_cast<u8>(gt);

                                auto val = valA;
                                subgate = val
                                    ? ((g & 2) >> 1) | ((g & 8) >> 2)
                                    : (g & 1) | ((g & 4) >> 1);
                            }

                            switch (subgate)
                            {
                            case 0:
                                expEvalC = expGarbleC = ShGcRuntime::mPublicLabels[0];
                                break;
                            case 1:
                                expGarbleC = expGarbleC ^ xorOffset;
                                break;
                            case 2:
                                break;
                            case 3:
                                expEvalC = expGarbleC = ShGcRuntime::mPublicLabels[1];
                                break;
                            default:
                                throw std::runtime_error(LOCATION);
                                break;
                            }
                        }


                        if (neq(evalC, expEvalC))
                        {
                            auto evalC = ShGcRuntime::evaluateConstGate(constA, constB, in, gt);
                            throw UnitTestFail();
                        }

                        if (neq(garbleC, expGarbleC))
                        {
                            auto garbleC = ShGcRuntime::garbleConstGate(constA, constB, garbleIn, gt, xorOffset);
                            throw UnitTestFail();
                        }
                    }
                }
            }
        }
    }
}


void runProgram(std::function<void(Runtime&)>  program)
{
    PRNG prng(OneBlock);

    IOService ios(0);


    std::thread thrd([&]() {
        setThreadName("party1");

        Session ep1(ios, "127.0.0.1:1212", SessionMode::Client, "n");
        Channel chl1 = ep1.addChannel("n");
        PRNG prng(ZeroBlock);

        ShGcRuntime rt1;
        rt1.init(chl1, prng.get<block>(), ShGcRuntime::Evaluator, 1);


        program(rt1);


        chl1.close();
        ep1.stop();

    });

    setThreadName("party0");
    Session ep0(ios, "127.0.0.1:1212", SessionMode::Server, "n");
    Channel chl0 = ep0.addChannel("n");
    ShGcRuntime rt0;
    rt0.init(chl0, prng.get<block>(), ShGcRuntime::Garbler, 0);

    program(rt0);


    thrd.join();
    chl0.close();
    ep0.stop();
    ios.stop();
}

void ShGcRuntime_basicArith_Test()
{
    i32 addResult = 0;
    i32 subResult = 0;
    i32 mulResult = 0;
    i32 divResult = 0;
    i32 gteResult = 0;
    i32 grtResult = 0;
    i32 lstResult = 0;
    i32 lteResult = 0;
    i32 gte2Result = 0;
    i32 grt2Result = 0;
    i32 lst2Result = 0;
    i32 lte2Result = 0;
    i32 maxresult = 0;

    i64 inputVal0 = 254324;
    i64 inputVal1 = -5323;

    auto program = [&](Runtime& rt)
    {


        std::array<Party, 2> parties{
            Party(rt, 0),
            Party(rt, 1)
        };

        // choose how large the arithmetic should be.
        u64 bitCount0 = 32;
        u64 bitCount1 = 32;

        // get the two input variables. If this party is
        // the local party, then lets use our input value.
        // Otherwise the remote party will provide the value.
        auto input0 = parties[0].isLocalParty() ?
            parties[0].input<sInt>(inputVal0, bitCount0) :
            parties[0].input<sInt>(bitCount0);

        sInt input1 = parties[1].isLocalParty() ?
            parties[1].input<sInt>(inputVal1, bitCount1) :
            parties[1].input<sInt>(bitCount1);


        // perform some computation
        auto add = input1 + input0;
        auto sub = input1 - input0;
        auto mul = input1 * input0;
        auto div = input1 / input0;


        auto gt = input1 > input0;
        parties[0].getRuntime().processesQueue();
        auto gt2 = input0 > input1;
        parties[0].getRuntime().processesQueue();

        auto gteq = input1 >= input0;
        auto lteq = input1 <= input0;
        auto lt = input1 < input0;

        auto gteq2 = input0 >= input1;
        auto lteq2 = input0 <= input1;
        auto lt2 = input0 < input1;

        auto max = gteq.ifelse(input1, input0);

        // reveal this output to party 0 and then party 1.
        parties[0].reveal(add);
        parties[0].reveal(sub);
        parties[0].reveal(mul);
        parties[0].reveal(div);
        parties[1].reveal(gt);
        parties[1].reveal(gteq);
        parties[1].reveal(lteq);
        parties[1].reveal(lt);
        parties[1].reveal(gt2);
        parties[1].reveal(gteq2);
        parties[1].reveal(lteq2);
        parties[1].reveal(lt2);
        parties[1].reveal(max);


        if (parties[0].isLocalParty())
        {
            addResult = add.getValue();
            subResult = sub.getValue();
            mulResult = mul.getValue();
            divResult = div.getValue();
        }
        else {
            grtResult = gt.getValue();
            grt2Result = gt2.getValue();

            gteResult = gteq.getValue();
            lteResult = lteq.getValue();
            lstResult = lt.getValue();
            gte2Result = gteq2.getValue();
            lte2Result = lteq2.getValue();
            lst2Result = lt2.getValue();
            maxresult = max.getValue();
        }

        parties[0].getRuntime().processesQueue();
    };
    runProgram(program);


    //if (addResult != inputVal1 + inputVal0) throw UnitTestFail();
    //if (subResult != inputVal1 - inputVal0) throw UnitTestFail();
    //if (mulResult != inputVal1 * inputVal0) throw UnitTestFail();
    //if (divResult != inputVal1 / inputVal0) throw UnitTestFail();
    if (grtResult != inputVal1 > inputVal0)
        throw UnitTestFail();
    if (grt2Result != inputVal0 > inputVal1)
        throw UnitTestFail();



    if (gteResult != inputVal1 >= inputVal0)
        throw UnitTestFail();
    if (gte2Result != inputVal0 >= inputVal1) throw UnitTestFail();
    if (lteResult != inputVal1 <= inputVal0) throw UnitTestFail();
    if (lte2Result != inputVal0 <= inputVal1) throw UnitTestFail();
    if (lstResult != inputVal1 < inputVal0) throw UnitTestFail();
    if (lst2Result != inputVal0 < inputVal1) throw UnitTestFail();
    if (maxresult != std::max(inputVal0, inputVal1)) throw UnitTestFail();

}

void ShGcRuntime_SequentialOp_Test()
{
    i32 addResult = 0;
    i32 subResult = 0;
    i32 mulResult = 0;
    i32 divResult = 0;
    i32 gteResult = 0;
    i32 lstResult = 0;
    i32 maxresult = 0;

    i64 inputVal0 = 254324;
    i64 inputVal1 = -5323;

    auto program = [&](Runtime& rt)
    {


        std::array<Party, 2> parties{
            Party(rt, 0),
            Party(rt, 1)
        };

        // choose how large the arithmetic should be.
        u64 bitCount0 = 32;
        u64 bitCount1 = 32;

        // get the two input variables. If this party is
        // the local party, then lets use our input value.
        // Otherwise the remote party will provide the value.
        auto input0 = parties[0].isLocalParty() ?
            parties[0].input<sInt>(inputVal0, bitCount0) :
            parties[0].input<sInt>(bitCount0);

        auto input1 = parties[1].isLocalParty() ?
            parties[1].input<sInt>(inputVal1, bitCount1) :
            parties[1].input<sInt>(bitCount1);


        auto add = ~input1 + input0;

        // reveal this output to party 0 and then party 1.
        parties[0].reveal(add);


        if (parties[0].isLocalParty())
        {
            addResult = add.getValue();
        }

        parties[0].getRuntime().processesQueue();
    };
    runProgram(program);


    if (addResult != ~inputVal1 + inputVal0)
    {
        std::cout << "act " << addResult << std::endl;
        std::cout << "exp " << (~inputVal1 + inputVal0) << std::endl;
        std::cout << "oth " << (inputVal1 + inputVal0) << std::endl;
        throw UnitTestFail();
    }
    //if (maxresult != std::max(inputVal0, inputVal1)) throw UnitTestFail();


}



void evaluate(
    BetaCircuit& cir,
    const span<std::vector<u8>>& input,
    const span<std::vector<u8>>& publicFlag,
    const span<std::vector<u8>>& output)
{

    PRNG prng(toBlock(234543));
    std::vector<block> memG(cir.mWireCount), memE(cir.mWireCount);
    std::array<block, 2> tweaksE{ ZeroBlock, toBlock(1,0) }, tweaksG{ ZeroBlock, toBlock(1,0) },
        zeroAndXorOffset{ ZeroBlock, prng.get<block>() | OneBlock };
    auto& xorOffset = zeroAndXorOffset[1];

    std::vector<GarbledGate<2>> garbledGates;


    std::vector<BitVector> input2(input.size()), output2(output.size());
    for (u64 i = 0; i < output.size(); ++i) {
        output2[i].resize(output[i].size());
    }
    for (u64 i = 0; i < input.size(); ++i) {
        input2[i].resize(input[i].size());
        for (u64 j = 0; j < input[i].size(); ++j) {
            input2[i][j] = input[i][j];
        }
    }
    cir.evaluate(input2, output2);

    garbledGates.resize(cir.mNonXorGateCount);
    auto iterG = memG.begin();
    auto iterE = memE.begin();

    std::vector<std::vector<block>> inLabelsG(input.size()), inLabelsE(input.size());

    for (u64 i = 0; i < inLabelsG.size(); ++i)
    {
        inLabelsG[i].resize(input[i].size());
        prng.get(inLabelsG[i].data(), inLabelsG[i].size());
        inLabelsE[i] = inLabelsG[i];

        for (u64 j = 0; j < inLabelsG[i].size(); ++j) {
            if (input[i][j])
                inLabelsE[i][j] = inLabelsE[i][j] ^ xorOffset;

            if (publicFlag[i][j])
            {
                inLabelsG[i][j] = inLabelsE[i][j] = ShGcRuntime::mPublicLabels[input[i][j]];
            }

            *iterG++ = inLabelsG[i][j];
            *iterE++ = inLabelsE[i][j];
        }
    }

    std::vector<block> garbledMem(cir.mGates.size()), evalMem(cir.mGates.size());
	std::vector<u8> auxBits;

    ShGcRuntime::garble(cir, memG, tweaksG, garbledGates, zeroAndXorOffset, auxBits, garbledMem.data());

	ShGcRuntime::evaluate(cir, memE, tweaksE, garbledGates, [iter = auxBits.begin()]() mutable {return (bool)*iter++; }, evalMem.data());

    for (u64 i = 0; i < garbledMem.size(); ++i)
    {
        if (ShGcRuntime::isConstLabel(garbledMem[i])) {
			if (neq(evalMem[i], garbledMem[i]))
			{
				ShGcRuntime::garble(cir, memG, tweaksG, garbledGates, zeroAndXorOffset, auxBits, garbledMem.data());
				ShGcRuntime::evaluate(cir, memE, tweaksE, garbledGates, [iter = auxBits.begin()]() mutable {return (bool)*iter++; }, evalMem.data());
                throw std::runtime_error(LOCATION);
			}
        }
        else {
            if (neq(evalMem[i], garbledMem[i]) &&
                neq(evalMem[i], garbledMem[i] ^ xorOffset))
                throw std::runtime_error(LOCATION);
        }
    }

    for (u64 i = 0; i < output.size(); ++i) {
        for (u64 j = 0; j < output[i].size(); ++j) {

            block e = *iterE++, g = *iterG++;

            if (ShGcRuntime::isConstLabel(e))
            {
                output[i][j] = eq(ShGcRuntime::mPublicLabels[1], e);

                if (neq(e, g)) {
                    std::cout << "mixed Pub label @ " << j << ", val = " << output[i][j] << " -> " << e << " != " << g << std::endl;
                    throw UnitTestFail(LOCATION);
                }
            }
            else
            {

                output[i][j] = PermuteBit(e^g);
                if (neq(e, g ^ (output[i][j] ? xorOffset : ZeroBlock))) {
                    std::cout << "bad label @ " << j << ", val = " << (int)output[i][j] << " -> " << e << " != " << g << " " << (g ^ xorOffset) << std::endl;
                    throw UnitTestFail(LOCATION);
                }

                if (output2[i][j] != output[i][j]) {
                    std::cout << "bad value @ " << j << ", val = " << (int)output[i][j] << " != exp = " << output2[i][j] << std::endl;
                    throw UnitTestFail(LOCATION);
                }
            }
        }
    }
}

enum class InputType
{
    Private,
    Mixed,
    Public
};

void evaluate(BetaCircuit* cir, PRNG& prng, InputType type)
{
    std::vector<std::vector<u8>>
        inputs(cir->mInputs.size()),
        pubVal(cir->mInputs.size()),
        outputs(cir->mOutputs.size());

    for (u64 i = 0; i < outputs.size(); ++i)
    {
        outputs[i].resize(cir->mOutputs[i].mWires.size());
    }

    for (u64 i = 0; i < inputs.size(); ++i)
    {
        pubVal[i].resize(cir->mInputs[i].mWires.size());
        inputs[i].resize(cir->mInputs[i].mWires.size());
        for (u64 j = 0; j < inputs[i].size(); ++j)
        {
            inputs[i][j] = prng.get<bool>();

            switch (type)
            {
            case InputType::Private:
                pubVal[i][j] = 0;
                break;
            case InputType::Mixed:
                pubVal[i][j] = prng.get<bool>();
                break;
            case InputType::Public:
                pubVal[i][j] = 1;
                break;
            default:
                break;
            }
        }
    }

    evaluate(*cir, inputs, pubVal, outputs);
}

void ShGcRuntime_CircuitInvert_Test()
{
    CircuitLibrary lib;
    u64 aSize(10);
    auto cir = lib.int_bitInvert(aSize);
    PRNG prng(ZeroBlock);

    std::vector<std::vector<u8>> inputs(1), pubVal(1), outputs(1);
    inputs[0].resize(aSize);
    pubVal[0].resize(aSize);
    outputs[0].resize(aSize);

    for (u64 i = 0; i < aSize; ++i)
        inputs[0][i] = prng.get<bool>();

    evaluate(*cir, inputs, pubVal, outputs);

    for (u64 j = 0; j < aSize; ++j) {
        if (inputs[0][j] == outputs[0][j]) {
            std::cout << "exp " << j << " " << !inputs[0][j] << "\nact " << j << " " << outputs[0][j] << std::endl;
            throw UnitTestFail(LOCATION);
        }
    }
}

i64 fill(std::vector<u8>& dest, PRNG& prng)
{
    if (dest.size() > 64) throw std::runtime_error(LOCATION);
    BitVector bv(dest.size());
    //bv.randomize(prng);
    for (u64 i = 0; i < bv.size(); ++i)
    {
        bv[i] = dest[i] = prng.get<bool>();
    }
    i64 ret = 0;
    memcpy(&ret, bv.data(), bv.sizeBytes());
    return ret;
}

i64 get(const std::vector<u8>& src)
{
    i64 ret = 0;
    for (u64 i = 0; i < src.size(); ++i)
        ret += bool(src[i]) * (1 << i);
    return ret;
}

void ShGcRuntime_CircuitAdd_Test()
{
    CircuitLibrary lib;
    u64 size(5);
    auto cir = lib.int_int_add(size, size, size);
    auto trials = 100;
    PRNG prng(ZeroBlock);

    std::vector<std::vector<u8>> inputs(2), pubVal(2), outputs(1);
    inputs[0].resize(size);
    inputs[1].resize(size);
    pubVal[0].resize(size);
    pubVal[1].resize(size);
    outputs[0].resize(size);

    for (u64 i = 0; i < trials; ++i)
    {
        u32 a = fill(inputs[0], prng);
        u32 b = fill(inputs[1], prng);
        u32 c = a + b;
        BitVector cc((u8*)&c, size);

        evaluate(*cir, inputs, pubVal, outputs);

        for (u64 j = 0; j < size; ++j) {
            if (cc[j] != outputs[0][j]) {
                std::cout << i << " " << j << " prob: " << a << " + " << b << " = " << c << std::endl;
                std::cout << "exp = " << cc[j] << " != " << i32(outputs[0][j]) << std::endl;
                std::cout << "exp = " << c << " != " << get(outputs[0]) << std::endl;
                throw UnitTestFail(LOCATION);
            }
        }
    }
}

void ShGcRuntime_CircuitMult_Test()
{
    CircuitLibrary lib;
    u64 size(5);
    auto cir = lib.int_int_mult(size, size, size);
    auto trials = 100;
    PRNG prng(ZeroBlock);

    std::vector<std::vector<u8>> inputs(2), pubVal(2), outputs(1);
    inputs[0].resize(size);
    inputs[1].resize(size);
    pubVal[0].resize(size);
    pubVal[1].resize(size);
    outputs[0].resize(size);

    for (u64 i = 0; i < trials; ++i)
    {
        u32 a = fill(inputs[0], prng);
        u32 b = fill(inputs[1], prng);
        u32 c = a * b;
        BitVector cc((u8*)&c, size);

        evaluate(*cir, inputs, pubVal, outputs);

        for (u64 j = 0; j < size; ++j) {
            if (cc[j] != outputs[0][j]) {
                std::cout << i << " " << j << " prob: " << a << " * " << b << " = " << c << std::endl;
                std::cout << "exp = " << cc[j] << " != " << i32(outputs[0][j]) << std::endl;
                std::cout << "exp = " << c << " != " << get(outputs[0]) << std::endl;
                throw UnitTestFail(LOCATION);
            }
        }
    }
}


void shGcRuntime_CircuitEval_Test()
{
    auto trials(10);
    PRNG prng(ZeroBlock);

    CircuitLibrary lib;
    auto sizeA(13), sizeB(10), sizeC(11);
    std::vector<BetaCircuit*> cirs{
        lib.int_int_gteq(sizeA, sizeA),
        lib.int_int_gteq(sizeA, sizeB),
        lib.int_int_add(sizeA, sizeA, sizeA),
        lib.int_int_add(sizeA, sizeB, sizeC),
        lib.int_int_subtract(sizeA, sizeA, sizeA),
        lib.int_int_subtract(sizeA, sizeB, sizeC),
        lib.int_int_mult(sizeA, sizeA, sizeA),
        lib.int_int_mult(sizeA, sizeB, sizeC),
        lib.int_int_div(sizeA, sizeA, sizeA),
        lib.int_int_div(sizeA, sizeB, sizeA),
        lib.int_int_lt(sizeA, sizeA),
        lib.int_int_lt(sizeA, sizeB),
        lib.int_bitInvert(sizeA),
        lib.int_addSign(sizeA),
        lib.int_int_bitwiseAnd(sizeA, sizeA, sizeA),
        //lib.int_int_bitwiseAnd(sizeA, sizeB, sizeC),
        lib.int_int_bitwiseOr(sizeA, sizeA, sizeA),
        //lib.int_int_bitwiseOr(sizeA, sizeB, sizeC),
        lib.int_int_multiplex(sizeA),
        lib.int_negate(sizeA),
        lib.int_removeSign(sizeA)
    };


    for (auto cir : cirs)
    {
        for (auto i = 0; i < trials; ++i)
        {
            for (auto type : { InputType::Public, InputType::Mixed, InputType::Private })
            {
                evaluate(cir, prng, type);
            }
        }
    }
}