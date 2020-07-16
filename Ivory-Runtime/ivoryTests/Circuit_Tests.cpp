#include "Circuit_Tests.h"

#include "ivory/Circuit/CircuitLibrary.h"

#include <fstream>
#include "Common.h"
#include "cryptoTools/Common/Log.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Crypto/AES.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "DebugCircuits.h"

using namespace osuCrypto;


#ifdef max
#undef max
#endif
#ifdef min
#undef min
#endif
i64 signExtend(i64 v, u64 b, bool print = false)
{
    i64 loc = (i64(1) << (b - 1));
    i64 sign = v & loc;

    if (sign)
    {
        i64 mask = i64(-1) << (b);
        auto ret = v | mask;
        if (print)
        {

            std::cout << "sign: " << BitVector((u8*)&sign, 64) << std::endl;;
            std::cout << "mask: " << BitVector((u8*)&mask, 64) << std::endl;;
            std::cout << "v   : " << BitVector((u8*)&v, 64) << std::endl;;
            std::cout << "ret : " << BitVector((u8*)&ret, 64) << std::endl;;

        }
        return ret;
    }
    else
    {
        i64 mask = (i64(1) << b) - 1;
        auto ret = v & mask;
        if (print)
        {

            std::cout << "sign: " << BitVector((u8*)&loc, 64) << std::endl;;
            std::cout << "mask: " << BitVector((u8*)&mask, 64) << std::endl;;
            std::cout << "v   : " << BitVector((u8*)&v, 64) << std::endl;;
            std::cout << "ret : " << BitVector((u8*)&ret, 64) << std::endl;;

        }
        return ret;
    }
}

void Circuit_SequentialOp_Test()
{

    setThreadName("CP_Test_Thread");


    CircuitLibrary lib;


    PRNG prng(ZeroBlock);
    u64 tries = 10;


    for (u64 i = 0; i < tries; ++i)
    {

        u64 aSize = prng.get<u32>() % 24 + 1,
            bSize = prng.get<u32>() % 24 + 1,
            cSize = std::min<u64>(prng.get<u32>() % 24 + 1, std::max(aSize, bSize) + 1);

        auto* cirAdd = lib.int_int_add(aSize, bSize, cSize);
        //auto* cirNeg = lib.int_negate(aSize);
        auto* cirInv = lib.int_bitInvert(aSize);


        i64 a = signExtend(prng.get<i64>(), aSize);
        i64 b = signExtend(prng.get<i64>(), bSize);
        i64 c = signExtend((~a + b), cSize);

        std::vector<BitVector> invInputs(1), invOutput(1);
        invInputs[0].append((u8*)&a, aSize);
        invOutput[0].resize(aSize);

        cirInv->evaluate(invInputs, invOutput);


        std::vector<BitVector> addInputs(2), addOutput(1);
        addInputs[0] = invOutput[0];
        addInputs[1].append((u8*)&b, bSize);
        addOutput[0].resize(cSize);



        cirAdd->evaluate(addInputs, addOutput);

        i64 cc = 0;
        memcpy(&cc, addOutput[0].data(), addOutput[0].sizeBytes());

        cc = signExtend(cc, cSize);

        if (cc != c)
        {
            std::cout << "i " << i << std::endl;

            BitVector cExp;
            cExp.append((u8*)&c, cSize);
            std::cout << "a  : " << invInputs[0] << std::endl;
            std::cout << "~a : " << addInputs[0] << std::endl;
            std::cout << "b  : " << addInputs[1] << std::endl;
            std::cout << "exp: " << cExp << std::endl;
            std::cout << "act: " << addOutput[0] << std::endl;

            throw UnitTestFail();
        }

    }

}

void Circuit_int_Adder_Test()
{
    setThreadName("CP_Test_Thread");


    CircuitLibrary lib;


    PRNG prng(ZeroBlock);
    u64 tries = 1000;


    for (u64 i = 0; i < tries; ++i)
    {

        u64 aSize = prng.get<u32>() % 24 + 1,
            bSize = prng.get<u32>() % 24 + 1,
            cSize = std::min<u64>(prng.get<u32>() % 24 + 1, std::max(aSize, bSize) + 1);

        auto* cir = lib.int_int_add(aSize, bSize, cSize);


        i64 a = signExtend(prng.get<i64>(), aSize);
        i64 b = signExtend(prng.get<i64>(), bSize);
        i64 c = signExtend((a + b), cSize);


        std::vector<BitVector> inputs(2), output(1);
        inputs[0].append((u8*)&a, aSize);
        inputs[1].append((u8*)&b, bSize);
        output[0].resize(cSize);

        cir->evaluate(inputs, output);

        i64 cc = 0;
        memcpy(&cc, output[0].data(), output[0].sizeBytes());

        cc = signExtend(cc, cSize);

        if (cc != c)
        {
            std::cout << "i " << i << std::endl;

            BitVector cExp;
            cExp.append((u8*)&c, cSize);
            std::cout << "a  : " << inputs[0] << std::endl;
            std::cout << "b  : " << inputs[1] << std::endl;
            std::cout << "exp: " << cExp << std::endl;
            std::cout << "act: " << output[0] << std::endl;

            throw UnitTestFail();
        }

    }
}


void Circuit_int_Adder_const_Test()
{
    setThreadName("CP_Test_Thread");


    CircuitLibrary lib;


    PRNG prng(ZeroBlock);
    u64 tries = 1000;


    for (u64 i = 0; i < tries; ++i)
    {

        u64 aSize = prng.get<u32>() % 16 + 1,
            bSize = prng.get<u32>() % 16 + 1,
            cSize = std::min<u64>(prng.get<u32>() % 24 + 1, std::max(aSize, bSize) + 1);

        i64 a = signExtend(prng.get<i64>(), aSize);
        i64 b = signExtend(prng.get<i64>(), bSize);
        i64 c = signExtend((a + b), cSize);

        auto* cir = lib.int_intConst_add(aSize, bSize, b, cSize);



        std::vector<BitVector> inputs(1), output(1);
        inputs[0].append((u8*)&a, aSize);
        output[0].resize(cSize);

        cir->evaluate(inputs, output);

        i64 cc = 0;
        memcpy(&cc, output[0].data(), output[0].sizeBytes());

        cc = signExtend(cc, cSize);

        if (cc != c)
        {
            std::cout << "i " << i << std::endl;

            BitVector cExp;
            cExp.append((u8*)&c, cSize);
            std::cout << "a  : " << inputs[0] << "  " << a<< std::endl;
            std::cout << "b  : " << BitVector((u8*)&b, bSize) << "  " << b  << std::endl;
            std::cout << "exp: " << cExp << "   " << c<< std::endl;
            std::cout << "act: " << output[0] << "   "<< cc << std::endl;

            throw UnitTestFail();
        }

    }
}


void Circuit_int_Subtractor_Test()
{
    setThreadName("CP_Test_Thread");


    CircuitLibrary lib;


    PRNG prng(ZeroBlock);
    u64 tries = 1000;


    for (u64 i = 0; i < tries; ++i)
    {

        u64 aSize = prng.get<u32>() % 24 + 1,
            bSize = prng.get<u32>() % 24 + 1,
            cSize = std::min<u64>(prng.get<u32>() % 24 + 1, std::max(aSize, bSize) + 1);

        auto* cir = lib.int_int_subtract(aSize, bSize, cSize);


        i64 a = signExtend(prng.get<i64>(), aSize);
        i64 b = signExtend(prng.get<i64>(), bSize);
        i64 c = signExtend((a - b), cSize);


        std::vector<BitVector> inputs(2), output(1);
        inputs[0].append((u8*)&a, aSize);
        inputs[1].append((u8*)&b, bSize);
        output[0].resize(cSize);

        cir->evaluate(inputs, output);

        i64 cc = 0;
        memcpy(&cc, output[0].data(), output[0].sizeBytes());
        cc = signExtend(cc, cSize);

        if (cc != c)
        {
            std::cout << "i " << i << std::endl;
            BitVector cExp;
            cExp.append((u8*)&c, cSize);
            std::cout << " a : " << inputs[0] << std::endl;
            std::cout << "-b : " << inputs[1] << std::endl;
            std::cout << "exp: " << cExp << std::endl;
            std::cout << "act: " << output[0] << std::endl;

            throw UnitTestFail();
        }
    }
}



void Circuit_int_Subtractor_const_Test()
{
    setThreadName("CP_Test_Thread");


    CircuitLibrary lib;


    PRNG prng(ZeroBlock);
    u64 tries = 1000;


    for (u64 i = 0; i < tries; ++i)
    {

        u64 aSize = prng.get<u32>() % 24 + 1,
            bSize = prng.get<u32>() % 24 + 1,
            cSize = std::min<u64>(prng.get<u32>() % 24 + 1, std::max(aSize, bSize) + 1);

        i64 a = signExtend(prng.get<i64>(), aSize);
        i64 b = signExtend(prng.get<i64>(), bSize);
        i64 c = signExtend((a - b), cSize);


        auto* cir = lib.int_intConst_subtract(aSize, bSize,b, cSize);


        std::vector<BitVector> inputs(1), output(1);
        inputs[0].append((u8*)&a, aSize);
        output[0].resize(cSize);

        cir->evaluate(inputs, output);

        i64 cc = 0;
        memcpy(&cc, output[0].data(), output[0].sizeBytes());
        cc = signExtend(cc, cSize);

        if (cc != c)
        {
            std::cout << "i " << i << std::endl;
            BitVector cExp;
            cExp.append((u8*)&c, cSize);
            std::cout << " a : " << inputs[0] << std::endl;
            std::cout << "-b : " << inputs[1] << std::endl;
            std::cout << "exp: " << cExp << std::endl;
            std::cout << "act: " << output[0] << std::endl;

            throw UnitTestFail();
        }
    }
}


void Circuit_uint_Adder_Test()
{
    setThreadName("CP_Test_Thread");


    CircuitLibrary lib;


    PRNG prng(ZeroBlock);
    u64 tries = 1000;


    for (u64 i = 0; i < tries; ++i)
    {

        u64 aSize = prng.get<u32>() % 24 + 1,
            bSize = prng.get<u32>() % 24 + 1,
            cSize = std::min<u64>(prng.get<u32>() % 24 + 1, std::max(aSize, bSize) + 1);

        auto* cir = lib.uint_uint_add(aSize, bSize, cSize);


        u64 a = prng.get<i64>() & ((u64(1) << aSize) - 1);
        u64 b = prng.get<i64>() & ((u64(1) << bSize) - 1);
        u64 c = (a + b) & ((u64(1) << cSize) - 1);


        std::vector<BitVector> inputs(2), output(1);
        inputs[0].append((u8*)&a, aSize);
        inputs[1].append((u8*)&b, bSize);
        output[0].resize(cSize);

        cir->evaluate(inputs, output);

        i64 cc = 0;
        memcpy(&cc, output[0].data(), output[0].sizeBytes());

        if (cc != c)
        {
            std::cout << "i " << i << std::endl;

            BitVector cExp;
            cExp.append((u8*)&c, cSize);
            std::cout << "a  : " << inputs[0] << std::endl;
            std::cout << "b  : " << inputs[1] << std::endl;
            std::cout << "exp: " << cExp << std::endl;
            std::cout << "act: " << output[0] << std::endl;

            throw UnitTestFail();
        }

    }
}

void Circuit_uint_Subtractor_Test()
{
    setThreadName("CP_Test_Thread");


    CircuitLibrary lib;


    PRNG prng(ZeroBlock);
    u64 tries = 1000;


    for (u64 i = 0; i < tries; ++i)
    {

        u64 aSize = prng.get<u32>() % 24 + 1,
            bSize = prng.get<u32>() % 24 + 1,
            cSize = std::min<u64>(prng.get<u32>() % 24 + 1, std::max(aSize, bSize) + 1);

        auto* cir = lib.uint_uint_subtract(aSize, bSize, cSize);
        
        u64 a = prng.get<i64>() & ((u64(1) << aSize) - 1);
        u64 b = prng.get<i64>() & ((u64(1) << bSize) - 1);
        u64 c = (a - b) & ((u64(1) << cSize) - 1);


        std::vector<BitVector> inputs(2), output(1);
        inputs[0].append((u8*)&a, aSize);
        inputs[1].append((u8*)&b, bSize);
        output[0].resize(cSize);

        cir->evaluate(inputs, output);

        u64 cc = 0;
        memcpy(&cc, output[0].data(), output[0].sizeBytes());

        if (cc != c)
        {
            std::cout << "i " << i << std::endl;
            BitVector cExp;
            cExp.append((u8*)&c, cSize);
            std::cout << " a : " << inputs[0] << std::endl;
            std::cout << "-b : " << inputs[1] << std::endl;
            std::cout << "exp: " << cExp<< "  " << c << std::endl;
            std::cout << "act: " << output[0] << "  " << cc<< std::endl;

            throw UnitTestFail();
        }
    }
}


void Circuit_int_Multiply_Test()
{
    setThreadName("CP_Test_Thread");


    CircuitLibrary lib;


    PRNG prng(ZeroBlock);
    u64 tries = 100;


    for (u64 i = 0; i < tries; ++i)
    {

        u64 aSize =  prng.get<u32>() % 16 + 1,
            bSize = prng.get<u32>() % 16 + 1,
            cSize =  std::min<u64>(aSize + bSize, std::min<u64>(prng.get<u32>() % 16 + 1, std::max(aSize, bSize)));

        auto* cir = lib.int_int_mult(aSize, bSize, cSize);


        i64 a = signExtend(prng.get<i64>(), aSize);
        i64 b = signExtend(prng.get<i64>(), bSize);
        i64 c = signExtend((a * b), cSize);


        std::vector<BitVector> inputs(2), output(1);
        inputs[0].append((u8*)&a, aSize);
        inputs[1].append((u8*)&b, bSize);
        output[0].resize(cSize);

        cir->evaluate(inputs, output, i == 125);

        i64 cc = 0;
        memcpy(&cc, output[0].data(), output[0].sizeBytes());
        cc = signExtend(cc, cSize);

        if (cc != c)
        {
            std::cout << "i " << i << std::endl;
            BitVector cExp;
            cExp.append((u8*)&c, cSize);
            std::cout << " a : " << inputs[0] << "  " << a << std::endl;
            std::cout << "*b : " << inputs[1] << "  " << b << std::endl;
            std::cout << "exp: " << cExp << "   " << c << std::endl;
            std::cout << "act: " << output[0] << "   " << cc<< std::endl;

            throw UnitTestFail();
        }
    }
}



void Circuit_int_Divide_Test()
{
    setThreadName("CP_Test_Thread");


    CircuitLibrary lib;


    PRNG prng(ZeroBlock);
    u64 tries = 200;


    for (u64 i = 0; i < tries; ++i)
    {

        u64 aSize =prng.get<u32>() % 16 + 1,
            bSize = prng.get<u32>() % 16 + 1,
            cSize =  aSize;

        auto* cir = lib.int_int_div(aSize, bSize, cSize);

        //std::cout << aSize << "  " << cir->mGates.size() << "  " << cir->mNonXorGateCount << std::endl;

        i64 a = signExtend(prng.get<i64>(), aSize);
        i64 b = signExtend(prng.get<i64>(), bSize);
        b = b ? b : signExtend(1, bSize);

        i64 c = signExtend((a / b), cSize);


        std::vector<BitVector> inputs(2), output(1);
        inputs[0].append((u8*)&a, aSize);
        inputs[1].append((u8*)&b, bSize);
        output[0].resize(cSize);

        cir->evaluate(inputs, output);

        i64 cc = 0;
        memcpy(&cc, output[0].data(), output[0].sizeBytes());
        cc = signExtend(cc, cSize);

        if (cc != c)
        {
            std::cout << "i " << i << std::endl;
            BitVector cExp;
            cExp.append((u8*)&c, cSize);
            std::cout << " a : " << inputs[0] << "  " << a << std::endl;
            std::cout << "/b : " << inputs[1] << "  " << b << std::endl;
            std::cout << "exp: " << cExp << "   " << c << std::endl;
            std::cout << "act: " << output[0] << "   " << cc << std::endl;

            throw UnitTestFail();
        }
    }
}




void Circuit_int_LessThan_Test()
{
    setThreadName("CP_Test_Thread");


    CircuitLibrary lib;


    PRNG prng(ZeroBlock);
    u64 tries = 200;


    for (u64 i = 0; i < tries; ++i)
    {

        u64 aSize = prng.get<u32>() % 16 + 1,
            bSize = prng.get<u32>() % 16 + 1;

        auto* cir = lib.int_int_lt(aSize, bSize);


        i64 a = signExtend(prng.get<i64>(), aSize);
        i64 b = signExtend(prng.get<i64>(), bSize);
        bool c = a < b;


        std::vector<BitVector> inputs(2), output(1);
        inputs[0].append((u8*)&a, aSize);
        inputs[1].append((u8*)&b, bSize);
        output[0].resize(1);

        cir->evaluate(inputs, output);

        i64 cc = 0;
        memcpy(&cc, output[0].data(), output[0].sizeBytes());

        if ((bool)cc != c)
        {
            std::cout << "i " << i << std::endl;
            std::cout << " a : " << inputs[0] << "  " << a << std::endl;
            std::cout << "<b : " << inputs[1] << "  " << b << std::endl;
            std::cout << "exp: " << c << std::endl;
            std::cout << "act: " << output[0] << "   " << cc << std::endl;


            cir = lib.int_int_subtract(aSize, bSize, std::max(aSize, bSize));
            output.clear();
            output.emplace_back(std::max(aSize, bSize));

            cir->evaluate(inputs, output);

            std::cout << "act: " << output[0] << "   " << cc << std::endl;


            throw UnitTestFail();
        }
    }
}




void Circuit_int_GreaterThanEq_Test()
{
    setThreadName("CP_Test_Thread");


    CircuitLibrary lib;


    PRNG prng(ZeroBlock);
    u64 tries = 200;


    for (u64 i = 0; i < tries; ++i)
    {

        u64 aSize = prng.get<u32>() % 16 + 1,
            bSize = prng.get<u32>() % 16 + 1;

        auto* cir = lib.int_int_gteq(aSize, bSize);


        i64 a = signExtend(prng.get<i64>(), aSize);
        i64 b = signExtend(prng.get<i64>(), bSize);
        bool c = a >= b;


        std::vector<BitVector> inputs(2), output(1);
        inputs[0].append((u8*)&a, aSize);
        inputs[1].append((u8*)&b, bSize);
        output[0].resize(1);

        cir->evaluate(inputs, output);

        i64 cc = 0;
        memcpy(&cc, output[0].data(), output[0].sizeBytes());

        if (cc != c)
        {
            std::cout << "i " << i << std::endl;
            std::cout << "  a : " << inputs[0] << "  " << a << std::endl;
            std::cout << ">=b: " << inputs[1] << "  " << b << std::endl;
            std::cout << "exp: " << c << std::endl;
            std::cout << "act: " << output[0] << "   " << cc << std::endl;


            cir = lib.int_int_subtract(aSize, bSize, std::max(aSize, bSize));
            output.clear();
            output.emplace_back(std::max(aSize, bSize));

            cir->evaluate(inputs, output);

            std::cout << "act: " << output[0] << "   " << cc << std::endl;


            throw UnitTestFail();
        }
    }
}

void Circuit_uint_LessThan_Test()
{
    setThreadName("CP_Test_Thread");


    CircuitLibrary lib;


    PRNG prng(ZeroBlock);
    u64 tries = 200;


    for (u64 i = 0; i < tries; ++i)
    {

        u64 aSize = prng.get<u32>() % 16 + 1,
            bSize = prng.get<u32>() % 16 + 1;
        
        u64 aMask = (u64(1) << aSize) - 1;
        u64 bMask = (u64(1) << bSize) - 1;


        u64 a = prng.get<u64>() & aMask;
        u64 b = prng.get<u64>() & bMask;
        bool c = a < b;


        auto* cir = lib.uint_uint_lt(aSize, bSize);
        std::vector<BitVector> inputs(2), output(1);
        inputs[0].append((u8*)&a, aSize);
        inputs[1].append((u8*)&b, bSize);
        output[0].resize(1);

        cir->evaluate(inputs, output);

        i64 cc = 0;
        memcpy(&cc, output[0].data(), output[0].sizeBytes());

        if (cc != c)
        {
            std::cout << "i " << i << std::endl;
            std::cout << " a : " << inputs[0] << "  " << a << std::endl;
            std::cout << "<b : " << inputs[1] << "  " << b << std::endl;
            std::cout << "exp: " << c << std::endl;
            std::cout << "act: " << output[0] << "   " << cc << std::endl;


            cir = lib.int_int_subtract(aSize, bSize, std::max(aSize, bSize));
            output.clear();
            output.emplace_back(std::max(aSize, bSize));

            cir->evaluate(inputs, output);

            std::cout << "act: " << output[0] << "   " << cc << std::endl;


            throw UnitTestFail();
        }
    }
}




void Circuit_uint_GreaterThanEq_Test()
{
    setThreadName("CP_Test_Thread");


    CircuitLibrary lib;


    PRNG prng(ZeroBlock);
    u64 tries = 200;


    for (u64 i = 0; i < tries; ++i)
    {

        u64 aSize = prng.get<u32>() % 16 + 1,
            bSize = prng.get<u32>() % 16 + 1;

        u64 aMask = (u64(1) << aSize) - 1;
        u64 bMask = (u64(1) << bSize) - 1;

        u64 a = prng.get<u64>() & aMask;
        u64 b = prng.get<u64>() & bMask;
        bool c = a >= b;

        auto* cir = lib.uint_uint_gteq(aSize, bSize);


        std::vector<BitVector> inputs(2), output(1);
        inputs[0].append((u8*)&a, aSize);
        inputs[1].append((u8*)&b, bSize);
        output[0].resize(1);

        cir->evaluate(inputs, output);


        i64 cc = 0;
        memcpy(&cc, output[0].data(), output[0].sizeBytes());
            std::cout << "i " << i << std::endl;
            std::cout << "  a: " << inputs[0] << "  " << a << std::endl;
            std::cout << ">=b: " << inputs[1] << "  " << b << std::endl;
            std::cout << "exp: " << c << std::endl;
            std::cout << "act: " << output[0] << "   " << cc << std::endl;


            cir = lib.int_int_subtract(aSize, bSize, std::max(aSize, bSize));
            output.clear();
            output.emplace_back(std::max(aSize, bSize));

            cir->evaluate(inputs, output);

            std::cout << "act: " << output[0] << "   " << cc << std::endl;


        if (cc != c)
        {

            throw UnitTestFail();
        }
    }
}



void Circuit_multiplex_Test()
{
    setThreadName("CP_Test_Thread");


    CircuitLibrary lib;


    PRNG prng(ZeroBlock);
    u64 tries = 200;


    for (u64 i = 0; i < tries; ++i)
    {

        u64 aSize = prng.get<u32>() % 16 + 1;

        auto* cir = lib.int_int_multiplex(aSize);


        i64 a = signExtend(prng.get<i64>(), aSize);
        i64 b = signExtend(prng.get<i64>(), aSize);
        i64 c = prng.getBit();
        i64 d = c ? a : b;


        std::vector<BitVector> inputs(3), output(1);
        inputs[0].append((u8*)&a, aSize);
        inputs[1].append((u8*)&b, aSize);
        inputs[2].append((u8*)&c, 1);
        output[0].resize(aSize);

        cir->evaluate(inputs, output);

        i64 cc = 0;
        memcpy(&cc, output[0].data(), output[0].sizeBytes());
        cc = signExtend(cc, aSize);

        if (cc != d)
        {
            std::cout << "i " << i << std::endl;
            std::cout << "  a : " << inputs[0] << "  " << a << std::endl;
            std::cout << "  b : " << inputs[1] << "  " << b << std::endl;
            std::cout << "  c : " << inputs[2] << "  " << c << std::endl;
            std::cout << "exp: " << d << "  " << c << std::endl;
            std::cout << "act: " << output[0] << "   " << cc << std::endl;


            throw UnitTestFail();
        }
    }
}



void Circuit_bitInvert_Test()
{
    setThreadName("CP_Test_Thread");


    CircuitLibrary lib;


    PRNG prng(ZeroBlock);
    u64 tries = 200;


    for (u64 i = 0; i < tries; ++i)
    {

        u64 aSize = prng.get<u32>() % 16 + 1;

        auto* cir = lib.int_bitInvert(aSize);


        i64 a = signExtend(prng.get<i64>(), aSize);
        i64 d = ~a;


        std::vector<BitVector> inputs(1), output(1);
        inputs[0].append((u8*)&a, aSize);
        output[0].resize(aSize);

        cir->evaluate(inputs, output);

        i64 cc = 0;
        memcpy(&cc, output[0].data(), output[0].sizeBytes());
        cc = signExtend(cc, aSize);

        if (cc != d)
        {
            std::cout << "i " << i << std::endl;
            std::cout << "  a : " << inputs[0] << "  " << a << std::endl;
            std::cout << "exp: " << d << std::endl;
            std::cout << "act: " << output[0] << "   " << cc << std::endl;


            throw UnitTestFail();
        }
    }
}



void Circuit_negate_Test()
{
    setThreadName("CP_Test_Thread");


    CircuitLibrary lib;


    PRNG prng(ZeroBlock);
    u64 tries = 200;


    for (u64 i = 0; i < tries; ++i)
    {

        u64 aSize = prng.get<u32>() % 16 + 1;

        auto* cir = lib.int_negate(aSize);


        i64 a = signExtend(prng.get<i64>(), aSize);
        i64 d = signExtend (-a, aSize);


        std::vector<BitVector> inputs(1), output(1);
        inputs[0].append((u8*)&a, aSize);
        output[0].resize(aSize);

        cir->evaluate(inputs, output);

        i64 cc = 0;
        memcpy(&cc, output[0].data(), output[0].sizeBytes());
        cc = signExtend(cc, aSize);

        if (cc != d)
        {
            std::cout << "i " << i << std::endl;
            std::cout << "  a : " << inputs[0] << "  " << a << std::endl;
            std::cout << "exp: " << d << std::endl;
            std::cout << "act: " << output[0] << "   " << cc << std::endl;


            throw UnitTestFail();
        }
    }
}



void Circuit_removeSign_Test()
{
    setThreadName("CP_Test_Thread");


    CircuitLibrary lib;


    PRNG prng(ZeroBlock);
    u64 tries = 200;


    for (u64 i = 0; i < tries; ++i)
    {

        u64 aSize = prng.get<u32>() % 16 + 1;

        auto* cir = lib.int_removeSign(aSize);


        i64 a = signExtend(prng.get<i64>(), aSize);
        i64 c = signExtend(a < 0? -a : a, aSize);


        std::vector<BitVector> inputs(1), output(1);
        inputs[0].append((u8*)&a, aSize);
        output[0].resize(aSize);

        cir->evaluate(inputs, output);

        i64 cc = 0;
        memcpy(&cc, output[0].data(), output[0].sizeBytes());
        cc = signExtend(cc, aSize);

        if (cc != c)
        {
            std::cout << "i " << i << std::endl;
            std::cout << "  a : " << inputs[0] << "  " << a << std::endl;
            std::cout << "exp: " << c << std::endl;
            std::cout << "act: " << output[0] << "   " << cc << std::endl;


            throw UnitTestFail();
        }
    }
}

void Circuit_addSign_Test()
{
    setThreadName("CP_Test_Thread");


    CircuitLibrary lib;


    PRNG prng(ZeroBlock);
    u64 tries = 200;


    for (u64 i = 0; i < tries; ++i)
    {

        u64 aSize = prng.get<u32>() % 16 + 1;

        auto* cir = lib.int_addSign(aSize);


        i64 a = signExtend(prng.get<i64>(), aSize);
        bool sign = prng.getBit();
        i64 c = signExtend(sign ? -a : a, aSize);


        std::vector<BitVector> inputs(2), output(1);
        inputs[0].append((u8*)&a, aSize);
        inputs[1].append((u8*)&sign, 1);
        output[0].resize(aSize);

        cir->evaluate(inputs, output);

        i64 cc = 0;
        memcpy(&cc, output[0].data(), output[0].sizeBytes());
        cc = signExtend(cc, aSize);

        if (cc != c)
        {
            std::cout << "i " << i << std::endl;
            std::cout << "  a : " << inputs[0] << "  " << a << std::endl;
            std::cout << "exp: " << c << std::endl;
            std::cout << "act: " << output[0] << "   " << cc << std::endl;


            throw UnitTestFail();
        }
    }
}