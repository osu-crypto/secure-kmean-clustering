//#include "stdafx.h"

#include <thread>
#include <vector>
#include <memory>

#include "Common.h"
#include "cryptoTools/Common/Defines.h"
#include "ZpNumber_Tests.h"
//#include "Math/ZpField.h"


#include "cryptoTools/Common/BitVector.h"

using namespace osuCrypto;

void ZpNumber_ToBits_Test()
{
    //ZpField field(ZpParam128);

    //PRNG prng(ZeroBlock);

    //ZpNumber one(field, 1);

    //BitVector bv(128);
    //bv[0] = 1;



    //ZpNumber nn(field);

    //nn.fromBits(bv.data());
    //BitVector vv(128);


    //nn.toBits(vv.data());

    //std::cout << vv << "\n" << bv << std::endl;

    //if (nn != one)
    //{
    //    BitVector onebv(128);
    //    one.toBits(onebv.data());

    //    std::cout << "one = " << one << "  " << onebv << std::endl;
    //    std::cout << "nn  = " << nn << "  " << bv << std::endl;

    //    throw UnitTestFail();
    //}
}


void ZpNumber_Basic_Test()
{

    //u64 mod = 23;
    //ZpField field(ZpParam5_INSECURE);

    //PRNG prng(ZeroBlock);

    //ZpNumber one(field, 1);
    //ZpNumber zero(field, 0);


    //if (one + one != 2)
    //{
    //    std::cout << one + one << std::endl;
    //    throw UnitTestFail("1 + 1 != 2");
    //}

    //if (one != one * one)
    //{
    //    std::cout << one << std::endl;
    //    std::cout << one * one << std::endl;
    //    throw UnitTestFail("1 != 1* 1");
    //}


    //u64 tryCount = 100;

    //for (u64 i = 0; i < tryCount; ++i)
    //{

    //    auto mult_var = one;
    //    auto mult_var2 = one;
    //    auto mult_expected = u64(1);

    //    auto div_var = one;


    //    auto add_var = zero;
    //    auto add_expected = u64(0);
    //    auto sub_var = zero;
    //    auto sub_exp = i64(0);

    //    for (u64 j = 0; j < 20; ++j)
    //    {
    //        // sample Z*_p
    //        auto mult = (prng.get<u64>() % (mod - 1)) + 1;

    //        //std::cout << "mult in " << mult << std::endl;

    //        // sample Z_p
    //        auto add = prng.get<u64>() % mod;

    //        mult_expected = mult_expected * mult % mod;
    //        mult_var = mult_var * mult;
    //        mult_var2 = mult_var2 * ZpNumber(field, mult);

    //        div_var = div_var / mult;

    //        add_expected = (add_expected + add) % mod;
    //        add_var = add_var + add;

    //        sub_var = sub_var - add;
    //        sub_exp = (add > sub_exp ? (sub_exp - add + mod) : sub_exp - add) % mod;

    //        if (mult_var != mult_expected || mult_var2 != mult_expected)
    //        {
    //            std::cout << i << "  " << j << std::endl;
    //            std::cout << "mult var  " << mult_var << std::endl;
    //            std::cout << "mult var2 " << mult_var << std::endl;
    //            std::cout << "mult exp  " << std::hex << mult_expected << std::dec << std::endl;
    //            throw UnitTestFail("mod mult error");
    //        }

    //        if (add_var != add_expected)
    //        {
    //            std::cout << i << "  " << j << std::endl;
    //            std::cout << "add var  " << add_var << std::endl;
    //            std::cout << "add exp  " << std::hex << add_expected << std::dec << std::endl;
    //            throw UnitTestFail("mod add error");
    //        }


    //        if (sub_var != sub_exp)
    //        {
    //            std::cout << i << "  " << j << std::endl;
    //            std::cout << "sub var  " << sub_var << std::endl;
    //            std::cout << "sub exp  " << std::hex << sub_exp << std::dec << std::endl;
    //            throw UnitTestFail("mod add error");
    //        }





    //        if (div_var != one / mult_var)
    //        {
    //            std::cout << "div var  " << div_var << std::endl;
    //            std::cout << "div exp  " << one / mult_var << std::endl;
    //            throw UnitTestFail("mod div error");
    //        }

    //        if (sub_var != -add_var)
    //        {
    //            std::cout << "sub var  " << sub_var << std::endl;
    //            std::cout << "neg add  " << -add_var << std::endl;
    //            throw UnitTestFail("mod div error");
    //        }




    //    }




    //}

    //ZpNumber two(field, 2);
    //for (u32 i = 0; i < 32; ++i)
    //{
    //    auto tt = two;
    //    if (two.pow(i) != (u32(1) << i) % mod)
    //    {
    //        std::cout << i << std::endl;
    //        std::cout << "2^" << i << " = " << two.pow(i) << std::endl;
    //        throw UnitTestFail("mod div error");
    //    }

    //    if (tt.powEq(i) != (u32(1) << i) % mod)
    //    {
    //        std::cout << i << std::endl;
    //        std::cout << "2^" << i << " = " << tt << std::endl;
    //        throw UnitTestFail("mod div error");
    //    }
    //}
    //for (u64 i = 0; i < tryCount; ++i)
    //{

    //    ZpNumber val0(field, prng);
    //    ZpNumber val1(field, prng);

    //    auto mul = val0 * val1;
    //    auto add = val0 + val1;

    //    ZpNumber copy = mul;
    //    auto div = copy;
    //    div /= val1;

    //    if (!val1.iszero() && div != val0)
    //    {
    //        std::cout << "copy       = " << copy << std::endl;
    //        std::cout << "mul        = " << mul << std::endl;
    //        std::cout << "val1       = " << val1 << std::endl;
    //        std::cout << "mul / val1 = " << div << std::endl;
    //        std::cout << "val0       = " << val0 << std::endl;
    //        throw UnitTestFail();
    //    }

    //    if (!val0.iszero() && mul / val0 != val1)
    //    {

    //        std::cout << "      val0 = " << val0 << std::endl;
    //        std::cout << "mul /val0  = " << mul / val0 << std::endl;
    //        std::cout << "val1       = " << val1 << std::endl;
    //        throw UnitTestFail();
    //    }

    //    if (add - val0 != val1)
    //    {
    //        std::cout << "add - val0 = " << add - val0 << std::endl;
    //        std::cout << "val1       = " << val1 << std::endl;

    //        throw UnitTestFail();
    //    }
    //    if (add - val1 != val0)
    //    {
    //        std::cout << "add - val1 = " << add - val1 << std::endl;
    //        std::cout << "val0       = " << val0 << std::endl;

    //        throw UnitTestFail();
    //    }

    //}

    //if (zero - 1 != mod - 1)
    //{
    //    std::cout << "-1 = " << zero - 1 << " != " << mod - 1 << std::endl;
    //    throw UnitTestFail("-1 mod p");
    //}

    ////bool ok = false;
    //for (u64 i = 0; i < tryCount; ++i)
    //{
    //    ZpNumber var(field, prng);
    //    //std::cout << var << std::endl;

    //    //if (var == 22)
    //    //{
    //    //    ok = true;
    //    //}

    //    if (var > (mod - 1))
    //    {
    //        std::cout << "bad rand'" << std::endl;
    //        std::cout << "var " << var << std::endl;
    //        std::cout << "mod " << std::hex << mod << std::dec << std::endl;
    //        std::cout << "odr " << field.getFieldPrime() << std::endl;
    //        throw UnitTestFail("bad rand'");
    //    }
    //}

    ////if (ok == false)
    ////{
    ////    std::cout << "bad rand 22" << std::endl;
    ////    throw UnitTestFail("bad rand 22");
    ////}


    //ZpNumber rand(field, prng), r(field);

    //ByteStream buff(rand.sizeBytes());

    //rand.toBytes(buff.data());

    //r.fromBytes(buff.data());

    //if (r != rand)
    //{
    //    std::cout << "r    " << rand << std::endl;
    //    std::cout << "r'   " << r << std::endl;

    //    throw UnitTestFail("");
    //}


}



void ZpNumber_BasicLarge_Test()
{
/*
    ZpField field(ZpParam128);

    PRNG prng(ZeroBlock);

    ZpNumber one(field, 1);
    ZpNumber zero(field, 0);


    if (one + one != 2)
    {
        std::cout << one + one << std::endl;
        throw UnitTestFail("1 + 1 != 2");
    }

    if (one != one * one)
    {
        std::cout << one << std::endl;
        std::cout << one * one << std::endl;
        throw UnitTestFail("1 != 1* 1");
    }


    u64 tryCount = 100;
    for (u64 i = 0; i < tryCount; ++i)
    {

        ZpNumber val0(field, prng);
        ZpNumber val1(field, prng);

        auto mul = val0 * val1;
        auto add = val0 + val1;

        ZpNumber copy = mul;
        auto div = copy;
        div /= val1;

        if (div != val0)
        {
            std::cout << "copy       = " << copy << std::endl;
            std::cout << "mul        = " << mul << std::endl;
            std::cout << "val1       = " << val1 << std::endl;
            std::cout << "mul / val1 = " << div << std::endl;
            std::cout << "val0       = " << val0 << std::endl;
            throw UnitTestFail();
        }

        if (mul / val0 != val1)
            throw UnitTestFail();

        if (add - val0 != val1 || add - val1 != val0)
            throw UnitTestFail();

    }

    ZpNumber rand(field, prng), r(field);
    ByteStream buff(rand.sizeBytes());
    rand.toBytes(buff.data());
    r.fromBytes(buff.data());

    if (r != rand)
    {
        std::cout << "r    " << rand << std::endl;
        std::cout << "r'   " << r << std::endl;

        throw UnitTestFail("");
    }*/
}