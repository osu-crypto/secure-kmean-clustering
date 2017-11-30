#include <iostream>

//using namespace std;
#include "tests_cryptoTools/UnitTests.h"
#include "libOTe_Tests/UnitTests.h"

#include <cryptoTools/Common/Defines.h>
using namespace osuCrypto;

#include "libOTe/TwoChooseOne/KosOtExtReceiver.h"
#include "libOTe/TwoChooseOne/KosOtExtSender.h"
#include "libOTe/TwoChooseOne/KosDotExtReceiver.h"
#include "libOTe/TwoChooseOne/KosDotExtSender.h"

#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Network/Endpoint.h>
#include <cryptoTools/Network/IOService.h>
#include <numeric>
#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Common/Log.h>
int miraclTestMain();

#include "libOTe/Tools/LinearCode.h"
#include "libOTe/Tools/bch511.h"
#include "libOTe/NChooseOne/Oos/OosNcoOtReceiver.h"
#include "libOTe/NChooseOne/Oos/OosNcoOtSender.h"
#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtReceiver.h"
#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtSender.h"

#include "libOTe/TwoChooseOne/IknpOtExtReceiver.h"
#include "libOTe/TwoChooseOne/IknpOtExtSender.h"

#include "libOTe/NChooseK/AknOtReceiver.h"
#include "libOTe/NChooseK/AknOtSender.h"
#include "libOTe/TwoChooseOne/LzKosOtExtReceiver.h"
#include "libOTe/TwoChooseOne/LzKosOtExtSender.h"

#include "CLP.h"
#include "main.h"



void kkrt_test(int i)
{
    setThreadName("Sender");

    PRNG prng0(_mm_set_epi32(4253465, 3434565, 234435, 23987045));

    u64 step = 1024;
    u64 numOTs = 1 << 16;
    u64 numThreads = 1;

    u64 otsPer = numOTs / numThreads;

    auto rr = i ? EpMode::Server : EpMode::Client;
    std::string name = "n";
    IOService ios(0);
    Endpoint ep0(ios, "localhost", 1212, rr, name);
    std::vector<Channel> chls(numThreads);

    for (u64 k = 0; k < numThreads; ++k)
        chls[k] = ep0.addChannel(name + ToString(k), name + ToString(k));



    u64 ncoinputBlkSize = 1, baseCount = 4 * 128;
    u64 codeSize = (baseCount + 127) / 128;

    std::vector<block> baseRecv(baseCount);
    std::vector<std::array<block, 2>> baseSend(baseCount);
    BitVector baseChoice(baseCount);
    baseChoice.randomize(prng0);

    prng0.get((u8*)baseSend.data()->data(), sizeof(block) * 2 * baseSend.size());
    for (u64 i = 0; i < baseCount; ++i)
    {
        baseRecv[i] = baseSend[i][baseChoice[i]];
    }

    block choice = prng0.get<block>();// ((u8*)choice.data(), ncoinputBlkSize * sizeof(block));

    std::vector<std::thread> thds(numThreads);

    if (i == 0)
    {

        for (u64 k = 0; k < numThreads; ++k)
        {
            thds[k] = std::thread(
                [&, k]()
            {
                KkrtNcoOtReceiver r;
                r.setBaseOts(baseSend);
                auto& chl = chls[k];

                r.init(otsPer, prng0, chl);
                block encoding1;
                for (u64 i = 0; i < otsPer; i += step)
                {
                    for (u64 j = 0; j < step; ++j)
                    {
                        r.encode(i + j, &choice, &encoding1);
                    }

                    r.sendCorrection(chl, step);
                }
                r.check(chl, ZeroBlock);

                chl.close();
            });
        }
        for (u64 k = 0; k < numThreads; ++k)
            thds[k].join();
    }
    else
    {
        Timer time;
        time.setTimePoint("start");
        block encoding2;

        for (u64 k = 0; k < numThreads; ++k)
        {
            thds[k] = std::thread(
                [&, k]()
            {
                KkrtNcoOtSender s;
                s.setBaseOts(baseRecv, baseChoice);
                auto& chl = chls[k];

                s.init(otsPer, prng0, chl);
                for (u64 i = 0; i < otsPer; i += step)
                {

                    s.recvCorrection(chl, step);

                    for (u64 j = 0; j < step; ++j)
                    {
                        s.encode(i + j, &choice, &encoding2);
                    }
                }
                s.check(chl, ZeroBlock);
                chl.close();
            });
        }


        for (u64 k = 0; k < numThreads; ++k)
            thds[k].join();

        time.setTimePoint("finish");
        std::cout << time << std::endl;
    }


    //for (u64 k = 0; k < numThreads; ++k)
        //chls[k]->close();

    ep0.stop();
    ios.stop();
}


void iknp_test(int i)
{
    setThreadName("Sender");

    PRNG prng0(_mm_set_epi32(4253465, 3434565, 234435, 23987045));

    u64 numOTs = 1 << 16;

    auto rr = i ? EpMode::Server : EpMode::Client;

    // get up the networking
    std::string name = "n";
    IOService ios(0);
    Endpoint ep0(ios, "localhost", 1212, rr, name);
    Channel chl = ep0.addChannel(name, name);


    // cheat and compute the base OT in the clear.
    u64 baseCount = 128;
    std::vector<block> baseRecv(baseCount);
    std::vector<std::array<block, 2>> baseSend(baseCount);
    BitVector baseChoice(baseCount);
    baseChoice.randomize(prng0);

    prng0.get((u8*)baseSend.data()->data(), sizeof(block) * 2 * baseSend.size());
    for (u64 i = 0; i < baseCount; ++i)
    {
        baseRecv[i] = baseSend[i][baseChoice[i]];
    }




    if (i)
    {
        BitVector choice(numOTs);
        std::vector<block> msgs(numOTs);
        choice.randomize(prng0);
        IknpOtExtReceiver r;
        r.setBaseOts(baseSend);

        r.receive(choice, msgs, prng0, chl);
    }
    else
    {
        std::vector<std::array<block, 2>> msgs(numOTs);

        Timer time;
        time.setTimePoint("start");
        IknpOtExtSender s;
        s.setBaseOts(baseRecv, baseChoice);

        s.send(msgs, prng0, chl);

        time.setTimePoint("finish");
        std::cout << time << std::endl;

    }


    chl.close();

    ep0.stop();
    ios.stop();
}

void code()
{
    PRNG prng(ZeroBlock);
    LinearCode code;
    code.random(prng, 128, 128 * 4);
    u64 n = 1 << 24;

    Timer t;
    t.setTimePoint("start");

    u8* in = new u8[code.plaintextU8Size()];
    u8* out = new u8[code.codewordU8Size()];

    for (u64 i = 0; i < n; ++i)
    {
        code.encode(in, out);
    }

    t.setTimePoint("end");
    std::cout << t << std::endl;
}



void base()
{

    IOService ios(0);
    Endpoint  ep0(ios, "127.0.0.1", 1212, EpMode::Server, "ep");
    Endpoint  ep1(ios, "127.0.0.1", 1212, EpMode::Client, "ep");

    auto chl1 = ep1.addChannel("s");
    auto chl0 = ep0.addChannel("s");


    NaorPinkas send, recv;


    auto thrd = std::thread([&]() {

        std::array<std::array<block, 2>, 128> msg;
        PRNG prng(ZeroBlock);

        for (u64 i = 0; i < 10; ++i)
            send.send(msg, prng, chl0);
    });


    std::array<block, 128> msg;
    PRNG prng(ZeroBlock);
    BitVector choice(128);

    Timer t;
    t.setTimePoint("s");
    for (u64 i = 0; i < 10; ++i)
    {

        recv.receive(choice, msg, prng, chl1);
        t.setTimePoint("e");


    }
    std::cout << t << std::endl;


    thrd.join();

    chl1.close();
    chl0.close();

}

#include <cryptoTools/gsl/span>

#include <cryptoTools/Common/Matrix.h>

int main(int argc, char** argv)
{

  std::cout << "main here" << std::endl;
	/*auto thrd = std::thread([]() { iknp_test(0); });
	iknp_test(1);
	thrd.join();

  
	thrd = std::thread([]() { kkrt_test(0); });
	kkrt_test(1);
	thrd.join();*/


	return 0;
}
