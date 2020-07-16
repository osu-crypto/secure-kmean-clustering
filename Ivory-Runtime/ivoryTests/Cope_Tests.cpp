#include "Cope_Tests.h"

//#include "CopeOtExtReceiver.h"
//#include "CopeOtExtSender.h"

#include "libOTe/Tools/Tools.h"
#include "cryptoTools/Network/Channel.h"
#include "cryptoTools/Network/Session.h"
#include "cryptoTools/Common/Log.h"
#include "cryptoTools/Common/BitVector.h"
#include "Common.h"
using namespace osuCrypto;

void cope_test()
{

    return;

    //setThreadName("Sender");

    //IOService ios(0);
    //Session ep0(ios, "127.0.0.1", 1212, SessionMode::Server, "ep");
    //Session ep1(ios, "127.0.0.1", 1212, SessionMode::Client, "ep");
    //Channel& senderChannel = ep1.addChannel("chl", "chl");
    //Channel& recvChannel = ep0.addChannel("chl", "chl");

    //PRNG prng0(_mm_set_epi32(4253465, 3434565, 234435, 23987045));
    //PRNG prng1(_mm_set_epi32(4253233465, 334565, 0, 235));

    //u64 numShares = 1;

    //ZpField field(ZpParam128);

    //std::vector<ZpNumber>
    //    recvShare(numShares, ZpNumber(field)),
    //    recvChoice(numShares, ZpNumber(field)),
    //    sendShare(numShares, ZpNumber(field));

    //std::vector<block> baseRecv(128);
    //std::vector<std::array<block, 2>> baseSend(128);
    //BitVector baseChoice(128);
    //baseChoice.randomize(prng0);
    ////baseChoice[0] = 1;

    //for (u64 i = 0; i < 128; ++i)
    //{
    //    baseSend[i][0] = prng0.get<block>();
    //    baseSend[i][1] = prng0.get<block>();
    //    baseRecv[i] = baseSend[i][baseChoice[i]];
    //}


    //for (u64 i = 0; i < numShares; ++i)
    //{
    //    recvChoice[i].randomize(prng0);
    //}

    //CopeOtExtSender sender;
    //CopeOtExtReceiver recv;

    //std::thread thrd = std::thread([&]() {
    //    setThreadName("receiver");

    //    recv.setBaseOts(baseSend);
    //    recv.receive(recvChoice, recvShare, prng0, recvChannel);
    //});

    //sender.setBaseOts(baseRecv, baseChoice);

    //sender.send(sendShare, senderChannel);
    //thrd.join();



    //senderChannel.close();
    //recvChannel.close();


    //ep1.stop();
    //ep0.stop();

    //ios.stop();


    //ZpNumber delta(field);
    //delta.fromBits(baseChoice.data());

    //for (u64 i = 0; i < numShares; ++i)
    //{


    //    if (sendShare[i] + recvShare[i] != recvChoice[i] * delta)
    //    {
    //        std::cout << "i = " << i << "\n";
    //        std::cout << "sendShare[i]  = " << sendShare[i] << "  (- " << -sendShare[i]   <<")\n";
    //        std::cout << "recvShare[i]  = " << recvShare[i] << "\n";
    //        std::cout << "            + ___________________________________\n";
    //        std::cout << "                " << sendShare[i] + recvShare[i] << "\n\n";
    //        std::cout << "detla         = " << delta << "\n";
    //        std::cout << "recvChoice[i] = " << recvChoice[i] << "\n";
    //        std::cout << "            * ___________________________________\n";
    //        std::cout << "                " << recvChoice[i] * delta << "\n\n";

    //        throw UnitTestFail();
    //    }
    //}

}
