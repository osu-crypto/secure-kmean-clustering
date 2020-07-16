#pragma once
#include "ivory/Runtime/Runtime.h"
#include "ivory/Circuit/Circuit.h"
#include "ivory/Circuit/BetaCircuit.h"
#include "ivory/Circuit/CircuitLibrary.h"




#include "libOTe/TwoChooseOne/IknpOtExtSender.h"
#include "libOTe/TwoChooseOne/IknpOtExtReceiver.h"

#include <queue>
#include <ivory/Runtime/ShGc/utils.h>


namespace osuCrypto
{
    //typedef std::vector<block> ShGcLabelVec;

    //struct ShGcRuntimeData :public RuntimeData
    //{
    //    ShGcRuntimeData(u64 bitCount)
    //        : mLabels(std::make_shared<ShGcLabelVec>(bitCount))
    //    { }

    //    std::shared_ptr<ShGcLabelVec> mLabels;
    //};

    class ShGcRuntime : public Runtime
    {
    public:
        enum Role
        {
            Garbler,
            Evaluator
        };
        static const std::array<block, 2> mPublicLabels;

        ShGcRuntime();
        ~ShGcRuntime();

        void init(Channel& chl, block seed, Role role, u64 partyIdx);

        ShGc::GarbledMem getNewMem(u64 size);
        void freeMem(const ShGc::GarbledMem& mem);

        sInt sIntInput(BitCount bc, u64 partyIdx) override;
        sInt sIntInput(sInt::ValueType v, BitCount bc) override;




        u64 getPartyIdx() override { return mPartyIdx; }

        CircuitLibrary mLibrary;



        Role mRole;
        u64 mPartyIdx;
		bool mDebugFlag = false;

        u64 mBytesSent;
        std::array<block,2> mZeroAndGlobalOffset;
        block mGlobalOffset;
        AES mAes;
        PRNG mPrng;
        u64 mInputIdx;
        Channel* mChannel;

        IknpOtExtReceiver mOtExtRecver;
        IknpOtExtSender mOtExtSender;

        std::vector<block> sharedMem;
        //std::vector<GarbledGate<2>> sharedGates;
		std::vector<u8> shareAuxBits;
        std::vector<block> sharedBuff;
        std::array<block, 2>mTweaks;

        ShGc::GarbledMem getPublicGarbledMem(u8* data, u64 bitCount);

        void enqueue(ShGc::InputItem&& item);
        void enqueue(ShGc::CircuitItem&& item);
        void enqueue(ShGc::OutputItem&& item);
        void processesQueue() override;

        void garblerOutput();
        void garblerCircuit();
        void garblerInput();

        void evaluatorInput();
        void evaluatorCircuit();
        void evaluatorOutput();

        BitVector mOtChoices;
        u64 mMaxQueueSize;
        u64 mOtCount;
        std::queue<ShGc::CircuitItem> mCrtQueue;
        std::queue<ShGc::InputItem> mInputQueue;
        std::queue<ShGc::OutputItem> mOutputQueue;

        static bool isConstLabel(const block& b);

        //std::queue<CircuitItem> mWorkQueue;
        //boost::lockfree::spsc_queue<CircuitItem*> mWorkQueue;

        static block evaluateConstGate(bool constA, bool constB, const std::array<block, 2>& in, const GateType& gt);
        static block garbleConstGate(bool constA, bool constB, const std::array<block, 2>& in, const GateType& gt, const block& xorOffset);

		std::function<bool()> mRecvBit;
        static void evaluate(
            const BetaCircuit& cir,
            const span<block>& memory,
            std::array<block, 2>& tweaks,
            const span<GarbledGate<2>>& garbledGates,
			const std::function<bool()>& getAuxilaryBit,
            block* DEBUG_labels = nullptr);


        static void garble(
            const BetaCircuit& cir,
            const span<block>& memory,
            std::array<block, 2>& tweaks,
            const span<GarbledGate<2>>&  garbledGateIter,
            const std::array<block,2>& zeroAndGlobalOffset,
			std::vector<u8>& auxilaryBits,
            block* DEBUG_labels = nullptr
        );

    };


}