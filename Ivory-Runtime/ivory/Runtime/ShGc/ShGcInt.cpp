#include "ShGcInt.h"
#include "ivory/Runtime/ShGc/ShGcRuntime.h"
#include "ivory/Runtime/Public/PublicInt.h"
namespace osuCrypto
{
    ShGcInt::ShGcInt(ShGcRuntime & rt, u64 bitCount)
        : mLabels(rt.getNewMem(bitCount))
        , mRt(rt)
    {}

    ShGcInt::~ShGcInt()
    {
        mRt.freeMem(mLabels);
    }

    void ShGcInt::copy(sIntBasePtr& c)
    {
        auto cc = dynamic_cast<ShGcInt*>(c.get());

        ShGc::CircuitItem w;
        w.mLabels.resize(2);
        w.mLabels[0] = cc->mLabels;
        w.mLabels[1] = mLabels;


        //mLabels = ShGcGarbledMem(new std::vector<block>(*cc->mLabels));

        //return sIntBasePtr(new ShGcInt(*this));
    }

    sIntBasePtr ShGcInt::copy()
    {
        return sIntBasePtr();
    }

    u64 ShGcInt::bitCount()
    {
        return mLabels->size();
    }

    Runtime & ShGcInt::getRuntime()
    {
        return mRt;
    }

    sIntBasePtr ShGcInt::add(sIntBasePtr& a, sIntBasePtr & b)
    {
        auto aa = getMemory(a);
        auto bb = getMemory(b);
        auto bc = std::max(aa->size(), bb->size());
        auto ret(new ShGcInt(mRt, bc));

        ShGc::CircuitItem workItem;
        workItem.mInputBundleCount = 2;
        workItem.mLabels.resize(3);
        workItem.mLabels[0] = aa;
        workItem.mLabels[1] = bb;
        workItem.mLabels[2] = ret->mLabels;

        workItem.mCircuit = mRt.mLibrary.int_int_add(
            workItem.mLabels[0]->size(),
            workItem.mLabels[1]->size(),
            workItem.mLabels[2]->size());


        mRt.enqueue(std::move(workItem));

        return sIntBasePtr(ret);
    }
    sIntBasePtr ShGcInt::subtract(sIntBasePtr& a, sIntBasePtr & b)
    {
        auto aa = getMemory(a);
        auto bb = getMemory(b);
        auto bc = std::max(aa->size(), bb->size());
        auto ret(new ShGcInt(mRt, bc));

        ShGc::CircuitItem workItem;
        workItem.mInputBundleCount = 2;
        workItem.mLabels.resize(3);
        workItem.mLabels[0] = aa;
        workItem.mLabels[1] = bb;
        workItem.mLabels[2] = ret->mLabels;

        workItem.mCircuit = mRt.mLibrary.int_int_subtract(
            workItem.mLabels[0]->size(),
            workItem.mLabels[1]->size(),
            workItem.mLabels[2]->size());

        mRt.enqueue(std::move(workItem));

        return sIntBasePtr(ret);
    }
    sIntBasePtr ShGcInt::multiply(sIntBasePtr& a, sIntBasePtr & b)
    {
        auto aa = getMemory(a);
        auto bb = getMemory(b);
        auto bc = std::max(aa->size(), bb->size());
        auto ret(new ShGcInt(mRt, bc));

        ShGc::CircuitItem workItem;
        workItem.mInputBundleCount = 2;
        workItem.mLabels.resize(3);
        workItem.mLabels[0] = aa;
        workItem.mLabels[1] = bb;
        workItem.mLabels[2] = ret->mLabels;

        workItem.mCircuit = mRt.mLibrary.int_int_mult(
            workItem.mLabels[0]->size(),
            workItem.mLabels[1]->size(),
            workItem.mLabels[2]->size());

        mRt.enqueue(std::move(workItem));

        return sIntBasePtr(ret);
    }

    sIntBasePtr ShGcInt::divide(sIntBasePtr& a, sIntBasePtr & b)
    {
        auto aa = getMemory(a);
        auto bb = getMemory(b);
        auto bc = std::max(aa->size(), bb->size());
        auto ret(new ShGcInt(mRt, bc));

        ShGc::CircuitItem workItem;
        workItem.mInputBundleCount = 2;
        workItem.mLabels.resize(3);
        workItem.mLabels[0] = aa;
        workItem.mLabels[1] = bb;
        workItem.mLabels[2] = ret->mLabels;

        workItem.mCircuit = mRt.mLibrary.int_int_div(
            workItem.mLabels[0]->size(),
            workItem.mLabels[1]->size(),
            workItem.mLabels[2]->size());

        mRt.enqueue(std::move(workItem));

        return sIntBasePtr(ret);
    }

    sIntBasePtr ShGcInt::negate()
    {
        auto ret(new ShGcInt(mRt, mLabels->size()));

        ShGc::CircuitItem workItem;
        workItem.mInputBundleCount = 1;
        workItem.mLabels.resize(2);
        workItem.mLabels[0] = mLabels;
        workItem.mLabels[1] = ret->mLabels;

        workItem.mCircuit = mRt.mLibrary.int_negate(
            workItem.mLabels[0]->size());

        mRt.enqueue(std::move(workItem));

        return sIntBasePtr(ret);
    }

	sIntBasePtr ShGcInt::abs()
	{
		auto ret(new ShGcInt(mRt, mLabels->size()));

		ShGc::CircuitItem workItem;
		workItem.mInputBundleCount = 1;
		workItem.mLabels.resize(2);
		workItem.mLabels[0] = mLabels;
		workItem.mLabels[1] = ret->mLabels;

		workItem.mCircuit = mRt.mLibrary.int_removeSign(
			workItem.mLabels[0]->size());

		mRt.enqueue(std::move(workItem));

		return sIntBasePtr(ret);
	}

    sIntBasePtr ShGcInt::gteq(sIntBasePtr& a, sIntBasePtr & b)
    {
        auto aa = getMemory(a);
        auto bb = getMemory(b);
        auto ret(new ShGcInt(mRt, 1));

        ShGc::CircuitItem workItem;
        workItem.mInputBundleCount = 2;
        workItem.mLabels.resize(3);
        workItem.mLabels[0] = aa;
        workItem.mLabels[1] = bb;
        workItem.mLabels[2] = ret->mLabels;

        workItem.mCircuit = mRt.mLibrary.int_int_gteq(
            workItem.mLabels[0]->size(),
            workItem.mLabels[1]->size());

        mRt.enqueue(std::move(workItem));

        return sIntBasePtr(ret);
    }

    sIntBasePtr ShGcInt::gt(sIntBasePtr& a, sIntBasePtr & b)
    {
        auto aa = getMemory(a);
        auto bb = getMemory(b);
        auto ret(new ShGcInt(mRt, 1));

        ShGc::CircuitItem workItem;
        workItem.mInputBundleCount = 2;
        workItem.mLabels.resize(3);
        workItem.mLabels[0] = bb;
        workItem.mLabels[1] = aa;
        workItem.mLabels[2] = ret->mLabels;

        workItem.mCircuit = mRt.mLibrary.int_int_lt(
            workItem.mLabels[0]->size(),
            workItem.mLabels[1]->size());

        mRt.enqueue(std::move(workItem));

        return sIntBasePtr(ret);
    }


	sIntBasePtr ShGcInt::ifequal(sIntBasePtr& a, sIntBasePtr & b)
	{
		auto aa = getMemory(a);
		auto bb = getMemory(b);
		auto ret(new ShGcInt(mRt, 1));

		ShGc::CircuitItem workItem;
		workItem.mInputBundleCount = 2;
		workItem.mLabels.resize(3);
		workItem.mLabels[0] = bb;
		workItem.mLabels[1] = aa;
		workItem.mLabels[2] = ret->mLabels;

		workItem.mCircuit = mRt.mLibrary.int_int_equal(
			workItem.mLabels[0]->size(),
			workItem.mLabels[1]->size());

		mRt.enqueue(std::move(workItem));

		return sIntBasePtr(ret);
	}

    sIntBasePtr ShGcInt::bitwiseInvert()
    {
        auto ret(new ShGcInt(mRt, mLabels->size()));

        ShGc::CircuitItem workItem;
        workItem.mInputBundleCount = 1;
        workItem.mLabels.resize(2);
        workItem.mLabels[0] = mLabels;
        workItem.mLabels[1] = ret->mLabels;

        workItem.mCircuit = mRt.mLibrary.int_bitInvert(
            workItem.mLabels[0]->size());

        mRt.enqueue(std::move(workItem));

        return sIntBasePtr(ret);
    }

    sIntBasePtr ShGcInt::bitwiseAnd(sIntBasePtr& a, sIntBasePtr & b)
    {
        auto aa = getMemory(a);
        auto bb = getMemory(b);
        auto ret(new ShGcInt(mRt, 1));

        ShGc::CircuitItem workItem;
        workItem.mInputBundleCount = 2;
        workItem.mLabels.resize(3);
        workItem.mLabels[0] = aa;
        workItem.mLabels[1] = bb;
        workItem.mLabels[2] = ret->mLabels;

        workItem.mCircuit = mRt.mLibrary.int_int_bitwiseAnd(
            workItem.mLabels[0]->size(),
            workItem.mLabels[1]->size(),
            workItem.mLabels[2]->size());

        mRt.enqueue(std::move(workItem));

        return sIntBasePtr(ret);
    }

    sIntBasePtr ShGcInt::bitwiseOr(sIntBasePtr& a, sIntBasePtr & b)
    {
        auto aa = getMemory(a);
        auto bb = getMemory(b);
        auto ret(new ShGcInt(mRt, 1));

        ShGc::CircuitItem workItem;
        workItem.mInputBundleCount = 2;
        workItem.mLabels.resize(3);
        workItem.mLabels[0] = aa;
        workItem.mLabels[1] = bb;
        workItem.mLabels[2] = ret->mLabels;

        workItem.mCircuit = mRt.mLibrary.int_int_bitwiseOr(
            workItem.mLabels[0]->size(),
            workItem.mLabels[1]->size(),
            workItem.mLabels[2]->size());

        mRt.enqueue(std::move(workItem));

        return sIntBasePtr(ret);
    }

    sIntBasePtr ShGcInt::ifelse(sIntBasePtr& a, sIntBasePtr & ifTrue, sIntBasePtr & ifFalse)
    {

        auto aa = getMemory(a);
        auto tt = getMemory(ifTrue);
        auto ff = getMemory(ifFalse);
        auto ret(new ShGcInt(mRt, tt->size()));
        sIntBasePtr rret(ret);

        ShGc::CircuitItem workItem;
        workItem.mInputBundleCount = 3;
        workItem.mLabels.resize(4);
        workItem.mLabels[0] = tt;
        workItem.mLabels[1] = ff;
        workItem.mLabels[2] = aa;
        workItem.mLabels[3] = ret->mLabels;

        if (workItem.mLabels[0]->size() != workItem.mLabels[1]->size() ||
            workItem.mLabels[0]->size() != workItem.mLabels[3]->size())
            throw std::runtime_error("IfElse must be performed with variables of the same bit length. " LOCATION);
        if (workItem.mLabels[2]->size()!= 1)
            throw std::runtime_error(LOCATION);

        workItem.mCircuit = mRt.mLibrary.int_int_multiplex(workItem.mLabels[0]->size());

        mRt.enqueue(std::move(workItem));

        return rret;
    }

    void ShGcInt::reveal(u64 partyIdx)
    {
        std::array<u64, 1> p{ partyIdx };
        reveal(p);
    }

    void ShGcInt::reveal(span<u64> pIdxs)
    {
        ShGc::OutputItem out;
        out.mLabels.reset(new std::vector<block>(bitCount()));
        if (std::find(pIdxs.begin(), pIdxs.end(), mRt.mPartyIdx) != pIdxs.end())
        {
            out.mOutputProm.reset(new std::promise<BitVector>());
            mFutr = out.mOutputProm->get_future();
        }
        else if (mFutr.valid())
        {
            mFutr = std::future<BitVector>();
        }

        out.mOutPartyIdxs.assign(pIdxs.begin(), pIdxs.end());

        ShGc::CircuitItem cc;
        cc.mLabels.resize(2);
        cc.mLabels[0] = mLabels;
        cc.mLabels[1] = out.mLabels;

        mRt.enqueue(std::move(out));
        mRt.enqueue(std::move(cc));
    }

    ShGcInt::ValueType ShGcInt::getValue()
    {
        mRt.processesQueue();
        auto bv = mFutr.get();
        ValueType v= 0;
        memcpy(&v, bv.data(), bv.sizeBytes());
        return v;
    }

    ShGc::GarbledMem ShGcInt::getMemory(sIntBasePtr & a)
    {
        auto shGcInt = dynamic_cast<ShGcInt*>(a.get());
        if (shGcInt) return shGcInt->mLabels;

        auto publicInt = dynamic_cast<PublicInt*>(a.get());
       if(publicInt) return mRt.getPublicGarbledMem((u8*)&publicInt->mValue, publicInt->mBitCount);


	   throw std::runtime_error("input Int must with be ShGcInt or PublicInt. "  LOCATION);
    }


}
