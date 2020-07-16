#include "Circuit.h"
#include "Gate.h"
#include "cryptoTools/Common/Log.h"
#include <sstream>
#include <unordered_map>
#include <set>
//#include "Circuit/DagCircuit.h"

namespace osuCrypto {



	Circuit::Circuit()
		:mHasMore(1)
	{
		mWireCount = mNonXorGateCount = mOutputCount = 0;
	}
	Circuit::Circuit(std::array<u64, 2> inputs)
		: mHasMore(1),mInputs(inputs)
	{
		mWireCount = mInputs[0] + mInputs[1];
		mNonXorGateCount = mOutputCount = 0;

		//mIndexArray.resize(InputWireCount());
		//for (u64 i = 0; i < InputWireCount(); ++i)
		//{
		//	mIndexArray[i] = _mm_set_epi64x(0, i);
		//}
	}


	Circuit::~Circuit()
	{
	}


	void Circuit::init()
	{

		//mIndexArray.resize(std::max(WireCount(), NonXorGateCount() * 2));
		//for (u64 i = 0; i < mIndexArray.size(); ++i)
		//{
		//	mIndexArray[i] = _mm_set1_epi64x(i);
		//}
	}



	u64 Circuit::AddGate(u64 input0, u64 input1, GateType gt)
	{
		if (input0 > mWireCount)
			throw std::runtime_error("");
		if (input1 > mWireCount && (gt  != GateType::na || input1 != (u64)-1))
				throw std::runtime_error("");
		
		if (gt == GateType::a ||
			gt == GateType::b ||
			gt == GateType::nb ||
			gt == GateType::One ||
			gt == GateType::Zero)
			throw std::runtime_error("");

		if (gt != GateType::Xor && gt != GateType::Nxor) ++mNonXorGateCount;
		mGates.emplace_back(input0, input1, mWireCount, gt);
		return mWireCount++;
	}

	//void Circuit::readBris(std::istream & in, bool reduce)
	//{
	//	if (in.eof())
	//		throw std::runtime_error("Circuit::readBris input istream is emprty");

	//	DagCircuit dag;
	//	dag.readBris(in);

	//	if (reduce)
	//		dag.removeInvertGates();

	//	dag.toCircuit(*this);

	//	if (reduce)
	//	{
	//		if (mGates.size() != dag.mNonInvertGateCount)
	//			throw std::runtime_error("");
	//	}
	//	else
	//	{
	//		if (mGates.size() != dag.mGates.size())
	//			throw std::runtime_error("");
	//	}

	//	init();
	//}



	//void Circuit::evaluate(std::vector<bool>& labels)
	//{
	//	labels.resize(mWireCount);

	//	//std::cout  << "in " << labels << std::endl;

	//	for (auto& gate : mGates)
	//	{
	//		u8 a = labels[gate.mInput[0]] ? 1 : 0;
	//		u8 b = labels[gate.mInput[1]] ? 2 : 0;
	//		labels[gate.mOutput] = gate.eval(a | b);
	//	}
	//}

	//void Circuit::translate(std::vector<bool>& labels, std::vector<bool>& output)
	//{
	//	output.resize(mOutputCount);
	//	for (u64 i = 0; i < mOutputs.size(); i++)
	//	{
	//		auto& wireIdx = mOutputs[i];
	//		output[i] = labels[wireIdx];
	//	}
	//}

	void Circuit::evaluate(BitVector& labels)
	{
		labels.resize(mWireCount);

		//std::cout  << "in " << labels << std::endl;

		for (auto& gate : mGates)
		{
			u8 a = labels[gate.mInput[0]] ? 1 : 0;
			u8 b = labels[gate.mInput[1]] ? 2 : 0;
			labels[gate.mWireIdx] = gate.eval(a | b);
		}
	}

	void Circuit::translate(BitVector& labels, BitVector& output)
	{
		output.reset(mOutputCount);
		for (u64 i = 0; i < mOutputs.size(); i++)
		{
			auto& wireIdx = mOutputs[i];
			output[i] = labels[wireIdx];

			//if (output[i] != labels[wireIdx])
			//	throw std::runtime_error("");
		}
	}


	void Circuit::xorShareInputs()
	{

		u64 wiresAdded = mInputs[0] + mInputs[1];

		std::array<u64, 2> oldInputs = mInputs;
		std::vector<Gate> oldGates(std::move(mGates));

		mInputs[0] += mInputs[1];
		mInputs[1] = mInputs[0];


		u64 inIter0 = 0;
		u64 inIter1 = mInputs[0];
		u64 outIter = mInputs[0] + mInputs[1];

		mGates.reserve(oldGates.size() + wiresAdded);
		
		for (u64 i = 0; i < oldInputs[0]; ++i)
		{
			mGates.emplace_back(inIter0++, inIter1++, outIter++, GateType::Xor);
		}

		for (u64 i = 0; i < oldInputs[1]; ++i)
		{
			mGates.emplace_back(inIter0++, inIter1++, outIter++, GateType::Xor);
		}

		u64 offset = 2 * wiresAdded;
		mWireCount = mWireCount + offset;

		for (auto& gate : oldGates)
		{
			mGates.emplace_back(
				gate.mInput[0] + offset, 
				gate.mInput[1] + offset,
				gate.mWireIdx   + offset,
				gate.Type());
		}

		for (auto& output : mOutputs)
			output += offset;
	}
	
	bool Circuit::hasMoreGates()
	{
		return mHasMore++ & 1;
	}

	span<Gate> Circuit::getMoreGates()
	{
		return span<Gate>(mGates.begin(), mGates.end());
	}
	span<u64> Circuit::getOutputIndices()
	{
		return span<u64>(mOutputs.begin(), mOutputs.end());
	}
    std::vector<u64> Circuit::getInputIndices()
	{
		auto begin = std::vector<u64>(mInputs[0] + mInputs[1]);
		for (u64 i = 0; i < mInputs[0] + mInputs[1]; ++i)
			begin[i] = i;

        return begin;
		//return span<u64>(mInputs.begin(), mInputs.end());
	}
	u64 Circuit::getInternalWireBuffSize() const
	{
		return mWireCount;
	}
	u64 Circuit::getInputWireBuffSize() const
	{
		return Inputs().size();
	}
	u64 Circuit::getNonXorGateCount() const
	{
		return NonXorGateCount();
	}
}