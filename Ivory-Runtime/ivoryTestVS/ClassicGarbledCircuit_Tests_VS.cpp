#include "stdafx.h"
#include "CppUnitTest.h"
//#include "Circuit/GarbledCircuit.h"
//#include "Circuit/ClassicGarbledCircuit.h"
//#include "Circuit/Circuit.h"
//#include "MyAssert.h"
//#include <fstream>
//#include "Common.h"
//#include "Common/Logger.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace libBDXTests
{
   //using namespace libBDX;
   TEST_CLASS(ClassicGarbledCircuit_Tests)
   {
   public:
      
   //   TEST_METHOD(ClassicGC_BasicGates_Test)
   //   {
   //      block seed = _mm_set_epi32(4253465, 3434565, 234435, 23987045); 

   //      InitDebugPrinting("..\\test.out");

   //      for (u8 gate = 0; gate < 16; ++gate)
   //      {
   //         GateType gt((GateType)gate);

			//if (gt == GateType::a ||
			//	gt == GateType::b ||
			//	gt == GateType::na ||
			//	gt == GateType::nb ||
			//	gt == GateType::One ||
			//	gt == GateType::Zero)
			//	continue;

   //         Circuit cd = OneGateCircuit(gt);

   //         ClassicGarbledCircuit gc(cd);
   //         gc.Garble(cd, seed);

   //         BitVector out;
   //         std::vector<block> labels;

   //         for (u8 i = 0; i < 4; ++i)
   //         {
   //            labels.clear();
   //            block a = (i & 1) ? gc.mWires[0].Label1(gc.mGlobalOffset) : gc.mWires[0].Label0;
   //            block b = (i & 2) ? gc.mWires[1].Label1(gc.mGlobalOffset) : gc.mWires[1].Label0;
   //            
   //            labels.push_back(a);
   //            labels.push_back(b);

   //            gc.evaluate(cd, labels);
   //            gc.translate(cd, labels, out);

			//   u8 expected = cd.Gates()[0].eval(i);
			//   if(expected != out[0])
			//	   throw UnitTestFail();
   //         }
   //      }
   //   }


   //   void ToBitVector(BitVector & vec, u64 input, u64 bits)
   //   {
		 // vec.reset(bits);
   //      for (u64 i = 0, mask = 1; i < bits; ++i, mask <<= 1)
   //      {
   //         vec[i] = ((input & mask) != 0);
   //      }
   //   }

   //   TEST_METHOD(ClassicGC_BitAdder_Test)
   //   {
   //      InitDebugPrinting("..\\test.out");
   //      u32 bits{ 4 };
   //      block seed = _mm_set_epi32(4253465, 3434565, 234435, 23987045);


   //      Circuit cd = AdderCircuit(bits);
   //      ClassicGarbledCircuit gc(cd);
   //      gc.Garble(cd, seed);

   //      for (u64 input0 = 0; input0 < ((u64)1 << bits); ++input0)
   //      {
   //         for (u64 input1 = 0; input1 < ((u64)1 <<bits); ++input1)
   //         {
   //            libBDX::Lg::out << " =================================================" << libBDX::Lg::endl;
			//   libBDX::Lg::out << input0 << "  " << input1 << libBDX::Lg::endl << libBDX::Lg::endl;

   //            BitVector inputVec;

			//   inputVec.append((u8*)&input0, bits);
			//   inputVec.append((u8*)&input1, bits);

   //            std::vector<block>labels;
   //            for (u64 i = 0; i < inputVec.size(); ++i)
   //            {
   //               if (inputVec[i])
   //               {
   //                  labels.push_back(gc.mWires[i].Label1(gc.mGlobalOffset));
   //               }
   //               else
   //                  labels.push_back(gc.mWires[i].Label0);
   //            }

   //            gc.evaluate(cd, labels);
   //            BitVector outputVec;
   //            gc.translate(cd, labels, outputVec);

   //            BitVector  expectedOut;
   //            ToBitVector(expectedOut, input0 + input1, bits + 1);

   //            cd.evaluate(inputVec);
   //            BitVector  outputVec2;
   //            cd.translate(inputVec, outputVec2);

   //            if(outputVec.size() != expectedOut.size())
			//	   throw UnitTestFail();

   //            for (auto i = 0; i < outputVec.size(); ++i)
   //            {
			//	   if (outputVec[i] != expectedOut[i])
			//		   throw UnitTestFail();
   //               //Assert::AreEqual(true, true, L"Output bits dont match");
   //            }
   //         }
   //      }
   //   }
   };
}