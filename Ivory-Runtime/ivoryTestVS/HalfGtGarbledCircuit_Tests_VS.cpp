#include "stdafx.h"
#include "CppUnitTest.h"
#include "HalfGtGarbledCircuit_Tests.h"
#include "Common.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace libBDXTests
{
   TEST_CLASS(HalfGtGarbledCircuit_Tests)
   {
   public:
      

	   TEST_METHOD(HalfGtGC_BasicGates_Test)
      {
		  InitDebugPrinting("../test.out");
		  HalfGtGC_BasicGates_Test_Impl();
      }

      TEST_METHOD(HalfGtGC_BitAdder_Test)
      {
		  HalfGtGC_BitAdder_Test_Impl();
      }

	  TEST_METHOD(HalfGtGC_BitAdder_Validate_Test)
	  {
		  HalfGtGC_BitAdder_Validate_Test_Impl();
	  }

	  TEST_METHOD(HalfGtGC_Stream_BitAdder_Test)
	  {
		  InitDebugPrinting("../test.out");
		  HalfGtGC_Stream_BitAdder_Test_Impl();
	  }
   };
}