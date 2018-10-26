#include "stdafx.h"
#ifdef  _MSC_VER
#include "CppUnitTest.h"
#include "Common.h"
#include "Tests.h"
#include "Circuit_Tests.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace osuCrypto
{
    TEST_CLASS(nOPRF_Tests)
    {
    public:

		
		TEST_METHOD(AdaptiveMUL_Zn_testVS)
		{
			InitDebugPrinting();
			AdaptiveMUL_Zn_test();
		}

		TEST_METHOD(AdaptiveMUL_testVS)
		{
			InitDebugPrinting();
			AdaptiveMUL_test();
		}

		TEST_METHOD(Circuit_int_LessThan_testVS)
		{
			InitDebugPrinting();
			Circuit_int_LessThan_Test();
		}

		TEST_METHOD(readData_testVS)
		{
			InitDebugPrinting();
			readData_test();
		}

		TEST_METHOD(ClusteringTesttVS)
		{
			InitDebugPrinting();
			ClusteringTest();
		}

		TEST_METHOD(DecAESTesttVS)
		{
			InitDebugPrinting();
			testDecAES();
		}

		TEST_METHOD(MulTesttVS)
		{
			InitDebugPrinting();
			MulTest();
		}

		TEST_METHOD(MinDistTesttVS)
		{
			InitDebugPrinting();
			testMinDist();
		}
		TEST_METHOD(MinDistFirstLevelTesttVS)
		{
			InitDebugPrinting();
			testMinDistFirstLevel();
		}
		
		
	
		
	
    };
}
#endif