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
	
	
    };
}
#endif