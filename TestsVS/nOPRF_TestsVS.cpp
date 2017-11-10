#include "stdafx.h"
#ifdef  _MSC_VER
#include "CppUnitTest.h"
#include "nOPRF_Tests.h"
#include "NcoOT_Tests.h"
#include "Common.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace tests_libOTe
{
    TEST_CLASS(nOPRF_Tests)
    {
    public:

       
        TEST_METHOD(nOPRF_100Receive_TestVS)
        {
            InitDebugPrinting();
            nOPRF_100Receive_Test_Impl();
        }
		      

    };
}
#endif