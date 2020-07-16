#include "stdafx.h"
#ifdef  _MSC_VER
#include "CppUnitTest.h"

#include "ZpNumber_Tests.h"

#include "Common.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;


TEST_CLASS(LocalChannel_Tests)
{
public:

	TEST_METHOD(ZpNumber_Basic)
	{
        InitDebugPrinting();
        ZpNumber_Basic_Test();
	}

    TEST_METHOD(ZpNumber_BasicLarge)
    {
        InitDebugPrinting();
        ZpNumber_BasicLarge_Test();
    }

    TEST_METHOD(ZpNumber_ToBits)
    {
        InitDebugPrinting();
        ZpNumber_ToBits_Test();
    }

};
#endif
