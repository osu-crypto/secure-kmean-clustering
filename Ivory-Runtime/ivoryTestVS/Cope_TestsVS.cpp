#include "stdafx.h"
#ifdef  _MSC_VER
#include "CppUnitTest.h"

#include "Cope_Tests.h"

#include "Common.h"


using namespace Microsoft::VisualStudio::CppUnitTestFramework;


TEST_CLASS(cope_Tests)
{
public:

	TEST_METHOD(Cope_TestVS)
	{
        InitDebugPrinting();
        cope_test();
	}

};
#endif
