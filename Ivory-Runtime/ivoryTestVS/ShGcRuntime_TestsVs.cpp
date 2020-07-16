#include "stdafx.h"
#ifdef  _MSC_VER
#include "CppUnitTest.h"

#include "Common.h"
#include "ShGcRuntime_tests.h"


using namespace Microsoft::VisualStudio::CppUnitTestFramework;


TEST_CLASS(ShGcRuntime_Tests)
{
public:


    TEST_METHOD(ShGcRuntime_publicGateGarble)
    {
        InitDebugPrinting();
        ShGcRuntime_publicGateGarble_Test();
    }


	TEST_METHOD(ShGcRuntime_BasicArithetic)
	{
        InitDebugPrinting();
		ShGcRuntime_basicArith_Test();
	}


    TEST_METHOD(ShGcRuntime_SequentialOp)
    {
        InitDebugPrinting();
        ShGcRuntime_SequentialOp_Test();
    }


    TEST_METHOD(ShGcRuntime_CircuitInvert)
    {
        InitDebugPrinting();
        ShGcRuntime_CircuitInvert_Test();
    }

    TEST_METHOD(ShGcRuntime_CircuitAdd)
    {
        InitDebugPrinting();
        ShGcRuntime_CircuitAdd_Test();
    }

    TEST_METHOD(ShGcRuntime_CircuitMult)
    {
        InitDebugPrinting();
        ShGcRuntime_CircuitMult_Test();
    }

    TEST_METHOD(ShGcRuntime_CircuitEval)
    {
        InitDebugPrinting();
        shGcRuntime_CircuitEval_Test();
    }


};
#endif
