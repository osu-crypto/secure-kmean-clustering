#include "stdafx.h"
#include "CppUnitTest.h"
#include "Common.h"

#include "Circuit_Tests.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace libBDXTests
{
	TEST_CLASS(Circuit_Tests)
	{
	public:

        TEST_METHOD(Circuit_SequentialOp)
        {
            InitDebugPrinting();
            Circuit_SequentialOp_Test();
        }


        TEST_METHOD(Circuit_int_Adder)
        {
            InitDebugPrinting();
            Circuit_int_Adder_Test();
        }

        TEST_METHOD(Circuit_uint_Adder)
        {
            InitDebugPrinting();
            Circuit_uint_Adder_Test();
        }

        TEST_METHOD(Circuit_int_Adder_const)
        {
            InitDebugPrinting();
            Circuit_int_Adder_const_Test();
        }

        TEST_METHOD(Circuit_int_Subtractor)
        {
            InitDebugPrinting();
            Circuit_int_Subtractor_Test();
        }

        TEST_METHOD(Circuit_int_Subtractor_const)
        {
            InitDebugPrinting();
            Circuit_int_Subtractor_const_Test();
        }

        TEST_METHOD(Circuit_uint_Subtractor)
        {
            InitDebugPrinting();
            Circuit_uint_Subtractor_Test();
        }

        TEST_METHOD(Circuit_int_Multiply)
        {
            InitDebugPrinting();
            Circuit_int_Multiply_Test();
        }

        TEST_METHOD(Circuit_int_Divide)
        {
            InitDebugPrinting();
            Circuit_int_Divide_Test();
        }

        TEST_METHOD(Circuit_int_LessThan)
        {
            InitDebugPrinting();
            Circuit_int_LessThan_Test();
        }

        TEST_METHOD(Circuit_int_GreaterThanEq)
        {
            InitDebugPrinting();
            Circuit_int_GreaterThanEq_Test();
        }

        TEST_METHOD(Circuit_uint_LessThan)
        {
            InitDebugPrinting();
            Circuit_uint_LessThan_Test();
        }


        TEST_METHOD(Circuit_uint_GreaterThanEq)
        {
            InitDebugPrinting();
            Circuit_uint_GreaterThanEq_Test();
        }


        TEST_METHOD(Circuit_multiplex)
        {
            InitDebugPrinting();
            Circuit_multiplex_Test();
        }


        TEST_METHOD(Circuit_bitInvert)
        {
            InitDebugPrinting();
            Circuit_bitInvert_Test();
        }

        TEST_METHOD(Circuit_int_negate)
        {
            InitDebugPrinting();
            Circuit_negate_Test();
        }

        TEST_METHOD(Circuit_int_removeSign)
        {
            InitDebugPrinting();
            Circuit_removeSign_Test();
        }

        TEST_METHOD(Circuit_int_addSign)
        {
            InitDebugPrinting();
            Circuit_addSign_Test();
        }
	};
}