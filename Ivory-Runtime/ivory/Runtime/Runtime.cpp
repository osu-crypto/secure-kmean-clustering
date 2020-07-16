#include "Runtime.h"
#include "ivory/Runtime/Public/PublicInt.h"
//#include "Clear/"

namespace osuCrypto
{
	Runtime::Runtime()
	{
	}


	Runtime::~Runtime()
	{
	}
    sIntBasePtr Runtime::getPublicInt(i64 v, u64 size)
    {
        return sIntBasePtr(new PublicInt(v, size));
    }
}