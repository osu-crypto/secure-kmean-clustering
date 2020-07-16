#include "DebugCircuits.h"

using namespace osuCrypto;

Circuit OneGateCircuit(GateType gt)
{
	Circuit cd(std::array<u64, 2>{ {1, 1} });
	//cd.SetInputWireCount(Role::First, 1);
	//cd.SetInputWireCount(Role::Second, 1);
	cd.AddGate(0, 1, gt);
	cd.AddOutputWire(2);
	return cd;
}


Circuit AdderCircuit(u64 bits)
{
	std::vector<u64> carrys;
	u64 diff = 0;

	Circuit cd(std::array<u64, 2>{ {bits + diff, bits} });
	/* cd.SetInputWireCount(Role::First, bits);
	cd.SetInputWireCount(Role::Second, bits);*/


	cd.AddOutputWire(cd.AddGate(0, bits + diff, GateType::Xor));
	carrys.push_back(cd.AddGate(0, bits + diff, GateType::And));

	for (u64 i = 1; i < bits; ++i)
	{
		auto xorIn = cd.AddGate(i, i + bits + diff, GateType::Xor);
		cd.AddOutputWire(cd.AddGate(xorIn, carrys.back(), GateType::Xor));
		auto carry0 = cd.AddGate(xorIn, carrys.back(), GateType::And);
		auto carry1 = cd.AddGate(i, i + bits + diff, GateType::And);
		carrys.push_back(cd.AddGate(carry0, carry1, GateType::Or));
	}
	cd.AddOutputWire(carrys.back());
	cd.init();
	return cd;
}
