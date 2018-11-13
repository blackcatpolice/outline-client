#include <iostream>

#include "windows.h"
#include "fwpmtypes.h"
#include "fwpmu.h"

using namespace::std;

#define EXIT_ON_ERROR(fnName) \
   if (result != ERROR_SUCCESS) \
   { \
      printf(#fnName " = 0x%08X\n", result); \
      return 1; \
   }

PCWSTR providerName = L"Outline";

int main(int argc, char **)
{
	cout << "connecting to engine" << endl;
	HANDLE engine = 0;

    // mingw64 is missing FWPM_* constants
	// FWPM_SESSION_FLAG_DYNAMIC = 1;
    
	FWPM_SESSION0 session;
	memset(&session, 0, sizeof(session));

	session.flags = 1; // FWPM_SESSION_FLAG_DYNAMIC;

	DWORD result = FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, &session, &engine);
	EXIT_ON_ERROR(FwpmEngineOpen0);

	cout << "creating filters" << endl;

	FWPM_FILTER0 filter;
	memset(&filter, 0, sizeof(filter));

	FWPM_FILTER_CONDITION0 conds[3];

	// First condition matches UDP traffic only.
	conds[0].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
	conds[0].matchType = FWP_MATCH_EQUAL;
	conds[0].conditionValue.type = FWP_UINT8;
	conds[0].conditionValue.uint16 = IPPROTO_UDP;

	// Second condition matches the remote port.
	conds[1].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
	conds[1].matchType = FWP_MATCH_EQUAL;
	conds[1].conditionValue.type = FWP_UINT16;
	conds[1].conditionValue.uint16 = 53;

	// Third condition matches remote host.
	conds[2].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
	conds[2].matchType = FWP_MATCH_EQUAL;
	conds[2].conditionValue.type = FWP_UINT32;
	conds[2].conditionValue.uint32 = 0x01010101;

	/*
	// Third condition matches the outbound interface.
	// index of the network interface, as enumerated by the network stack.
	conds[2].fieldKey = FWPM_CONDITION_LOCAL_INTERFACE_INDEX;
	conds[2].matchType = FWP_MATCH_EQUAL;
	conds[2].conditionValue.type = FWP_UINT32;
	// route print
	conds[2].conditionValue.uint32 = 3;
	*/

	filter.displayData.name = (PWSTR)providerName;

	filter.filterCondition = conds;
	filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;

	UINT64 filterid;

	result = FwpmTransactionBegin0(engine, 0);
	EXIT_ON_ERROR(FwpmTransactionBegin0);

	// BLOCK
	filter.numFilterConditions = 2;
	filter.action.type = FWP_ACTION_BLOCK;
	result = FwpmFilterAdd0(engine, &filter, NULL, &filterid);
	EXIT_ON_ERROR(FwpmFilterAdd0);
	printf("IPv4 port 53 blocked with ID %I64d\r\n", filterid);

	// WHITELIST
	filter.numFilterConditions = 3;
	filter.action.type = FWP_ACTION_PERMIT;
	result = FwpmFilterAdd0(engine, &filter, NULL, &filterid);
	EXIT_ON_ERROR(FwpmFilterAdd0);
	printf("IPv4 port 53 whitelisted on TAP device with ID %I64d\r\n", filterid);

	result = FwpmTransactionCommit0(engine);
	EXIT_ON_ERROR(FwpmTransactionCommit0);

	cout << "yo" << endl;
	system("pause");

	return 0;
}
