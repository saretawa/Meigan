#include <windows.h>
#include <lm.h>
#include <activeds.h>
#include <adshlp.h>
#include <iostream>
#include <fstream>
#include <sddl.h>
#include <map>
#include <vector>
#include <functional>
#include <string>
#include <algorithm>

#pragma comment(lib, "activeds.lib")
#pragma comment(lib, "adsiid.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "netapi32.lib")

std::wostream* gOut = &std::wcout;
std::wofstream gFileOut;
bool gVerbose = false;
bool gShareTree = false;

std::string ToLower(std::string str) {
	for (auto& c : str) c = tolower(c);
	return str;
}

void Log(const std::wstring& msg, const std::wstring& level = L"*") {
	if (level == L"*" && !gVerbose) return;
	std::wcout << L"[" << level << L"] " << msg << std::endl;
	if (gOut != &std::wcout)
		*gOut << L"[" << level << L"] " << msg << std::endl;
}

void LogHR(const std::wstring& msg, HRESULT hr) {
	if (!gVerbose) return;
	wchar_t buf[256];
	swprintf(buf, 256, L"%s: 0x%08X", msg.c_str(), hr);
	Log(buf, FAILED(hr) ? L"-" : L"+");
}

void LogResult(const std::wstring& msg, const std::wstring& level = L"+") {
	std::wstring color = L"\x1b[0m";
	if (level == L"+") color = L"\x1b[92m"; // green
	else if (level == L"-") color = L"\x1b[91m"; // red
	else if (level == L"!") color = L"\x1b[93m"; // yellow
	else if (level == L"*") color = L"\x1b[96m"; // cyan
	std::wcout << color << L"[" << level << L"] " << msg << L"\x1b[0m" << std::endl;
	if (gOut != &std::wcout)
		*gOut << L"[" << level << L"] " << msg << std::endl;
}

std::wstring DecodeUAC(DWORD uac) {
	std::wstring flags = L"";
	if (uac & 0x0002)   flags += L"DISABLED ";
	if (uac & 0x0010)   flags += L"LOCKOUT ";
	if (uac & 0x0020)   flags += L"PASSWD_NOTREQD ";
	if (uac & 0x0040)   flags += L"PASSWD_CANT_CHANGE ";
	if (uac & 0x10000)  flags += L"DONT_EXPIRE_PASSWD ";
	if (uac & 0x40000)  flags += L"SMARTCARD_REQUIRED ";
	if (uac & 0x80000)  flags += L"TRUSTED_FOR_DELEGATION ";
	if (uac & 0x100000) flags += L"NOT_DELEGATED ";
	if (uac & 0x200000) flags += L"USE_DES_KEY_ONLY ";
	if (uac & 0x400000) flags += L"DONT_REQ_PREAUTH ";
	return flags.empty() ? L"NORMAL" : flags;
}

std::wstring FileTimeToReadable(LONGLONG ft) {
	if (ft == 0) return L"Never";
	if (ft == 9223372036854775807) return L"Never Expires";
	FILETIME filetime;
	filetime.dwLowDateTime = (DWORD)(ft & 0xFFFFFFFF);
	filetime.dwHighDateTime = (DWORD)(ft >> 32);
	SYSTEMTIME st;
	FileTimeToSystemTime(&filetime, &st);
	wchar_t buf[64];
	swprintf(buf, 64, L"%04d-%02d-%02d %02d:%02d:%02d",
		st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
	return std::wstring(buf);
}

LONGLONG DaysAgoFileTime(int days) {
	SYSTEMTIME st;
	GetSystemTime(&st);
	FILETIME ft;
	SystemTimeToFileTime(&st, &ft);
	ULARGE_INTEGER uli;
	uli.LowPart = ft.dwLowDateTime;
	uli.HighPart = ft.dwHighDateTime;
	uli.QuadPart -= (ULONGLONG)days * 24 * 60 * 60 * 10000000ULL;
	return (LONGLONG)uli.QuadPart;
}

std::wstring DecodeSid(PBYTE sidBytes, DWORD length) {
	PSID pSid = (PSID)sidBytes;
	LPWSTR sidStr = nullptr;
	if (ConvertSidToStringSidW(pSid, &sidStr)) {
		std::wstring result(sidStr);
		LocalFree(sidStr);
		return result;
	}
	return L"[invalid sid]";
}

std::wstring SidToName(PSID pSid) {
	wchar_t name[256] = {}, domain[256] = {};
	DWORD nameLen = 256, domainLen = 256;
	SID_NAME_USE use;
	if (LookupAccountSidW(nullptr, pSid, name, &nameLen, domain, &domainLen, &use)) {
		std::wstring result = domain;
		if (!result.empty()) result += L"\\";
		result += name;
		return result;
	}
	LPWSTR sidStr = nullptr;
	if (ConvertSidToStringSidW(pSid, &sidStr)) {
		std::wstring result(sidStr);
		LocalFree(sidStr);
		return result;
	}
	return L"[unknown]";
}

std::wstring DecodeGroupType(LONG gt) {
	std::wstring result = L"";
	if (gt & ADS_GROUP_TYPE_GLOBAL_GROUP)       result += L"Global ";
	if (gt & ADS_GROUP_TYPE_DOMAIN_LOCAL_GROUP) result += L"Domain Local ";
	if (gt & ADS_GROUP_TYPE_UNIVERSAL_GROUP)    result += L"Universal ";
	if (gt & ADS_GROUP_TYPE_SECURITY_ENABLED)   result += L"Security ";
	else                                         result += L"Distribution ";
	return result;
}

std::wstring DecodeGUID(PBYTE guidBytes) {
	GUID* pGuid = (GUID*)guidBytes;
	wchar_t buf[64];
	swprintf(buf, 64, L"{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
		pGuid->Data1, pGuid->Data2, pGuid->Data3,
		pGuid->Data4[0], pGuid->Data4[1],
		pGuid->Data4[2], pGuid->Data4[3],
		pGuid->Data4[4], pGuid->Data4[5],
		pGuid->Data4[6], pGuid->Data4[7]);
	return std::wstring(buf);
}

std::wstring DecodeTrustType(DWORD t) {
	switch (t) {
	case 1:  return L"Windows NT (Downlevel)";
	case 2:  return L"Active Directory (Uplevel)";
	case 3:  return L"MIT Kerberos";
	case 4:  return L"DCE";
	default: return L"Unknown";
	}
}

std::wstring DecodeTrustDirection(DWORD d) {
	switch (d) {
	case 0:  return L"Disabled";
	case 1:  return L"Inbound (they trust us)";
	case 2:  return L"Outbound (we trust them)";
	case 3:  return L"Bidirectional";
	default: return L"Unknown";
	}
}

std::wstring DecodeTrustAttributes(DWORD a) {
	std::wstring result = L"";
	if (a & 0x001) result += L"NON_TRANSITIVE ";
	if (a & 0x002) result += L"UPLEVEL_ONLY ";
	if (a & 0x004) result += L"QUARANTINED_DOMAIN ";
	if (a & 0x008) result += L"FOREST_TRANSITIVE ";
	if (a & 0x010) result += L"CROSS_ORGANIZATION ";
	if (a & 0x020) result += L"WITHIN_FOREST ";
	if (a & 0x040) result += L"TREAT_AS_EXTERNAL ";
	if (a & 0x080) result += L"USES_RC4_ENCRYPTION ";
	return result.empty() ? L"NONE" : result;
}

// ============================================================
// ACL helpers
// ============================================================

// Well-known extended right GUIDs
struct ExtendedRightEntry {
	const wchar_t* guid;
	const wchar_t* name;
	bool noise; // true = suppress from output
};

static ExtendedRightEntry gExtendedRights[] = {
	// Offensive - surface these
	{ L"{00299570-246d-11d0-a768-00aa006e0529}", L"ForceChangePassword",                    false },
	{ L"{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}", L"DS-Replication-Get-Changes",             false },
	{ L"{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}", L"DS-Replication-Get-Changes-All",         false },
	{ L"{89e95b76-444d-4c62-991a-0facbeda640c}", L"DS-Replication-Get-Changes-Filtered",    false },
	{ L"{0e10c968-78fb-11d2-90d4-00c04f79dc55}", L"Enroll",                                 false },
	{ L"{a05b8cc2-17bc-4802-a710-e7c15ab866a2}", L"AutoEnroll",                             false },
	{ L"{9923a32a-3607-11d2-b9be-0000f87a36b2}", L"DS-Install-Replica",                     false },
	// Noise - suppress
	{ L"{ab721a53-1e2f-11d0-9819-00aa0040529b}", L"User-Change-Password",                   true  },
	{ L"{ab721a54-1e2f-11d0-9819-00aa0040529b}", L"Send-As",                                true  },
	{ L"{ab721a56-1e2f-11d0-9819-00aa0040529b}", L"Receive-As",                             true  },
	{ L"{91e647de-d96f-4b70-9557-d63ff4f3ccd8}", L"Private-Information",                    true  },
	{ L"{4c164200-20c0-11d0-a768-00aa006e0529}", L"User-Logon",                             true  },
	{ L"{5f202010-79a5-11d0-9020-00c04fc2d4cf}", L"DS-Replication-Synchronize",             true  },
	{ L"{05c74c5e-4deb-43b4-bd9f-86664c2a7fd5}", L"User-Account-Restrictions",              true  },
	{ L"{72e39547-7b18-11d1-adef-00c04fd8d5cd}", L"DNS-Host-Name-Attributes",               true  },
	{ L"{00000000-0000-0000-0000-000000000000}", L"AllExtendedRights",                      false },
};

// Returns empty string for noise GUIDs (caller should skip)
std::wstring ResolveExtendedRight(const GUID* pGuid, bool& isNoise) {
	isNoise = false;
	wchar_t guidStr[64];
	swprintf(guidStr, 64,
		L"{%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}",
		pGuid->Data1, pGuid->Data2, pGuid->Data3,
		pGuid->Data4[0], pGuid->Data4[1],
		pGuid->Data4[2], pGuid->Data4[3],
		pGuid->Data4[4], pGuid->Data4[5],
		pGuid->Data4[6], pGuid->Data4[7]);

	std::wstring gs(guidStr);
	for (auto& c : gs) c = towlower(c);

	for (auto& e : gExtendedRights) {
		std::wstring eg(e.guid);
		for (auto& c : eg) c = towlower(c);
		if (gs == eg) {
			isNoise = e.noise;
			return e.noise ? L"" : e.name;
		}
	}
	// Unknown GUID — suppress, likely a default attribute right
	isNoise = true;
	return L"";
}

// Skip these trustees — default high-priv groups, noise
bool IsDefaultTrustee(const std::wstring& name) {
	static const wchar_t* defaults[] = {
		L"NT AUTHORITY\\SYSTEM",
		L"NT AUTHORITY\\SELF",
		L"BUILTIN\\Administrators",
		L"BUILTIN\\Account Operators",
		L"BUILTIN\\Print Operators",
		L"BUILTIN\\Backup Operators",
		L"BUILTIN\\Server Operators",
		L"Creator Owner",
		L"NT AUTHORITY\\ENTERPRISE DOMAIN CONTROLLERS",
	};
	std::wstring lower = name;
	for (auto& c : lower) c = towlower(c);

	for (auto& d : defaults) {
		std::wstring dl(d);
		for (auto& c : dl) c = towlower(c);
		if (lower == dl) return true;
	}

	if (lower.find(L"domain admins") != std::wstring::npos) return true;
	if (lower.find(L"enterprise admins") != std::wstring::npos) return true;
	if (lower.find(L"schema admins") != std::wstring::npos) return true;
	if (lower.find(L"key admins") != std::wstring::npos) return true;
	if (lower.find(L"cert publishers") != std::wstring::npos) return true;
	if (lower.find(L"terminal server license") != std::wstring::npos) return true;
	if (lower.find(L"everyone") != std::wstring::npos) return true;

	return false;
}

// Right severity ranking — lower = more dangerous
int RightSeverity(const std::wstring& right) {
	if (right.find(L"GenericAll") != std::wstring::npos)                           return 0;
	if (right.find(L"WriteDACL") != std::wstring::npos)                            return 1;
	if (right.find(L"WriteOwner") != std::wstring::npos)                           return 2;
	if (right.find(L"DS-Replication-Get-Changes-All") != std::wstring::npos)       return 3;
	if (right.find(L"DS-Replication-Get-Changes") != std::wstring::npos)           return 4;
	if (right.find(L"GenericWrite") != std::wstring::npos)                         return 5;
	if (right.find(L"WriteProperty(All)") != std::wstring::npos)                   return 6;
	if (right.find(L"ForceChangePassword") != std::wstring::npos)                  return 7;
	if (right.find(L"AllExtendedRights") != std::wstring::npos)                    return 8;
	if (right.find(L"Self-Membership") != std::wstring::npos)                      return 9;
	if (right.find(L"CreateChild") != std::wstring::npos)                          return 6;
	if (right.find(L"WriteProperty") != std::wstring::npos)                        return 10;
	return 99;
}

bool IsDCSync(const std::wstring& right) {
	return right.find(L"DS-Replication-Get-Changes-All") != std::wstring::npos ||
		right.find(L"DS-Replication-Get-Changes") != std::wstring::npos;
}

struct AclFinding {
	std::wstring targetDN;
	std::wstring targetSam;
	std::wstring targetType; // USER / GROUP / COMPUTER
	std::wstring trustee;
	std::wstring right;
	int severity;
};

std::wstring DecodeInterestingMask(DWORD mask, BYTE aceType, const GUID* pObjectType) {
	std::wstring rights = L"";

	if (mask & GENERIC_ALL)              rights += L"GenericAll ";
	if (mask & GENERIC_WRITE)            rights += L"GenericWrite ";
	if (mask & WRITE_DAC)                rights += L"WriteDACL ";
	if (mask & WRITE_OWNER)              rights += L"WriteOwner ";
	if (mask & ADS_RIGHT_DS_CREATE_CHILD) rights += L"CreateChild ";

	if ((mask & ADS_RIGHT_DS_CONTROL_ACCESS) && pObjectType) {
		bool isNoise = false;
		std::wstring extRight = ResolveExtendedRight(pObjectType, isNoise);
		if (!isNoise && !extRight.empty())
			rights += extRight + L" ";
	}
	else if ((mask & ADS_RIGHT_DS_CONTROL_ACCESS) && !pObjectType) {
		rights += L"AllExtendedRights ";
	}

	if ((mask & ADS_RIGHT_DS_WRITE_PROP) && pObjectType) {
		wchar_t guidStr[64];
		swprintf(guidStr, 64, L"{%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}",
			pObjectType->Data1, pObjectType->Data2, pObjectType->Data3,
			pObjectType->Data4[0], pObjectType->Data4[1],
			pObjectType->Data4[2], pObjectType->Data4[3],
			pObjectType->Data4[4], pObjectType->Data4[5],
			pObjectType->Data4[6], pObjectType->Data4[7]);
		std::wstring gs(guidStr);
		for (auto& c : gs) c = towlower(c);
		if (gs == L"{bf9679c0-0de6-11d0-a285-00aa003049e2}")
			rights += L"Self-Membership ";
		else if (gs == L"{3f78c3e5-f79a-46bd-a0b8-9d18116ddc79}")
			rights += L"RBCD ";
		else
			rights += L"WriteProperty ";
	}
	else if ((mask & ADS_RIGHT_DS_WRITE_PROP) && !pObjectType) {
		rights += L"WriteProperty(All) ";
	}

	return rights;
}

void ParseDACL(
	PSECURITY_DESCRIPTOR pSD,
	const std::wstring& targetDN,
	const std::wstring& targetSam,
	const std::wstring& targetType,
	const std::wstring& filterTrustee,
	const std::wstring& filterTarget,
	bool skipComputers,
	std::vector<AclFinding>& findings)
{
	PACL pDacl = nullptr;
	BOOL daclPresent = FALSE, daclDefaulted = FALSE;
	if (!GetSecurityDescriptorDacl(pSD, &daclPresent, &pDacl, &daclDefaulted)) return;
	if (!daclPresent || !pDacl) return;

	// --target filter: only show ACEs on this specific object
	if (!filterTarget.empty()) {
		std::wstring sl = targetSam, fl = filterTarget;
		for (auto& c : sl) c = towlower(c);
		for (auto& c : fl) c = towlower(c);
		if (sl.find(fl) == std::wstring::npos) return;
	}

	ACL_SIZE_INFORMATION aclInfo = {};
	GetAclInformation(pDacl, &aclInfo, sizeof(aclInfo), AclSizeInformation);

	for (DWORD i = 0; i < aclInfo.AceCount; i++) {
		LPVOID pAce = nullptr;
		if (!GetAce(pDacl, i, &pAce)) continue;

		ACE_HEADER* header = (ACE_HEADER*)pAce;
		if (header->AceType != ACCESS_ALLOWED_ACE_TYPE &&
			header->AceType != ACCESS_ALLOWED_OBJECT_ACE_TYPE) continue;

		PSID pTrusteeSid = nullptr;
		DWORD mask = 0;
		const GUID* pObjectType = nullptr;

		if (header->AceType == ACCESS_ALLOWED_ACE_TYPE) {
			ACCESS_ALLOWED_ACE* ace = (ACCESS_ALLOWED_ACE*)pAce;
			mask = ace->Mask;
			pTrusteeSid = (PSID)&ace->SidStart;
		}
		else {
			ACCESS_ALLOWED_OBJECT_ACE* ace = (ACCESS_ALLOWED_OBJECT_ACE*)pAce;
			mask = ace->Mask;
			if (ace->Flags & ACE_OBJECT_TYPE_PRESENT)
				pObjectType = &ace->ObjectType;
			DWORD offset = 0;
			if (ace->Flags & ACE_OBJECT_TYPE_PRESENT)             offset += sizeof(GUID);
			if (ace->Flags & ACE_INHERITED_OBJECT_TYPE_PRESENT)   offset += sizeof(GUID);
			pTrusteeSid = (PSID)((PBYTE)&ace->ObjectType + offset);
		}

		if (!pTrusteeSid || !IsValidSid(pTrusteeSid)) continue;

		std::wstring rights = DecodeInterestingMask(mask, header->AceType, pObjectType);
		if (rights.empty()) continue;

		std::wstring trusteeName = SidToName(pTrusteeSid);

		// Skip computer accounts as trustees (noise) unless explicitly filtering for one
		if (skipComputers && filterTrustee.empty()) {
			// heuristic: computer accounts end with $
			if (!trusteeName.empty() && trusteeName.back() == L'$') continue;
		}

		// Skip default trustees unless explicitly asked via --trustee
		if (filterTrustee.empty() && IsDefaultTrustee(trusteeName)) continue;

		// --trustee filter
		if (!filterTrustee.empty()) {
			std::wstring tl = trusteeName, fl = filterTrustee;
			for (auto& c : tl) c = towlower(c);
			for (auto& c : fl) c = towlower(c);
			if (tl.find(fl) == std::wstring::npos) continue;
		}

		// Deduplicate: skip if same target+trustee+right already recorded
		std::wstring key = targetSam + L"|" + trusteeName + L"|" + rights;
		bool seen = false;
		for (auto& existing : findings)
			if (existing.targetSam + L"|" + existing.trustee + L"|" + existing.right == key)
			{
				seen = true; break;
			}
		if (seen) continue;

		AclFinding f;
		f.targetDN = targetDN;
		f.targetSam = targetSam;
		f.targetType = targetType;
		f.trustee = trusteeName;
		f.right = rights;
		f.severity = RightSeverity(rights);
		findings.push_back(f);
	}
}


void PrintChains(const std::vector<AclFinding>& findings) {
	// Build trustee -> targets map
	std::map<std::wstring, std::vector<std::wstring>> trusteeTargets;
	std::map<std::wstring, std::wstring> samToTrustee; // sam -> display name of trustee

	for (auto& f : findings) {
		std::wstring tl = f.trustee;
		for (auto& c : tl) c = towlower(c);
		trusteeTargets[tl].push_back(f.targetSam);
		samToTrustee[f.targetSam] = f.trustee;
	}

	// For each finding, check if target is also a trustee somewhere — chain detected
	bool anyChain = false;
	for (auto& f : findings) {
		std::wstring tl = f.targetSam;
		for (auto& c : tl) c = towlower(c);
		if (trusteeTargets.count(tl)) {
			if (!anyChain) {
				*gOut << L"\n" << std::wstring(60, L'=') << std::endl;
				*gOut << L"  ATTACK PATH CHAINS" << std::endl;
				*gOut << std::wstring(60, L'=') << std::endl;
				anyChain = true;
			}
			// Print the chain: trustee -> target -> target's targets
			for (auto& next : trusteeTargets[tl]) {
				*gOut << L"\n  " << f.trustee
					<< L"  -->  " << f.targetSam
					<< L"  -->  " << next << std::endl;
			}
		}
	}
}

void ACLEnum(std::wstring baseDN, std::wstring dc, std::wstring filterTrustee,
	std::wstring filterTarget, bool dangerousOnly) {

	if (!filterTrustee.empty()) LogResult(L"Trustee: " + filterTrustee, L"*");
	if (!filterTarget.empty())  LogResult(L"Target:  " + filterTarget, L"*");

	IDirectorySearch* pSearch = nullptr;
	std::wstring ldapPath = dc.empty()
		? L"LDAP://" + baseDN
		: L"LDAP://" + dc + L"/" + baseDN;

	HRESULT hr = ADsGetObject(ldapPath.c_str(), IID_IDirectorySearch, (void**)&pSearch);
	if (FAILED(hr)) { LogHR(L"Failed to bind for ACL enum", hr); return; }

	ADS_SEARCHPREF_INFO prefs[3];
	prefs[0].dwSearchPref = ADS_SEARCHPREF_SEARCH_SCOPE;
	prefs[0].vValue.dwType = ADSTYPE_INTEGER;
	prefs[0].vValue.Integer = ADS_SCOPE_SUBTREE;
	prefs[1].dwSearchPref = ADS_SEARCHPREF_PAGESIZE;
	prefs[1].vValue.dwType = ADSTYPE_INTEGER;
	prefs[1].vValue.Integer = 100;
	prefs[2].dwSearchPref = ADS_SEARCHPREF_SECURITY_MASK;
	prefs[2].vValue.dwType = ADSTYPE_INTEGER;
	prefs[2].vValue.Integer = ADS_SECURITY_INFO_DACL | ADS_SECURITY_INFO_OWNER;
	pSearch->SetSearchPreference(prefs, 3);

	LPWSTR filter = (LPWSTR)L"(|(samAccountType=805306368)(objectClass=group)(objectClass=computer)(objectClass=organizationalUnit))";
	LPWSTR attrs[] = {
		(LPWSTR)L"distinguishedName",
		(LPWSTR)L"samAccountName",
		(LPWSTR)L"name",
		(LPWSTR)L"objectClass",
		(LPWSTR)L"nTSecurityDescriptor"
	};

	ADS_SEARCH_HANDLE hSearch;
	hr = pSearch->ExecuteSearch(filter, attrs, 5, &hSearch);
	if (FAILED(hr)) { LogHR(L"ExecuteSearch failed", hr); pSearch->Release(); return; }

	std::vector<AclFinding> findings;
	int objectCount = 0;

	HRESULT rowHr;
	while ((rowHr = pSearch->GetNextRow(hSearch)) != S_ADS_NOMORE_ROWS) {
		if (FAILED(rowHr)) break;

		std::wstring dn, sam, objClass;
		ADS_SEARCH_COLUMN col;

		if (SUCCEEDED(pSearch->GetColumn(hSearch, (LPWSTR)L"distinguishedName", &col))) {
			dn = col.pADsValues->CaseIgnoreString; pSearch->FreeColumn(&col);
		}
		if (SUCCEEDED(pSearch->GetColumn(hSearch, (LPWSTR)L"samAccountName", &col))) {
			sam = col.pADsValues->CaseIgnoreString; pSearch->FreeColumn(&col);
		}
		std::wstring ouName;
		if (SUCCEEDED(pSearch->GetColumn(hSearch, (LPWSTR)L"name", &col))) {
			ouName = col.pADsValues->CaseIgnoreString; pSearch->FreeColumn(&col);
		}
		if (sam.empty()) sam = ouName; // OUs have no samAccountName
		if (SUCCEEDED(pSearch->GetColumn(hSearch, (LPWSTR)L"objectClass", &col))) {
			// multi-valued — last value is most specific
			for (DWORD j = 0; j < col.dwNumValues; j++)
				objClass = col.pADsValues[j].CaseIgnoreString;
			pSearch->FreeColumn(&col);
		}

		// Determine type label
		std::wstring typeLabel = L"USER";
		std::wstring ol = objClass;
		for (auto& c : ol) c = towlower(c);
		if (ol == L"group")                typeLabel = L"GROUP";
		if (ol == L"computer")             typeLabel = L"COMPUTER";
		if (ol == L"organizationalunit")   typeLabel = L"OU";

		hr = pSearch->GetColumn(hSearch, (LPWSTR)L"nTSecurityDescriptor", &col);
		if (FAILED(hr)) continue;

		if (col.dwADsType == ADSTYPE_NT_SECURITY_DESCRIPTOR &&
			col.pADsValues->SecurityDescriptor.lpValue != nullptr) {
			PSECURITY_DESCRIPTOR pSD = (PSECURITY_DESCRIPTOR)col.pADsValues->SecurityDescriptor.lpValue;
			ParseDACL(pSD, dn, sam, typeLabel, filterTrustee, filterTarget, true, findings);
			objectCount++;
		}
		pSearch->FreeColumn(&col);
	}

	pSearch->CloseSearchHandle(hSearch);
	pSearch->Release();

	// Apply dangerous-only filter
	if (dangerousOnly) {
		std::vector<AclFinding> filtered;
		for (auto& f : findings) {
			if (f.severity <= 4) // GenericAll, WriteDACL, WriteOwner, DCSync
				filtered.push_back(f);
		}
		findings = filtered;
	}

	// Sort by severity
	std::sort(findings.begin(), findings.end(), [](const AclFinding& a, const AclFinding& b) {
		return a.severity < b.severity;
		});

	// ---- INBOUND: who has rights over what ----
	if (!findings.empty()) {
		std::wcout << L"\x1b[96m"; *gOut << L"\n[ACL FINDINGS]"; std::wcout << L"\x1b[0m" << std::endl;
		*gOut << std::wstring(60, L'-') << std::endl;
		for (auto& f : findings) {
			bool dcsync = IsDCSync(f.right);
			*gOut << L"\n  " << f.trustee << L" --> [" << f.targetType << L"] " << f.targetSam << std::endl;
			*gOut << L"  Rights: " << f.right;
			if (dcsync) *gOut << L" [!] DCSYNC";
			*gOut << std::endl;
			*gOut << L"  DN:     " << f.targetDN << std::endl;
		}
		*gOut << std::endl;
	}
	else {
		*gOut << L"\n[ACL] No non-default interesting ACEs found" << std::endl;
	}

	// Attack path chains
	if (filterTrustee.empty() && filterTarget.empty() && !findings.empty())
		PrintChains(findings);

	wchar_t buf[128];
	swprintf(buf, 128, L"ACL scan complete - %d objects scanned, %d interesting ACEs found",
		objectCount, (int)findings.size());
	LogResult(buf, findings.size() > 0 ? L"+" : L"!");
}

// ============================================================

std::wstring GetDomainInfo(bool printbasic, std::wstring dc = L"") {
	std::wstring rootDSEPath = dc.empty() ? L"LDAP://rootDSE" : L"LDAP://" + dc + L"/rootDSE";
	Log(L"Binding to " + rootDSEPath + L"...");

	IADs* pADs = nullptr;
	HRESULT hr = ADsGetObject(rootDSEPath.c_str(), IID_IADs, (void**)&pADs);
	if (FAILED(hr)) { LogHR(L"Failed to bind to rootDSE", hr); return L""; }

	std::wstring baseDN;

	struct domainproperty {
		std::wstring propertyDescription;
		BSTR propertyname;
	};

	domainproperty props[] = {
		{ L"Base DN:", SysAllocString(L"defaultNamingContext") },
		{ L"DNS Domain Name:", SysAllocString(L"ldapServiceName") },
		{ L"PDC:", SysAllocString(L"dsServiceName") }
	};

	for (auto& property : props) {
		VARIANT var;
		VariantInit(&var);
		HRESULT getHr = pADs->Get(property.propertyname, &var);

		if (FAILED(getHr)) {
			if (printbasic)
				LogResult(property.propertyDescription + L" (failed to read)", L"-");
		}
		else {
			if (printbasic) {
				if (var.vt != VT_EMPTY && var.bstrVal != nullptr)
					LogResult(property.propertyDescription + L" " + var.bstrVal, L"+");
				else
					LogResult(property.propertyDescription + L" (not found)", L"!");
			}
			if (property.propertyDescription == L"Base DN:") {
				if (var.vt != VT_EMPTY && var.bstrVal != nullptr)
					baseDN = std::wstring(var.bstrVal);
			}
		}

		VariantClear(&var);
		SysFreeString(property.propertyname);
	}

	pADs->Release();

	if (baseDN.empty())
		LogResult(L"Base DN is empty - LDAP searches will fail", L"-");
	else
		LogResult(L"Base DN resolved: " + baseDN, L"+");

	return baseDN;
}

IDirectorySearch* BindSearch(std::wstring baseDN, std::wstring dc = L"") {
	IDirectorySearch* pSearch = nullptr;
	std::wstring ldapPath = dc.empty()
		? L"LDAP://" + baseDN
		: L"LDAP://" + dc + L"/" + baseDN;

	HRESULT hr = ADsGetObject(ldapPath.c_str(), IID_IDirectorySearch, (void**)&pSearch);
	if (FAILED(hr)) { LogHR(L"Failed to bind", hr); return nullptr; }

	ADS_SEARCHPREF_INFO prefs[2];
	prefs[0].dwSearchPref = ADS_SEARCHPREF_SEARCH_SCOPE;
	prefs[0].vValue.dwType = ADSTYPE_INTEGER;
	prefs[0].vValue.Integer = ADS_SCOPE_SUBTREE;
	prefs[1].dwSearchPref = ADS_SEARCHPREF_PAGESIZE;
	prefs[1].vValue.dwType = ADSTYPE_INTEGER;
	prefs[1].vValue.Integer = 100;
	pSearch->SetSearchPreference(prefs, 2);

	return pSearch;
}

void PrintRow(LPWSTR* attrs, DWORD attrCount, LPWSTR header,
	IDirectorySearch* pSearch, ADS_SEARCH_HANDLE hSearch) {
	*gOut << L"\n[" << header << L"]" << std::endl;
	ADS_SEARCH_COLUMN col;

	for (DWORD i = 0; i < attrCount; i++) {
		HRESULT hr = pSearch->GetColumn(hSearch, attrs[i], &col);
		if (FAILED(hr)) continue;

		switch (col.dwADsType) {
		case ADSTYPE_CASE_IGNORE_STRING:
		case ADSTYPE_DN_STRING:
		case ADSTYPE_PRINTABLE_STRING:
		case ADSTYPE_NUMERIC_STRING:
			for (DWORD j = 0; j < col.dwNumValues; j++)
				*gOut << attrs[i] << L": " << col.pADsValues[j].CaseIgnoreString << std::endl;
			break;
		case ADSTYPE_INTEGER:
			if (wcscmp(attrs[i], L"userAccountControl") == 0)
				*gOut << L"userAccountControl: " << col.pADsValues->Integer
				<< L" (" << DecodeUAC(col.pADsValues->Integer) << L")" << std::endl;
			else if (wcscmp(attrs[i], L"groupType") == 0)
				*gOut << L"groupType: " << DecodeGroupType((LONG)col.pADsValues->Integer) << std::endl;
			else if (wcscmp(attrs[i], L"trustType") == 0)
				*gOut << L"trustType: " << DecodeTrustType(col.pADsValues->Integer) << std::endl;
			else if (wcscmp(attrs[i], L"trustDirection") == 0)
				*gOut << L"trustDirection: " << DecodeTrustDirection(col.pADsValues->Integer) << std::endl;
			else if (wcscmp(attrs[i], L"trustAttributes") == 0)
				*gOut << L"trustAttributes: " << DecodeTrustAttributes(col.pADsValues->Integer) << std::endl;
			else
				*gOut << attrs[i] << L": " << col.pADsValues->Integer << std::endl;
			break;
		case ADSTYPE_LARGE_INTEGER:
			*gOut << attrs[i] << L": " << FileTimeToReadable(col.pADsValues->LargeInteger.QuadPart) << std::endl;
			break;
		case ADSTYPE_BOOLEAN:
			*gOut << attrs[i] << L": " << (col.pADsValues->Boolean ? L"TRUE" : L"FALSE") << std::endl;
			break;
		case ADSTYPE_OCTET_STRING:
			if (wcscmp(attrs[i], L"objectSid") == 0)
				*gOut << attrs[i] << L": "
				<< DecodeSid(col.pADsValues->OctetString.lpValue, col.pADsValues->OctetString.dwLength) << std::endl;
			else if (wcscmp(attrs[i], L"objectGUID") == 0)
				*gOut << attrs[i] << L": " << DecodeGUID(col.pADsValues->OctetString.lpValue) << std::endl;
			else
				*gOut << attrs[i] << L": [binary - " << col.pADsValues->OctetString.dwLength << L" bytes]" << std::endl;
			break;
		case ADSTYPE_UTC_TIME:
			*gOut << attrs[i] << L": "
				<< col.pADsValues->UTCTime.wYear << L"-"
				<< col.pADsValues->UTCTime.wMonth << L"-"
				<< col.pADsValues->UTCTime.wDay << std::endl;
			break;
		default:
			*gOut << attrs[i] << L": [unhandled type " << col.dwADsType << L"]" << std::endl;
			break;
		}
		pSearch->FreeColumn(&col);
	}
}

void ADSearch(std::wstring baseDN, LPWSTR filter, LPWSTR* attrs,
	DWORD attrCount, LPWSTR header, std::wstring dc = L"") {

	Log(std::wstring(L"Running module: ") + header);
	Log(std::wstring(L"Filter: ") + filter);

	IDirectorySearch* pSearch = BindSearch(baseDN, dc);
	if (!pSearch) return;

	Log(L"Bound to: LDAP://" + (dc.empty() ? L"" : dc + L"/") + baseDN);

	ADS_SEARCHPREF_INFO secPref;
	secPref.dwSearchPref = ADS_SEARCHPREF_SECURITY_MASK;
	secPref.vValue.dwType = ADSTYPE_INTEGER;
	secPref.vValue.Integer = ADS_SECURITY_INFO_OWNER | ADS_SECURITY_INFO_GROUP | ADS_SECURITY_INFO_DACL;
	pSearch->SetSearchPreference(&secPref, 1);

	ADS_SEARCH_HANDLE hSearch;
	HRESULT hr = pSearch->ExecuteSearch(filter, attrs, attrCount, &hSearch);
	if (FAILED(hr)) { LogHR(L"ExecuteSearch failed", hr); pSearch->Release(); return; }
	LogHR(L"ExecuteSearch", hr);

	int count = 0;
	HRESULT rowHr;

	while ((rowHr = pSearch->GetNextRow(hSearch)) != S_ADS_NOMORE_ROWS) {
		if (FAILED(rowHr)) { LogHR(L"GetNextRow failed", rowHr); break; }
		if (rowHr == S_ADS_NOMORE_COLUMNS) continue;
		count++;
		PrintRow(attrs, attrCount, header, pSearch, hSearch);
	}

	wchar_t countBuf[128];
	swprintf(countBuf, 128, L"%s - %d result(s) found", header, count);
	LogResult(countBuf, count > 0 ? L"+" : L"!");

	pSearch->CloseSearchHandle(hSearch);
	pSearch->Release();
}

void GPOMap(std::wstring baseDN, std::wstring dc = L"") {
	Log(L"Building GPO -> OU map...");

	IDirectorySearch* pSearch = BindSearch(baseDN, dc);
	if (!pSearch) return;

	std::map<std::wstring, std::wstring> gpoNames;
	LPWSTR gpoAttrs[] = { (LPWSTR)L"displayName", (LPWSTR)L"distinguishedName" };

	ADS_SEARCH_HANDLE hSearch;
	HRESULT hr = pSearch->ExecuteSearch(
		(LPWSTR)L"(objectClass=groupPolicyContainer)", gpoAttrs, 2, &hSearch);

	if (SUCCEEDED(hr)) {
		HRESULT rowHr;
		while ((rowHr = pSearch->GetNextRow(hSearch)) != S_ADS_NOMORE_ROWS) {
			if (FAILED(rowHr)) break;
			std::wstring dn, name;
			ADS_SEARCH_COLUMN col;
			if (SUCCEEDED(pSearch->GetColumn(hSearch, (LPWSTR)L"distinguishedName", &col))) {
				dn = col.pADsValues->CaseIgnoreString; pSearch->FreeColumn(&col);
			}
			if (SUCCEEDED(pSearch->GetColumn(hSearch, (LPWSTR)L"displayName", &col))) {
				name = col.pADsValues->CaseIgnoreString; pSearch->FreeColumn(&col);
			}
			size_t start = dn.find(L"{"), end = dn.find(L"}");
			if (start != std::wstring::npos && end != std::wstring::npos)
				gpoNames[dn.substr(start, end - start + 1)] = name;
		}
		pSearch->CloseSearchHandle(hSearch);
	}

	LogResult(L"GPO map built - " + std::to_wstring(gpoNames.size()) + L" GPOs found", L"+");

	LPWSTR ouAttrs[] = { (LPWSTR)L"name", (LPWSTR)L"distinguishedName", (LPWSTR)L"gpLink" };
	LPWSTR filters[] = {
		(LPWSTR)L"(&(objectClass=organizationalUnit)(gpLink=*))",
		(LPWSTR)L"(&(objectClass=domainDNS)(gpLink=*))"
	};

	std::wcout << L"\x1b[96m"; *gOut << L"\n[GPO MAPPING]"; std::wcout << L"\x1b[0m" << std::endl;
	*gOut << std::wstring(60, L'-') << std::endl;

	int totalLinks = 0;

	for (auto& filter : filters) {
		hr = pSearch->ExecuteSearch(filter, ouAttrs, 3, &hSearch);
		if (FAILED(hr)) continue;

		HRESULT rowHr;
		while ((rowHr = pSearch->GetNextRow(hSearch)) != S_ADS_NOMORE_ROWS) {
			if (FAILED(rowHr)) break;
			std::wstring ouName, ouDN, gpLink;
			ADS_SEARCH_COLUMN col;
			if (SUCCEEDED(pSearch->GetColumn(hSearch, (LPWSTR)L"name", &col))) {
				ouName = col.pADsValues->CaseIgnoreString; pSearch->FreeColumn(&col);
			}
			if (SUCCEEDED(pSearch->GetColumn(hSearch, (LPWSTR)L"distinguishedName", &col))) {
				ouDN = col.pADsValues->CaseIgnoreString; pSearch->FreeColumn(&col);
			}
			if (SUCCEEDED(pSearch->GetColumn(hSearch, (LPWSTR)L"gpLink", &col))) {
				gpLink = col.pADsValues->CaseIgnoreString; pSearch->FreeColumn(&col);
			}
			if (gpLink.empty()) continue;

			*gOut << L"\nOU: " << ouName << std::endl;
			*gOut << L"DN: " << ouDN << std::endl;

			size_t pos = 0;
			while ((pos = gpLink.find(L"{", pos)) != std::wstring::npos) {
				size_t end = gpLink.find(L"}", pos);
				if (end == std::wstring::npos) break;
				std::wstring guid = gpLink.substr(pos, end - pos + 1);
				std::wstring gpoName = L"[unknown GUID]";
				auto it = gpoNames.find(guid);
				if (it != gpoNames.end()) gpoName = it->second;
				std::wstring enforcement = L"Not Enforced";
				size_t semicolon = gpLink.find(L";", end);
				size_t bracket = gpLink.find(L"]", end);
				if (semicolon != std::wstring::npos && semicolon < bracket) {
					std::wstring flag = gpLink.substr(semicolon + 1, bracket - semicolon - 1);
					if (flag == L"2") enforcement = L"ENFORCED";
					else if (flag == L"1") enforcement = L"DISABLED";
				}
				*gOut << L"  -> GPO: " << gpoName << L" " << guid << L" [" << enforcement << L"]" << std::endl;
				totalLinks++;
				pos = end + 1;
			}
		}
		pSearch->CloseSearchHandle(hSearch);
	}

	wchar_t buf[128];
	swprintf(buf, 128, L"GPO map complete - %d link(s) found", totalLinks);
	LogResult(buf, totalLinks > 0 ? L"+" : L"!");
	pSearch->Release();
}


// ============================================================
// Sessions — NetSessionEnum / NetWkstaUserEnum per computer
// ============================================================
void SessionsEnum(std::wstring baseDN, std::wstring dc) {
	// First collect computer list via LDAP
	IDirectorySearch* pSearch = BindSearch(baseDN, dc);
	if (!pSearch) return;

	LPWSTR attrs[] = { (LPWSTR)L"dNSHostName", (LPWSTR)L"samAccountName" };
	ADS_SEARCH_HANDLE hSearch;
	HRESULT hr = pSearch->ExecuteSearch(
		(LPWSTR)L"(objectClass=computer)", attrs, 2, &hSearch);
	if (FAILED(hr)) { pSearch->Release(); return; }

	std::vector<std::wstring> hosts;
	HRESULT rowHr;
	while ((rowHr = pSearch->GetNextRow(hSearch)) != S_ADS_NOMORE_ROWS) {
		if (FAILED(rowHr)) break;
		ADS_SEARCH_COLUMN col;
		if (SUCCEEDED(pSearch->GetColumn(hSearch, (LPWSTR)L"dNSHostName", &col))) {
			hosts.push_back(col.pADsValues->CaseIgnoreString);
			pSearch->FreeColumn(&col);
		}
	}
	pSearch->CloseSearchHandle(hSearch);
	pSearch->Release();

	std::wcout << L"\x1b[96m"; *gOut << L"\n[SESSIONS]"; std::wcout << L"\x1b[0m" << std::endl;
	*gOut << std::wstring(60, L'-') << std::endl;

	int totalSessions = 0;

	for (auto& host : hosts) {
		SESSION_INFO_10* pBuf = nullptr;
		DWORD entriesRead = 0, totalEntries = 0;
		NET_API_STATUS status = NetSessionEnum(
			(LPWSTR)host.c_str(), nullptr, nullptr,
			10, (LPBYTE*)&pBuf,
			MAX_PREFERRED_LENGTH,
			&entriesRead, &totalEntries, nullptr);

		if (status == NERR_Success && pBuf) {
			for (DWORD i = 0; i < entriesRead; i++) {
				std::wstring user = pBuf[i].sesi10_username;
				if (user.empty() || user[0] == L'$') continue; // skip machine accounts
				*gOut << L"\n  Host:    " << host << std::endl;
				*gOut << L"  User:    " << user << std::endl;
				*gOut << L"  Client:  " << pBuf[i].sesi10_cname << std::endl;
				wchar_t timeBuf[32];
				swprintf(timeBuf, 32, L"%us active / %us idle",
					pBuf[i].sesi10_time, pBuf[i].sesi10_idle_time);
				*gOut << L"  Time:    " << timeBuf << std::endl;
				totalSessions++;
			}
			NetApiBufferFree(pBuf);
		}
		else if (status == ERROR_ACCESS_DENIED) {
			Log(L"  [" + host + L"] Access denied", L"-");
		}
		// silently skip unreachable hosts
	}

	wchar_t buf[128];
	swprintf(buf, 128, L"Sessions complete - %d host(s) queried, %d session(s) found",
		(int)hosts.size(), totalSessions);
	LogResult(buf, totalSessions > 0 ? L"+" : L"!");
}

// ============================================================
// Local Admins — NetLocalGroupGetMembers per computer
// ============================================================
void LocalAdminsEnum(std::wstring baseDN, std::wstring dc) {
	IDirectorySearch* pSearch = BindSearch(baseDN, dc);
	if (!pSearch) return;

	LPWSTR attrs[] = { (LPWSTR)L"dNSHostName", (LPWSTR)L"samAccountName" };
	ADS_SEARCH_HANDLE hSearch;
	HRESULT hr = pSearch->ExecuteSearch(
		(LPWSTR)L"(objectClass=computer)", attrs, 2, &hSearch);
	if (FAILED(hr)) { pSearch->Release(); return; }

	std::vector<std::wstring> hosts;
	HRESULT rowHr;
	while ((rowHr = pSearch->GetNextRow(hSearch)) != S_ADS_NOMORE_ROWS) {
		if (FAILED(rowHr)) break;
		ADS_SEARCH_COLUMN col;
		if (SUCCEEDED(pSearch->GetColumn(hSearch, (LPWSTR)L"dNSHostName", &col))) {
			hosts.push_back(col.pADsValues->CaseIgnoreString);
			pSearch->FreeColumn(&col);
		}
	}
	pSearch->CloseSearchHandle(hSearch);
	pSearch->Release();

	std::wcout << L"\x1b[96m"; *gOut << L"\n[LOCAL ADMINS]"; std::wcout << L"\x1b[0m" << std::endl;
	*gOut << std::wstring(60, L'-') << std::endl;

	int totalFindings = 0;

	for (auto& host : hosts) {
		LOCALGROUP_MEMBERS_INFO_2* pBuf = nullptr;
		DWORD entriesRead = 0, totalEntries = 0;
		NET_API_STATUS status = NetLocalGroupGetMembers(
			(LPWSTR)host.c_str(),
			L"Administrators",
			2, (LPBYTE*)&pBuf,
			MAX_PREFERRED_LENGTH,
			&entriesRead, &totalEntries, nullptr);

		if (status == NERR_Success && pBuf) {
			bool headerPrinted = false;
			for (DWORD i = 0; i < entriesRead; i++) {
				std::wstring name = pBuf[i].lgrmi2_domainandname
					? pBuf[i].lgrmi2_domainandname : L"[unknown]";
				// Skip built-in local Administrator account
				std::wstring nl = name;
				for (auto& c : nl) c = towlower(c);
				if (nl.find(L"\\administrator") != std::wstring::npos) continue;

				if (!headerPrinted) {
					*gOut << L"\n  Host: " << host << std::endl;
					headerPrinted = true;
				}

				std::wstring typeStr;
				switch (pBuf[i].lgrmi2_sidusage) {
				case SidTypeUser:    typeStr = L"USER";    break;
				case SidTypeGroup:   typeStr = L"GROUP";   break;
				case SidTypeAlias:   typeStr = L"ALIAS";   break;
				default:             typeStr = L"OTHER";   break;
				}
				*gOut << L"    [" << typeStr << L"] " << name << std::endl;
				totalFindings++;
			}
			NetApiBufferFree(pBuf);
		}
		else if (status == ERROR_ACCESS_DENIED) {
			Log(L"  [" + host + L"] Access denied", L"-");
		}
	}

	wchar_t buf[128];
	swprintf(buf, 128, L"Local admins complete - %d host(s) queried, %d non-default member(s) found",
		(int)hosts.size(), totalFindings);
	LogResult(buf, totalFindings > 0 ? L"+" : L"!");
}

// ============================================================
// ACL Detail — full categorized ACL dump for one specific object
// ============================================================
void ACLDetail(std::wstring baseDN, std::wstring dc, std::wstring objectName) {
	IDirectorySearch* pSearch = BindSearch(baseDN, dc);
	if (!pSearch) return;

	ADS_SEARCHPREF_INFO prefs[3];
	prefs[0].dwSearchPref = ADS_SEARCHPREF_SEARCH_SCOPE;
	prefs[0].vValue.dwType = ADSTYPE_INTEGER;
	prefs[0].vValue.Integer = ADS_SCOPE_SUBTREE;
	prefs[1].dwSearchPref = ADS_SEARCHPREF_PAGESIZE;
	prefs[1].vValue.dwType = ADSTYPE_INTEGER;
	prefs[1].vValue.Integer = 100;
	prefs[2].dwSearchPref = ADS_SEARCHPREF_SECURITY_MASK;
	prefs[2].vValue.dwType = ADSTYPE_INTEGER;
	prefs[2].vValue.Integer = ADS_SECURITY_INFO_DACL | ADS_SECURITY_INFO_OWNER | ADS_SECURITY_INFO_GROUP;
	pSearch->SetSearchPreference(prefs, 3);

	// Build filter for the specific object
	wchar_t filterBuf[512];
	swprintf(filterBuf, 512,
		L"(|(samAccountName=%s)(cn=%s)(dNSHostName=%s))",
		objectName.c_str(), objectName.c_str(), objectName.c_str());

	LPWSTR attrs[] = {
		(LPWSTR)L"distinguishedName", (LPWSTR)L"samAccountName",
		(LPWSTR)L"objectClass", (LPWSTR)L"nTSecurityDescriptor"
	};

	ADS_SEARCH_HANDLE hSearch;
	HRESULT hr = pSearch->ExecuteSearch(filterBuf, attrs, 4, &hSearch);
	if (FAILED(hr)) { pSearch->Release(); return; }

	HRESULT rowHr = pSearch->GetNextRow(hSearch);
	if (rowHr == S_ADS_NOMORE_ROWS) {
		LogResult(L"Object not found: " + objectName, L"-");
		pSearch->CloseSearchHandle(hSearch);
		pSearch->Release();
		return;
	}

	std::wstring dn, sam, objClass;
	ADS_SEARCH_COLUMN col;
	if (SUCCEEDED(pSearch->GetColumn(hSearch, (LPWSTR)L"distinguishedName", &col))) {
		dn = col.pADsValues->CaseIgnoreString; pSearch->FreeColumn(&col);
	}
	if (SUCCEEDED(pSearch->GetColumn(hSearch, (LPWSTR)L"samAccountName", &col))) {
		sam = col.pADsValues->CaseIgnoreString; pSearch->FreeColumn(&col);
	}
	if (SUCCEEDED(pSearch->GetColumn(hSearch, (LPWSTR)L"objectClass", &col))) {
		for (DWORD j = 0; j < col.dwNumValues; j++)
			objClass = col.pADsValues[j].CaseIgnoreString;
		pSearch->FreeColumn(&col);
	}

	hr = pSearch->GetColumn(hSearch, (LPWSTR)L"nTSecurityDescriptor", &col);
	if (FAILED(hr) || col.dwADsType != ADSTYPE_NT_SECURITY_DESCRIPTOR) {
		LogResult(L"Could not read security descriptor", L"-");
		pSearch->CloseSearchHandle(hSearch);
		pSearch->Release();
		return;
	}

	PSECURITY_DESCRIPTOR pSD = (PSECURITY_DESCRIPTOR)col.pADsValues->SecurityDescriptor.lpValue;

	// Get owner
	PSID pOwnerSid = nullptr;
	BOOL ownerDefaulted = FALSE;
	GetSecurityDescriptorOwner(pSD, &pOwnerSid, &ownerDefaulted);
	std::wstring ownerName = pOwnerSid ? SidToName(pOwnerSid) : L"[unknown]";

	*gOut << L"\n[ACL DETAIL: " << sam << L"]" << std::endl;
	*gOut << std::wstring(60, L'-') << std::endl;
	*gOut << L"  Object:  " << sam << L" [" << objClass << L"]" << std::endl;
	*gOut << L"  DN:      " << dn << std::endl;
	*gOut << L"  Owner:   " << ownerName << std::endl;

	// Parse all ACEs — categorize into buckets
	PACL pDacl = nullptr;
	BOOL daclPresent = FALSE, daclDefaulted2 = FALSE;
	GetSecurityDescriptorDacl(pSD, &daclPresent, &pDacl, &daclDefaulted2);

	struct AceEntry {
		std::wstring trustee;
		std::wstring rights;
		bool isDefault;
	};

	std::vector<AceEntry> offensive, elevated, standard, defaultEntries;

	if (daclPresent && pDacl) {
		ACL_SIZE_INFORMATION aclInfo = {};
		GetAclInformation(pDacl, &aclInfo, sizeof(aclInfo), AclSizeInformation);

		for (DWORD i = 0; i < aclInfo.AceCount; i++) {
			LPVOID pAce = nullptr;
			if (!GetAce(pDacl, i, &pAce)) continue;
			ACE_HEADER* header = (ACE_HEADER*)pAce;

			BOOL isAllow = (header->AceType == ACCESS_ALLOWED_ACE_TYPE ||
				header->AceType == ACCESS_ALLOWED_OBJECT_ACE_TYPE);

			PSID pSid = nullptr;
			DWORD mask = 0;
			const GUID* pObjType = nullptr;

			if (header->AceType == ACCESS_ALLOWED_ACE_TYPE ||
				header->AceType == ACCESS_DENIED_ACE_TYPE) {
				ACCESS_ALLOWED_ACE* ace = (ACCESS_ALLOWED_ACE*)pAce;
				mask = ace->Mask;
				pSid = (PSID)&ace->SidStart;
			}
			else if (header->AceType == ACCESS_ALLOWED_OBJECT_ACE_TYPE ||
				header->AceType == ACCESS_DENIED_OBJECT_ACE_TYPE) {
				ACCESS_ALLOWED_OBJECT_ACE* ace = (ACCESS_ALLOWED_OBJECT_ACE*)pAce;
				mask = ace->Mask;
				if (ace->Flags & ACE_OBJECT_TYPE_PRESENT) pObjType = &ace->ObjectType;
				DWORD offset = 0;
				if (ace->Flags & ACE_OBJECT_TYPE_PRESENT)           offset += sizeof(GUID);
				if (ace->Flags & ACE_INHERITED_OBJECT_TYPE_PRESENT) offset += sizeof(GUID);
				pSid = (PSID)((PBYTE)&ace->ObjectType + offset);
			}
			else continue;

			if (!pSid || !IsValidSid(pSid)) continue;

			std::wstring trusteeName = SidToName(pSid);
			std::wstring prefix = isAllow ? L"ALLOW" : L"DENY ";

			// Build rights string — full detail mode, include everything
			std::wstring rights = prefix + L" | ";

			// Generic
			if (mask & GENERIC_ALL)              rights += L"GenericAll ";
			if (mask & GENERIC_READ)             rights += L"GenericRead ";
			if (mask & GENERIC_WRITE)            rights += L"GenericWrite ";
			if (mask & GENERIC_EXECUTE)          rights += L"GenericExecute ";
			if (mask & READ_CONTROL)             rights += L"ReadControl ";
			if (mask & WRITE_DAC)                rights += L"WriteDACL ";
			if (mask & WRITE_OWNER)              rights += L"WriteOwner ";
			if (mask & DELETE)                   rights += L"Delete ";
			// DS-specific
			if (mask & ADS_RIGHT_DS_CREATE_CHILD) rights += L"CreateChild ";
			if (mask & ADS_RIGHT_DS_DELETE_CHILD) rights += L"DeleteChild ";
			if (mask & 0x00000004)                rights += L"ListContents ";
			if (mask & ADS_RIGHT_DS_SELF)         rights += L"Self ";
			if (mask & ADS_RIGHT_DS_READ_PROP)    rights += L"ReadProp ";
			if (mask & ADS_RIGHT_DS_WRITE_PROP) {
				if (pObjType) {
					wchar_t gs[64];
					swprintf(gs, 64, L"{%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}",
						pObjType->Data1, pObjType->Data2, pObjType->Data3,
						pObjType->Data4[0], pObjType->Data4[1],
						pObjType->Data4[2], pObjType->Data4[3],
						pObjType->Data4[4], pObjType->Data4[5],
						pObjType->Data4[6], pObjType->Data4[7]);
					std::wstring gsl(gs); for (auto& c : gsl) c = towlower(c);
					static const struct { const wchar_t* g; const wchar_t* n; } propGuids[] = {
						{ L"{bf9679c0-0de6-11d0-a285-00aa003049e2}", L"member" },
						{ L"{3f78c3e5-f79a-46bd-a0b8-9d18116ddc79}", L"msDS-AllowedToActOnBehalfOfOtherIdentity(RBCD)" },
						{ L"{bf967a7f-0de6-11d0-a285-00aa003049e2}", L"userCertificate" },
						{ L"{bf9679a8-0de6-11d0-a285-00aa003049e2}", L"scriptPath" },
						{ L"{f3a64788-5306-11d1-a9c5-0000f80367c1}", L"servicePrincipalName" },
						{ L"{77b5b886-944a-11d1-aebd-0000f80367c1}", L"personalInformation" },
						{ L"{e45795b2-9455-11d1-aebd-0000f80367c1}", L"emailInformation" },
						{ L"{e45795b3-9455-11d1-aebd-0000f80367c1}", L"webInformation" },
						{ L"{ea1b7b93-5e48-46d5-bc6c-4df4fda78a35}", L"msDS-KeyCredentialLink" },
						{ L"{5b47d60f-6090-40b2-9f37-2a4de88f3063}", L"msDS-KeyCredentialLink(KeyAdmins)" },
						{ L"{6db69a1c-9422-11d1-aebd-0000f80367c1}", L"terminalServerLicenseServer" },
						{ L"{5805bc62-bdc9-4428-a5e2-856a0f4c185e}", L"allowedTSLogon" },
						{ L"{91e647de-d96f-4b70-9557-d63ff4f3ccd8}", L"privateInformation" },
						{ L"{bf967953-0de6-11d0-a285-00aa003049e2}", L"userAccountControl" },
						{ L"{bf967950-0de6-11d0-a285-00aa003049e2}", L"pwdLastSet" },
					};
					bool propFound = false;
					for (auto& pg : propGuids) {
						std::wstring pgl(pg.g); for (auto& c : pgl) c = towlower(c);
						if (gsl == pgl) { rights += L"WriteProp(" + std::wstring(pg.n) + L") "; propFound = true; break; }
					}
					if (!propFound) rights += L"WriteProp(" + std::wstring(gs) + L") ";
				}
				else { rights += L"WriteProp(All) "; }
			}
			if (mask & ADS_RIGHT_DS_DELETE_TREE)  rights += L"DeleteTree ";
			if (mask & 0x00000080)                rights += L"ListObject ";
			if (mask & ADS_RIGHT_DS_CONTROL_ACCESS) {
				if (pObjType) {
					bool isNoise = false;
					std::wstring extRight = ResolveExtendedRight(pObjType, isNoise);
					if (!extRight.empty())
						rights += extRight + L" ";
					// suppress unknown/noise extended rights in detail output
				}
				else { rights += L"AllExtendedRights "; }
			}

			// Categorize — default trustees always go to DEFAULT regardless of rights
			bool isDefault = IsDefaultTrustee(trusteeName);
			AceEntry entry{ trusteeName, rights, isDefault };
			int sev = RightSeverity(rights);

			if (!isAllow) {
				standard.push_back(entry);
			}
			else if (isDefault) {
				defaultEntries.push_back(entry);
			}
			else if (sev <= 7) {
				offensive.push_back(entry);
			}
			else {
				elevated.push_back(entry);
			}
		}
	}

	pSearch->FreeColumn(&col);
	pSearch->CloseSearchHandle(hSearch);
	pSearch->Release();

	// Dedup helper
	auto dedup = [](std::vector<AceEntry>& v) {
		std::vector<AceEntry> out;
		for (auto& e : v) {
			std::wstring key = e.trustee + L"|" + e.rights;
			bool seen = false;
			for (auto& o : out) if (o.trustee + L"|" + o.rights == key) { seen = true; break; }
			if (!seen) out.push_back(e);
		}
		v = out;
		};
	dedup(offensive); dedup(elevated); dedup(standard); dedup(defaultEntries);

	// Print categorized output
	auto printSection = [&](const std::vector<AceEntry>& entries, const std::wstring& label) {
		if (entries.empty()) return;
		*gOut << L"\n  -- " << label << L" --" << std::endl;
		for (auto& e : entries)
			*gOut << L"  " << e.trustee << L"\n    " << e.rights << std::endl;
		};

	printSection(offensive, L"OFFENSIVE (non-default dangerous rights)");
	printSection(elevated, L"ELEVATED  (non-default other rights)");
	printSection(standard, L"DENY ACEs");
	printSection(defaultEntries, L"DEFAULT   (high-priv built-in trustees)");

	*gOut << std::endl;
	LogResult(L"ACL detail complete: " + sam, L"+");
}


// ============================================================
// Fine-Grained Password Policies (PSOs)
// ============================================================
std::wstring FormatTimeSpan(LONGLONG interval) {
	// interval is stored as negative 100-nanosecond intervals
	if (interval == 0) return L"0";
	LONGLONG secs = (interval < 0 ? -interval : interval) / 10000000LL;
	LONGLONG mins = secs / 60; secs %= 60;
	LONGLONG hours = mins / 60; mins %= 60;
	LONGLONG days = hours / 24; hours %= 24;
	wchar_t buf[64] = {};
	if (days)  swprintf(buf, 64, L"%lldd %02lluh %02llum", days, hours, mins);
	else if (hours) swprintf(buf, 64, L"%lluh %02llum", hours, mins);
	else       swprintf(buf, 64, L"%llum %02llus", mins, secs);
	return buf;
}

void FineGrainedEnum(std::wstring baseDN, std::wstring dc) {
	// PSOs live in CN=Password Settings Container,CN=System,<baseDN>
	std::wstring psoDN = L"CN=Password Settings Container,CN=System," + baseDN;
	std::wstring ldapPath = dc.empty()
		? L"LDAP://" + psoDN
		: L"LDAP://" + dc + L"/" + psoDN;

	IDirectorySearch* pSearch = nullptr;
	HRESULT hr = ADsGetObject(ldapPath.c_str(), IID_IDirectorySearch, (void**)&pSearch);
	if (FAILED(hr)) {
		LogResult(L"No Fine-Grained Password Policies found (container not accessible)", L"!");
		return;
	}

	ADS_SEARCHPREF_INFO prefs[2];
	prefs[0].dwSearchPref = ADS_SEARCHPREF_SEARCH_SCOPE;
	prefs[0].vValue.dwType = ADSTYPE_INTEGER;
	prefs[0].vValue.Integer = ADS_SCOPE_ONELEVEL;
	prefs[1].dwSearchPref = ADS_SEARCHPREF_PAGESIZE;
	prefs[1].vValue.dwType = ADSTYPE_INTEGER;
	prefs[1].vValue.Integer = 100;
	pSearch->SetSearchPreference(prefs, 2);

	LPWSTR attrs[] = {
		(LPWSTR)L"cn",
		(LPWSTR)L"msDS-PasswordSettingsPrecedence",
		(LPWSTR)L"msDS-PasswordReversibleEncryptionEnabled",
		(LPWSTR)L"msDS-PasswordHistoryLength",
		(LPWSTR)L"msDS-MaximumPasswordAge",
		(LPWSTR)L"msDS-MinimumPasswordAge",
		(LPWSTR)L"msDS-MinimumPasswordLength",
		(LPWSTR)L"msDS-PasswordComplexityEnabled",
		(LPWSTR)L"msDS-LockoutThreshold",
		(LPWSTR)L"msDS-LockoutObservationWindow",
		(LPWSTR)L"msDS-LockoutDuration",
		(LPWSTR)L"msDS-PSOAppliesTo",
	};

	ADS_SEARCH_HANDLE hSearch;
	hr = pSearch->ExecuteSearch(
		(LPWSTR)L"(objectClass=msDS-PasswordSettings)",
		attrs, 12, &hSearch);
	if (FAILED(hr)) { pSearch->Release(); return; }

	*gOut << L"\n[FINE-GRAINED PASSWORD POLICIES]" << std::endl;
	*gOut << std::wstring(60, L'=') << std::endl;

	int count = 0;
	HRESULT rowHr;

	while ((rowHr = pSearch->GetNextRow(hSearch)) != S_ADS_NOMORE_ROWS) {
		if (FAILED(rowHr)) break;
		count++;

		ADS_SEARCH_COLUMN col;
		std::wstring name;
		LONG precedence = 0, histLen = 0, minLen = 0, lockoutThresh = 0;
		LONGLONG maxAge = 0, minAge = 0, lockoutWindow = 0, lockoutDur = 0;
		bool complexity = false, reversible = false;
		std::vector<std::wstring> appliesTo;

		if (SUCCEEDED(pSearch->GetColumn(hSearch, (LPWSTR)L"cn", &col))) {
			name = col.pADsValues->CaseIgnoreString; pSearch->FreeColumn(&col);
		}
		if (SUCCEEDED(pSearch->GetColumn(hSearch, (LPWSTR)L"msDS-PasswordSettingsPrecedence", &col))) {
			precedence = col.pADsValues->Integer; pSearch->FreeColumn(&col);
		}
		if (SUCCEEDED(pSearch->GetColumn(hSearch, (LPWSTR)L"msDS-MinimumPasswordLength", &col))) {
			minLen = col.pADsValues->Integer; pSearch->FreeColumn(&col);
		}
		if (SUCCEEDED(pSearch->GetColumn(hSearch, (LPWSTR)L"msDS-PasswordHistoryLength", &col))) {
			histLen = col.pADsValues->Integer; pSearch->FreeColumn(&col);
		}
		if (SUCCEEDED(pSearch->GetColumn(hSearch, (LPWSTR)L"msDS-LockoutThreshold", &col))) {
			lockoutThresh = col.pADsValues->Integer; pSearch->FreeColumn(&col);
		}
		if (SUCCEEDED(pSearch->GetColumn(hSearch, (LPWSTR)L"msDS-PasswordComplexityEnabled", &col))) {
			complexity = col.pADsValues->Boolean != 0; pSearch->FreeColumn(&col);
		}
		if (SUCCEEDED(pSearch->GetColumn(hSearch, (LPWSTR)L"msDS-PasswordReversibleEncryptionEnabled", &col))) {
			reversible = col.pADsValues->Boolean != 0; pSearch->FreeColumn(&col);
		}
		if (SUCCEEDED(pSearch->GetColumn(hSearch, (LPWSTR)L"msDS-MaximumPasswordAge", &col))) {
			maxAge = col.pADsValues->LargeInteger.QuadPart; pSearch->FreeColumn(&col);
		}
		if (SUCCEEDED(pSearch->GetColumn(hSearch, (LPWSTR)L"msDS-MinimumPasswordAge", &col))) {
			minAge = col.pADsValues->LargeInteger.QuadPart; pSearch->FreeColumn(&col);
		}
		if (SUCCEEDED(pSearch->GetColumn(hSearch, (LPWSTR)L"msDS-LockoutObservationWindow", &col))) {
			lockoutWindow = col.pADsValues->LargeInteger.QuadPart; pSearch->FreeColumn(&col);
		}
		if (SUCCEEDED(pSearch->GetColumn(hSearch, (LPWSTR)L"msDS-LockoutDuration", &col))) {
			lockoutDur = col.pADsValues->LargeInteger.QuadPart; pSearch->FreeColumn(&col);
		}
		if (SUCCEEDED(pSearch->GetColumn(hSearch, (LPWSTR)L"msDS-PSOAppliesTo", &col))) {
			for (DWORD j = 0; j < col.dwNumValues; j++)
				appliesTo.push_back(col.pADsValues[j].CaseIgnoreString);
			pSearch->FreeColumn(&col);
		}

		// ── Header ──
		*gOut << L"\n  Policy:     " << name << std::endl;
		*gOut << L"  Precedence: " << precedence
			<< L"  (lower = higher priority)" << std::endl;
		*gOut << std::wstring(60, L'-') << std::endl;

		// ── Password settings ──
		*gOut << L"  [Password Settings]" << std::endl;
		*gOut << L"    Min Length:    " << minLen << std::endl;
		*gOut << L"    History:       " << histLen << L" passwords remembered" << std::endl;
		*gOut << L"    Complexity:    " << (complexity ? L"Enabled" : L"Disabled") << std::endl;
		*gOut << L"    Reversible:    " << (reversible ? L"YES (cleartext stored!)" : L"No") << std::endl;
		*gOut << L"    Max Age:       " << (maxAge == 0 ? L"0 (never expires)" : FormatTimeSpan(maxAge)) << std::endl;
		*gOut << L"    Min Age:       " << (minAge == 0 ? L"0 (no minimum)" : FormatTimeSpan(minAge)) << std::endl;

		// ── Lockout settings — highlight spray-relevant info ──
		*gOut << L"\n  [Lockout Settings]" << std::endl;
		if (lockoutThresh == 0) {
			*gOut << L"    Threshold:     0  [!!!] NO LOCKOUT - safe to spray" << std::endl;
		}
		else {
			*gOut << L"    Threshold:     " << lockoutThresh << L" attempts" << std::endl;
		}
		*gOut << L"    Obs. Window:   " << (lockoutWindow == 0 ? L"N/A" : FormatTimeSpan(lockoutWindow)) << std::endl;
		*gOut << L"    Duration:      " << (lockoutDur == 0 ? L"N/A" : FormatTimeSpan(lockoutDur)) << std::endl;

		// ── Applies to ──
		*gOut << L"\n  [Applies To]" << std::endl;
		if (appliesTo.empty()) {
			*gOut << L"    (none assigned)" << std::endl;
		}
		else {
			for (auto& t : appliesTo)
				*gOut << L"    " << t << std::endl;
		}
		*gOut << std::endl;
	}

	pSearch->CloseSearchHandle(hSearch);
	pSearch->Release();

	wchar_t buf[128];
	swprintf(buf, 128, L"Fine-grained policies complete - %d PSO(s) found", count);
	LogResult(buf, count > 0 ? L"+" : L"!");
}


// ============================================================
// Shares — NetShareEnum per computer
// ============================================================

// ============================================================
// Share Tree — recursive directory listing of a share path
// ============================================================
void PrintShareTree(const std::wstring& uncPath, int depth = 0) {
	if (depth > 3) return; // max depth
	std::wstring indent(depth * 2 + 6, L' ');
	std::wstring searchPath = uncPath + L"\\*";

	WIN32_FIND_DATAW ffd;
	HANDLE hFind = FindFirstFileW(searchPath.c_str(), &ffd);
	if (hFind == INVALID_HANDLE_VALUE) {
		DWORD err = GetLastError();
		if (err == ERROR_ACCESS_DENIED)
			*gOut << indent << L"[access denied]" << std::endl;
		else if (err != ERROR_NO_MORE_FILES)
			*gOut << indent << L"[empty or inaccessible]" << std::endl;
		return;
	}

	do {
		std::wstring name = ffd.cFileName;
		if (name == L"." || name == L"..") continue;

		if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
			*gOut << indent << L"[DIR]  " << name << std::endl;
			if (depth < 2) // only recurse 2 levels
				PrintShareTree(uncPath + L"\\" + name, depth + 1);
		}
		else {
			// Format file size
			ULARGE_INTEGER sz;
			sz.HighPart = ffd.nFileSizeHigh;
			sz.LowPart = ffd.nFileSizeLow;
			wchar_t szStr[32];
			if (sz.QuadPart >= 1073741824) swprintf(szStr, 32, L"%.1fGB", sz.QuadPart / 1073741824.0);
			else if (sz.QuadPart >= 1048576)    swprintf(szStr, 32, L"%.1fMB", sz.QuadPart / 1048576.0);
			else if (sz.QuadPart >= 1024)       swprintf(szStr, 32, L"%.1fKB", sz.QuadPart / 1024.0);
			else                                swprintf(szStr, 32, L"%lluB", sz.QuadPart);
			*gOut << indent << L"[FILE] " << name << L"  (" << szStr << L")" << std::endl;
		}
	} while (FindNextFileW(hFind, &ffd));

	FindClose(hFind);
}

void SharesEnum(std::wstring baseDN, std::wstring dc) {
	IDirectorySearch* pSearch = BindSearch(baseDN, dc);
	if (!pSearch) return;

	LPWSTR attrs[] = { (LPWSTR)L"dNSHostName" };
	ADS_SEARCH_HANDLE hSearch;
	HRESULT hr = pSearch->ExecuteSearch((LPWSTR)L"(objectClass=computer)", attrs, 1, &hSearch);
	if (FAILED(hr)) { pSearch->Release(); return; }

	std::vector<std::wstring> hosts;
	HRESULT rowHr;
	while ((rowHr = pSearch->GetNextRow(hSearch)) != S_ADS_NOMORE_ROWS) {
		if (FAILED(rowHr)) break;
		ADS_SEARCH_COLUMN col;
		if (SUCCEEDED(pSearch->GetColumn(hSearch, (LPWSTR)L"dNSHostName", &col))) {
			hosts.push_back(col.pADsValues->CaseIgnoreString);
			pSearch->FreeColumn(&col);
		}
	}
	pSearch->CloseSearchHandle(hSearch);
	pSearch->Release();

	// Default share names to skip
	static const wchar_t* defaultShares[] = {
		L"ADMIN$", L"C$", L"D$", L"E$", L"IPC$",
		L"NETLOGON", L"SYSVOL", L"PRINT$", nullptr
	};

	std::wcout << L"\x1b[96m"; *gOut << L"\n[SHARES]"; std::wcout << L"\x1b[0m" << std::endl;
	*gOut << std::wstring(60, L'-') << std::endl;

	int totalShares = 0;

	for (auto& host : hosts) {
		SHARE_INFO_1* pBuf = nullptr;
		DWORD entriesRead = 0, totalEntries = 0;
		NET_API_STATUS status = NetShareEnum(
			(LPWSTR)host.c_str(), 1, (LPBYTE*)&pBuf,
			MAX_PREFERRED_LENGTH, &entriesRead, &totalEntries, nullptr);

		if (status == NERR_Success && pBuf) {
			bool headerPrinted = false;
			for (DWORD i = 0; i < entriesRead; i++) {
				std::wstring name = pBuf[i].shi1_netname ? pBuf[i].shi1_netname : L"";
				if (name.empty()) continue;

				// Skip default shares
				std::wstring nl = name;
				for (auto& c : nl) c = towupper(c);
				bool isDefault = false;
				for (int d = 0; defaultShares[d]; d++) {
					if (nl == defaultShares[d]) { isDefault = true; break; }
				}
				// Also skip single-letter admin shares (E$, F$, etc)
				if (nl.size() == 2 && nl[1] == L'$') isDefault = true;
				if (isDefault) continue;

				if (!headerPrinted) {
					*gOut << L"\n  Host: " << host << std::endl;
					headerPrinted = true;
				}

				std::wstring remark = pBuf[i].shi1_remark ? pBuf[i].shi1_remark : L"";
				std::wstring typeStr;
				switch (pBuf[i].shi1_type & ~STYPE_SPECIAL) {
				case STYPE_DISKTREE:  typeStr = L"Disk";    break;
				case STYPE_PRINTQ:    typeStr = L"Print";   break;
				case STYPE_DEVICE:    typeStr = L"Device";  break;
				case STYPE_IPC:       typeStr = L"IPC";     break;
				default:              typeStr = L"Other";   break;
				}
				if (pBuf[i].shi1_type & STYPE_SPECIAL) typeStr += L"(Hidden)";

				*gOut << L"    [" << typeStr << L"] " << name;
				if (!remark.empty()) *gOut << L"  (" << remark << L")";
				*gOut << std::endl;

				// Get share permissions via level 502
				SHARE_INFO_502* pShareInfo = nullptr;
				if (NetShareGetInfo((LPWSTR)host.c_str(), (LPWSTR)name.c_str(),
					502, (LPBYTE*)&pShareInfo) == NERR_Success && pShareInfo) {
					if (pShareInfo->shi502_path && pShareInfo->shi502_path[0])
						*gOut << L"      Path:  " << pShareInfo->shi502_path << std::endl;
					if (pShareInfo->shi502_security_descriptor &&
						IsValidSecurityDescriptor(pShareInfo->shi502_security_descriptor)) {
						PACL pDacl2 = nullptr; BOOL p2 = FALSE, d2 = FALSE;
						GetSecurityDescriptorDacl(pShareInfo->shi502_security_descriptor, &p2, &pDacl2, &d2);
						if (p2 && pDacl2) {
							ACL_SIZE_INFORMATION ai2 = {};
							GetAclInformation(pDacl2, &ai2, sizeof(ai2), AclSizeInformation);
							*gOut << L"      Perms:" << std::endl;
							for (DWORD ax = 0; ax < ai2.AceCount; ax++) {
								LPVOID pAx = nullptr;
								if (!GetAce(pDacl2, ax, &pAx)) continue;
								ACE_HEADER* hx = (ACE_HEADER*)pAx;
								if (hx->AceType != ACCESS_ALLOWED_ACE_TYPE &&
									hx->AceType != ACCESS_DENIED_ACE_TYPE) continue;
								ACCESS_ALLOWED_ACE* ax2 = (ACCESS_ALLOWED_ACE*)pAx;
								PSID pSx = (PSID)&ax2->SidStart;
								if (!IsValidSid(pSx)) continue;
								std::wstring atype = (hx->AceType == ACCESS_ALLOWED_ACE_TYPE) ? L"ALLOW" : L"DENY ";
								DWORD m = ax2->Mask;
								std::wstring perms;
								if ((m & 0x001F01FF) == 0x001F01FF)   perms = L"FullControl";
								else if ((m & 0x001301BF) == 0x001301BF) perms = L"Change";
								else if ((m & 0x001200A9) == 0x001200A9) perms = L"Read";
								else if (m & GENERIC_ALL)  perms = L"FullControl";
								else if (m & GENERIC_WRITE) perms = L"Write";
								else if (m & GENERIC_READ)  perms = L"Read";
								else { wchar_t ms[16]; swprintf(ms, 16, L"0x%08X", m); perms = ms; }
								*gOut << L"        " << atype << L"  " << SidToName(pSx)
									<< L"  [" << perms << L"]" << std::endl;
							}
						}
					}
					// Tree listing if --tree flag
					if (gShareTree && pShareInfo->shi502_path && pShareInfo->shi502_path[0]) {
						std::wstring uncTree = L"\\\\" + host + L"\\" + name;
						*gOut << L"      Tree:" << std::endl;
						PrintShareTree(uncTree, 0);
					}
					NetApiBufferFree(pShareInfo);
				}
				totalShares++;
			}
			NetApiBufferFree(pBuf);
		}
		else if (status == ERROR_ACCESS_DENIED) {
			Log(L"  [" + host + L"] Access denied", L"-");
		}
	}

	wchar_t buf[128];
	swprintf(buf, 128, L"Shares complete - %d host(s) queried, %d non-default share(s) found",
		(int)hosts.size(), totalShares);
	LogResult(buf, totalShares > 0 ? L"+" : L"!");
}

// ============================================================
// Password Not Changed — pwdLastSet older than N days
// ============================================================
void PassNotChangedEnum(std::wstring baseDN, std::wstring dc, int days = 365) {
	LONGLONG cutoff = DaysAgoFileTime(days);

	wchar_t filterBuf[256];
	swprintf(filterBuf, 256,
		L"(&(samAccountType=805306368)(pwdLastSet<=%I64d)"
		L"(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
		L"(!(pwdLastSet=0)))",
		cutoff);

	LPWSTR attrs[] = {
		(LPWSTR)L"samAccountName",
		(LPWSTR)L"distinguishedName",
		(LPWSTR)L"pwdLastSet",
		(LPWSTR)L"lastLogon",
		(LPWSTR)L"userAccountControl",
		(LPWSTR)L"adminCount",
		(LPWSTR)L"objectSid"
	};

	wchar_t header[64];
	swprintf(header, 64, L"PASS_NOT_CHANGED_%dDAYS", days);
	ADSearch(baseDN, filterBuf, attrs, 7, header, dc);
}

// ============================================================
// RBCD — resource-based constrained delegation
// ============================================================
void RBCDEnum(std::wstring baseDN, std::wstring dc) {
	LPWSTR attrs[] = {
		(LPWSTR)L"samAccountName",
		(LPWSTR)L"distinguishedName",
		(LPWSTR)L"msDS-AllowedToActOnBehalfOfOtherIdentity",
		(LPWSTR)L"objectClass",
		(LPWSTR)L"userAccountControl",
		(LPWSTR)L"objectSid"
	};

	IDirectorySearch* pSearch = BindSearch(baseDN, dc);
	if (!pSearch) return;

	ADS_SEARCHPREF_INFO prefs[2];
	prefs[0].dwSearchPref = ADS_SEARCHPREF_SEARCH_SCOPE;
	prefs[0].vValue.dwType = ADSTYPE_INTEGER;
	prefs[0].vValue.Integer = ADS_SCOPE_SUBTREE;
	prefs[1].dwSearchPref = ADS_SEARCHPREF_PAGESIZE;
	prefs[1].vValue.dwType = ADSTYPE_INTEGER;
	prefs[1].vValue.Integer = 100;
	pSearch->SetSearchPreference(prefs, 2);

	LPWSTR filter = (LPWSTR)L"(msDS-AllowedToActOnBehalfOfOtherIdentity=*)";
	ADS_SEARCH_HANDLE hSearch;
	HRESULT hr = pSearch->ExecuteSearch(filter, attrs, 6, &hSearch);
	if (FAILED(hr)) { pSearch->Release(); return; }

	*gOut << L"\n[RBCD - Resource-Based Constrained Delegation]" << std::endl;
	*gOut << std::wstring(60, L'-') << std::endl;

	int count = 0;
	HRESULT rowHr;
	while ((rowHr = pSearch->GetNextRow(hSearch)) != S_ADS_NOMORE_ROWS) {
		if (FAILED(rowHr)) break;

		std::wstring sam, dn, objClass;
		ADS_SEARCH_COLUMN col;

		if (SUCCEEDED(pSearch->GetColumn(hSearch, (LPWSTR)L"samAccountName", &col))) {
			sam = col.pADsValues->CaseIgnoreString; pSearch->FreeColumn(&col);
		}
		if (SUCCEEDED(pSearch->GetColumn(hSearch, (LPWSTR)L"distinguishedName", &col))) {
			dn = col.pADsValues->CaseIgnoreString; pSearch->FreeColumn(&col);
		}
		if (SUCCEEDED(pSearch->GetColumn(hSearch, (LPWSTR)L"objectClass", &col))) {
			for (DWORD j = 0; j < col.dwNumValues; j++)
				objClass = col.pADsValues[j].CaseIgnoreString;
			pSearch->FreeColumn(&col);
		}

		// Parse msDS-AllowedToActOnBehalfOfOtherIdentity SD
		std::wstring trustedBy = L"[not readable]";
		hr = pSearch->GetColumn(hSearch, (LPWSTR)L"msDS-AllowedToActOnBehalfOfOtherIdentity", &col);
		if (SUCCEEDED(hr)) {
			PSECURITY_DESCRIPTOR pSD = nullptr;
			std::vector<BYTE> sdBuf;

			// Attribute can come back as octet string or NT SD depending on ADSI version
			if (col.dwADsType == ADSTYPE_NT_SECURITY_DESCRIPTOR &&
				col.pADsValues->SecurityDescriptor.lpValue) {
				pSD = (PSECURITY_DESCRIPTOR)col.pADsValues->SecurityDescriptor.lpValue;
			}
			else if (col.dwADsType == ADSTYPE_OCTET_STRING &&
				col.pADsValues->OctetString.lpValue &&
				col.pADsValues->OctetString.dwLength > 0) {
				DWORD sdLen = col.pADsValues->OctetString.dwLength;
				sdBuf.resize(sdLen);
				memcpy(sdBuf.data(), col.pADsValues->OctetString.lpValue, sdLen);
				pSD = (PSECURITY_DESCRIPTOR)sdBuf.data();
			}

			if (pSD && IsValidSecurityDescriptor(pSD)) {
				PACL pDacl = nullptr;
				BOOL present = FALSE, defaulted = FALSE;
				GetSecurityDescriptorDacl(pSD, &present, &pDacl, &defaulted);

				if (present && pDacl) {
					ACL_SIZE_INFORMATION info = {};
					GetAclInformation(pDacl, &info, sizeof(info), AclSizeInformation);
					std::wstring trustees;

					for (DWORD ai = 0; ai < info.AceCount; ai++) {
						LPVOID pAce = nullptr;
						if (!GetAce(pDacl, ai, &pAce)) continue;
						ACE_HEADER* hdr = (ACE_HEADER*)pAce;
						PSID pSid = nullptr;

						if (hdr->AceType == ACCESS_ALLOWED_ACE_TYPE ||
							hdr->AceType == ACCESS_DENIED_ACE_TYPE) {
							pSid = (PSID) & ((ACCESS_ALLOWED_ACE*)pAce)->SidStart;
						}
						else if (hdr->AceType == ACCESS_ALLOWED_OBJECT_ACE_TYPE ||
							hdr->AceType == ACCESS_DENIED_OBJECT_ACE_TYPE) {
							ACCESS_ALLOWED_OBJECT_ACE* oa = (ACCESS_ALLOWED_OBJECT_ACE*)pAce;
							DWORD off = 0;
							if (oa->Flags & ACE_OBJECT_TYPE_PRESENT)           off += sizeof(GUID);
							if (oa->Flags & ACE_INHERITED_OBJECT_TYPE_PRESENT) off += sizeof(GUID);
							pSid = (PSID)((PBYTE)&oa->ObjectType + off);
						}

						if (!pSid || !IsValidSid(pSid)) continue;

						// Try name lookup first, fall back to raw SID string
						std::wstring entry = SidToName(pSid);
						if (!trustees.empty()) trustees += L"\n              ";
						trustees += entry;
					}

					if (!trustees.empty())
						trustedBy = trustees;
					else if (info.AceCount == 0)
						trustedBy = L"[DACL empty]";
					else
						trustedBy = L"[" + std::to_wstring(info.AceCount) + L" ACE(s) - SIDs unresolvable]";
				}
				else {
					trustedBy = L"[no DACL]";
				}
			}
			else if (pSD) {
				// SD present but invalid - dump SDDL as fallback
				LPWSTR sddl = nullptr;
				if (ConvertSecurityDescriptorToStringSecurityDescriptorW(
					pSD, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &sddl, nullptr) && sddl) {
					trustedBy = L"[raw] " + std::wstring(sddl);
					LocalFree(sddl);
				}
			}
			else {
				trustedBy = L"[unrecognized SD type: " + std::to_wstring(col.dwADsType) + L"]";
			}
			pSearch->FreeColumn(&col);
		}

		std::wstring ol = objClass;
		for (auto& c : ol) c = towlower(c);
		std::wstring typeLabel = (ol == L"computer") ? L"COMPUTER" : L"USER";

		*gOut << L"\n  [" << typeLabel << L"] " << sam << std::endl;
		*gOut << L"  DN:         " << dn << std::endl;
		*gOut << L"  Trusted by: " << trustedBy << std::endl;
		*gOut << L"  Note:       Any trusted principal can impersonate any user to this target" << std::endl;
		count++;
	}

	pSearch->CloseSearchHandle(hSearch);
	pSearch->Release();

	wchar_t buf[128];
	swprintf(buf, 128, L"RBCD complete - %d object(s) with msDS-AllowedToActOnBehalfOfOtherIdentity set", count);
	LogResult(buf, count > 0 ? L"+" : L"!");
}

// ============================================================
// MAQ — Machine Account Quota
// ============================================================
void MAQEnum(std::wstring baseDN, std::wstring dc) {
	std::wstring ldapPath = dc.empty()
		? L"LDAP://" + baseDN
		: L"LDAP://" + dc + L"/" + baseDN;

	IADs* pADs = nullptr;
	HRESULT hr = ADsGetObject(ldapPath.c_str(), IID_IADs, (void**)&pADs);
	if (FAILED(hr)) { LogResult(L"Failed to bind for MAQ check", L"-"); return; }

	VARIANT var;
	VariantInit(&var);
	hr = pADs->Get(SysAllocString(L"ms-DS-MachineAccountQuota"), &var);

	std::wcout << L"\x1b[96m"; *gOut << L"\n[MACHINE ACCOUNT QUOTA]"; std::wcout << L"\x1b[0m" << std::endl;
	*gOut << std::wstring(60, L'-') << std::endl;

	if (SUCCEEDED(hr) && var.vt == VT_I4) {
		LONG maq = var.lVal;
		*gOut << L"  ms-DS-MachineAccountQuota: " << maq << std::endl;
		if (maq == 0) {
			*gOut << L"  Status: Only admins can join machines to the domain" << std::endl;
			LogResult(L"MAQ = 0 - unprivileged machine creation disabled", L"!");
		}
		else {
			*gOut << L"  Status: Any authenticated user can join up to " << maq << L" machine(s)" << std::endl;
			*gOut << L"  Note:   RBCD attack prerequisite satisfied - machine accounts can be created" << std::endl;
			wchar_t buf[128];
			swprintf(buf, 128, L"MAQ = %d - unprivileged users can add machines [RBCD prereq met]", maq);
			LogResult(buf, L"+");
		}
	}
	else {
		*gOut << L"  ms-DS-MachineAccountQuota: (not readable)" << std::endl;
		LogResult(L"MAQ - could not read attribute", L"-");
	}

	VariantClear(&var);
	pADs->Release();
}

void PrintUsage() {
	std::wcout << L"" << std::endl;
	// ASCII art banner
	std::wcout << L"" << std::endl;
	std::wcout << L"" << std::endl;
	std::wcout << L"" << std::endl;
	std::wcout << L"  __  __   _____   ___    ____      _      _   _ " << std::endl;
	std::wcout << L"  __  __   _____   ___    ____      _      _   _ " << std::endl;
	std::wcout << L" |  \\/  | | ____| |_ _|  / ___|    / \\    | \\ | |" << std::endl;
	std::wcout << L" | |\\/| | |  _|    | |  | |  _    / _ \\   |  \\| |" << std::endl;
	std::wcout << L" | |  | | | |___   | |  | |_| |  / ___ \\  | |\\  |" << std::endl;
	std::wcout << L" |_|  |_| |_____| |___|  \\____| /_/   \\_\\ |_| \\_|" << std::endl;
	std::wcout << L"" << std::endl;
	std::wcout << L"  Active Directory Enumeration Tool  |  v0.1" << std::endl;
	std::wcout << L"  by saretawa" << std::endl;
	std::wcout << L"  For authorized use only" << std::endl;
	std::wcout << L"" << std::endl;
	std::wcout << L"  Usage: Meigan.exe <module> [options]" << std::endl;
	std::wcout << L"" << std::endl;
	std::wcout << L"  MODULES - CORE" << std::endl;
	std::wcout << L"  --------------" << std::endl;
	std::wcout << L"    users          All domain user accounts with full attribute detail" << std::endl;
	std::wcout << L"    groups         Domain groups with membership, type and security flags" << std::endl;
	std::wcout << L"    computers      Domain computers with OS version, last logon, SPNs" << std::endl;
	std::wcout << L"    dclist         All domain controllers with OS and FSMO role info" << std::endl;
	std::wcout << L"    trusts         Domain and forest trusts with direction, type, attributes" << std::endl;
	std::wcout << L"    ous            Organizational units with GPO links and delegation info" << std::endl;
	std::wcout << L"" << std::endl;
	std::wcout << L"  MODULES - ATTACK SURFACE" << std::endl;
	std::wcout << L"  ------------------------" << std::endl;
	std::wcout << L"    spns           Kerberoastable accounts (ServicePrincipalName set)" << std::endl;
	std::wcout << L"    asrep          ASREPRoastable accounts (no Kerberos pre-auth required)" << std::endl;
	std::wcout << L"    admins         Accounts with adminCount=1 (protected by AdminSDHolder)" << std::endl;
	std::wcout << L"    delegation     Unconstrained delegation (TrustedForDelegation flag)" << std::endl;
	std::wcout << L"    constrained    Constrained delegation (msDS-AllowedToDelegateTo set)" << std::endl;
	std::wcout << L"    laps           Computers with readable LAPS password (ms-Mcs-AdmPwd)" << std::endl;
	std::wcout << L"    shares         Non-default SMB shares on domain computers" << std::endl;
	std::wcout << L"                   Skips ADMIN$, C$, IPC$, SYSVOL, NETLOGON and hidden shares" << std::endl;
	std::wcout << L"" << std::endl;
	std::wcout << L"  MODULES - WEAK CONFIGURATIONS" << std::endl;
	std::wcout << L"  -----------------------------" << std::endl;
	std::wcout << L"    disabled       Disabled user accounts" << std::endl;
	std::wcout << L"    noexpiry       Accounts with DONT_EXPIRE_PASSWD flag set" << std::endl;
	std::wcout << L"    emptypass      Accounts with PASSWD_NOTREQD (no password required)" << std::endl;
	std::wcout << L"    stale          Enabled accounts with no logon activity in 90+ days" << std::endl;
	std::wcout << L"    passnotchanged Accounts whose password has not changed in 365+ days" << std::endl;
	std::wcout << L"                   Good spray target list - likely weak or reused passwords" << std::endl;
	std::wcout << L"    finegrained    Fine-Grained Password Policies (PSOs)" << std::endl;
	std::wcout << L"                   Shows min length, complexity, lockout threshold per policy" << std::endl;
	std::wcout << L"                   Lockout=0 flagged as spray-safe. Lists applies-to targets." << std::endl;
	std::wcout << L"" << std::endl;
	std::wcout << L"  MODULES - DELEGATION / RBCD" << std::endl;
	std::wcout << L"  ---------------------------" << std::endl;
	std::wcout << L"    rbcd           Objects with msDS-AllowedToActOnBehalfOfOtherIdentity set" << std::endl;
	std::wcout << L"                   Resolves trusted principals from the security descriptor" << std::endl;
	std::wcout << L"    maq            Machine Account Quota on the domain object" << std::endl;
	std::wcout << L"                   If >0, any user can join machines - RBCD attack prerequisite" << std::endl;
	std::wcout << L"" << std::endl;
	std::wcout << L"  MODULES - ACL / PERMISSIONS" << std::endl;
	std::wcout << L"  ---------------------------" << std::endl;
	std::wcout << L"    acls           Scan all objects for non-default dangerous ACEs" << std::endl;
	std::wcout << L"                   Detects: GenericAll, WriteDACL, WriteOwner, GenericWrite," << std::endl;
	std::wcout << L"                   CreateChild, ForceChangePassword, AllExtendedRights," << std::endl;
	std::wcout << L"                   DCSync (flagged), RBCD, Self-Membership" << std::endl;
	std::wcout << L"                   Covers users, groups, computers and OUs" << std::endl;
	std::wcout << L"                   Auto-detects multi-hop attack chains in full scan" << std::endl;
	std::wcout << L"                   Use with --trustee, --target, --detail, --dangerous" << std::endl;
	std::wcout << L"" << std::endl;
	std::wcout << L"  MODULES - GROUP POLICY" << std::endl;
	std::wcout << L"  ----------------------" << std::endl;
	std::wcout << L"    gpos           All GPOs with version number and SYSVOL path" << std::endl;
	std::wcout << L"    gpomap         GPO to OU mapping showing enforcement and inheritance" << std::endl;
	std::wcout << L"" << std::endl;
	std::wcout << L"  MODULES - HOST-BASED  (requires network access and appropriate rights)" << std::endl;
	std::wcout << L"  -----------------------------------------------------------------------" << std::endl;
	std::wcout << L"    sessions       Active SMB sessions per computer (NetSessionEnum)" << std::endl;
	std::wcout << L"                   Shows username, client IP, active and idle time" << std::endl;
	std::wcout << L"    localadmins    Local Administrators group members per computer" << std::endl;
	std::wcout << L"                   Skips built-in accounts. Tags USER/GROUP/ALIAS." << std::endl;
	std::wcout << L"" << std::endl;
	std::wcout << L"    all            Run all modules sequentially" << std::endl;
	std::wcout << L"" << std::endl;
	std::wcout << L"  OPTIONS - GLOBAL" << std::endl;
	std::wcout << L"  ----------------" << std::endl;
	std::wcout << L"    --dc <host>        Target a specific domain controller" << std::endl;
	std::wcout << L"                       Default: auto-discovered via rootDSE" << std::endl;
	std::wcout << L"    --output <file>    Write output to file in addition to stdout" << std::endl;
	std::wcout << L"    --verbose          Show LDAP bind/search debug and HRESULT values" << std::endl;
	std::wcout << L"    --filter <filter>  Execute a raw LDAP filter against the domain" << std::endl;
	std::wcout << L"    --help, -h         Show this help menu" << std::endl;
	std::wcout << L"" << std::endl;
	std::wcout << L"  OPTIONS - ACL  (use with: acls)" << std::endl;
	std::wcout << L"  --------------------------------" << std::endl;
	std::wcout << L"    --trustee <name>   Objects this principal has rights over (outbound)" << std::endl;
	std::wcout << L"                       Partial, case-insensitive match" << std::endl;
	std::wcout << L"    --target <name>    Non-default trustees with rights over this object" << std::endl;
	std::wcout << L"    --detail <name>    Full categorized ACL dump for one specific object" << std::endl;
	std::wcout << L"                       Sections: Offensive / Elevated / Deny / Default" << std::endl;
	std::wcout << L"    --dangerous        Highest-severity rights only:" << std::endl;
	std::wcout << L"                       GenericAll, WriteDACL, WriteOwner, DCSync" << std::endl;
	std::wcout << L"" << std::endl;
	std::wcout << L"  EXAMPLES" << std::endl;
	std::wcout << L"  --------" << std::endl;
	std::wcout << L"    Meigan.exe users                              Basic user enumeration" << std::endl;
	std::wcout << L"    Meigan.exe spns                               Find Kerberoastable accounts" << std::endl;
	std::wcout << L"    Meigan.exe laps                               Find readable LAPS passwords" << std::endl;
	std::wcout << L"    Meigan.exe finegrained                        PSOs and lockout thresholds" << std::endl;
	std::wcout << L"    Meigan.exe maq                                Machine account quota check" << std::endl;
	std::wcout << L"    Meigan.exe shares                             Non-default SMB shares" << std::endl;
	std::wcout << L"    Meigan.exe passnotchanged                     Passwords not changed in 365d" << std::endl;
	std::wcout << L"    Meigan.exe rbcd                               RBCD-configured objects" << std::endl;
	std::wcout << L"    Meigan.exe acls                               Full ACL scan" << std::endl;
	std::wcout << L"    Meigan.exe acls --dangerous                   Critical rights only" << std::endl;
	std::wcout << L"    Meigan.exe acls --trustee john.doe            What john.doe can do" << std::endl;
	std::wcout << L"    Meigan.exe acls --target administrator        Who can compromise admin" << std::endl;
	std::wcout << L"    Meigan.exe acls --detail bob                  Full ACL breakdown for bob" << std::endl;
	std::wcout << L"    Meigan.exe users --dc DC01.corp.com           Target specific DC" << std::endl;
	std::wcout << L"    Meigan.exe all --output full_recon.txt        Full domain dump to file" << std::endl;
	std::wcout << L"" << std::endl;
}

void RunModule(std::string cmd, std::wstring baseDN, std::wstring customFilter, std::wstring dc,
	std::wstring trustee, std::wstring target, std::wstring detail, bool dangerousOnly) {
	LPWSTR userAttrs[] = {
		(LPWSTR)L"samAccountName", (LPWSTR)L"distinguishedName",
		(LPWSTR)L"cn", (LPWSTR)L"description", (LPWSTR)L"memberOf",
		(LPWSTR)L"userAccountControl", (LPWSTR)L"lastLogon",
		(LPWSTR)L"pwdLastSet", (LPWSTR)L"whenCreated", (LPWSTR)L"whenChanged",
		(LPWSTR)L"mail", (LPWSTR)L"title", (LPWSTR)L"department",
		(LPWSTR)L"manager", (LPWSTR)L"adminCount", (LPWSTR)L"servicePrincipalName",
		(LPWSTR)L"objectSid", (LPWSTR)L"objectGUID", (LPWSTR)L"logonCount",
		(LPWSTR)L"badPwdCount", (LPWSTR)L"badPasswordTime", (LPWSTR)L"accountExpires",
		(LPWSTR)L"scriptPath", (LPWSTR)L"profilePath", (LPWSTR)L"homeDirectory",
		(LPWSTR)L"comment", (LPWSTR)L"info"
	};
	LPWSTR groupAttrs[] = {
		(LPWSTR)L"cn", (LPWSTR)L"sAMAccountName", (LPWSTR)L"distinguishedName",
		(LPWSTR)L"description", (LPWSTR)L"member", (LPWSTR)L"memberOf",
		(LPWSTR)L"managedBy", (LPWSTR)L"groupType", (LPWSTR)L"adminCount",
		(LPWSTR)L"objectSid", (LPWSTR)L"objectGUID", (LPWSTR)L"whenCreated",
		(LPWSTR)L"whenChanged", (LPWSTR)L"nTSecurityDescriptor"
	};
	LPWSTR computerAttrs[] = {
		(LPWSTR)L"cn", (LPWSTR)L"samAccountName", (LPWSTR)L"distinguishedName",
		(LPWSTR)L"operatingSystem", (LPWSTR)L"operatingSystemVersion",
		(LPWSTR)L"operatingSystemServicePack", (LPWSTR)L"lastLogon",
		(LPWSTR)L"whenCreated", (LPWSTR)L"userAccountControl",
		(LPWSTR)L"objectSid", (LPWSTR)L"objectGUID", (LPWSTR)L"dNSHostName",
		(LPWSTR)L"servicePrincipalName", (LPWSTR)L"description",
		(LPWSTR)L"managedBy", (LPWSTR)L"location"
	};
	LPWSTR spnAttrs[] = {
		(LPWSTR)L"samAccountName", (LPWSTR)L"servicePrincipalName",
		(LPWSTR)L"distinguishedName", (LPWSTR)L"pwdLastSet",
		(LPWSTR)L"lastLogon", (LPWSTR)L"userAccountControl",
		(LPWSTR)L"adminCount", (LPWSTR)L"objectSid"
	};
	LPWSTR asrepAttrs[] = {
		(LPWSTR)L"samAccountName", (LPWSTR)L"distinguishedName",
		(LPWSTR)L"pwdLastSet", (LPWSTR)L"userAccountControl",
		(LPWSTR)L"adminCount", (LPWSTR)L"objectSid"
	};
	LPWSTR adminAttrs[] = {
		(LPWSTR)L"samAccountName", (LPWSTR)L"distinguishedName",
		(LPWSTR)L"cn", (LPWSTR)L"memberOf", (LPWSTR)L"userAccountControl",
		(LPWSTR)L"pwdLastSet", (LPWSTR)L"lastLogon", (LPWSTR)L"objectSid",
		(LPWSTR)L"servicePrincipalName", (LPWSTR)L"description"
	};
	LPWSTR delegationAttrs[] = {
		(LPWSTR)L"samAccountName", (LPWSTR)L"distinguishedName",
		(LPWSTR)L"userAccountControl", (LPWSTR)L"servicePrincipalName",
		(LPWSTR)L"msDS-AllowedToDelegateTo", (LPWSTR)L"objectSid",
		(LPWSTR)L"pwdLastSet", (LPWSTR)L"adminCount"
	};
	LPWSTR trustAttrs[] = {
		(LPWSTR)L"cn", (LPWSTR)L"distinguishedName",
		(LPWSTR)L"trustPartner", (LPWSTR)L"trustType",
		(LPWSTR)L"trustDirection", (LPWSTR)L"trustAttributes",
		(LPWSTR)L"whenCreated", (LPWSTR)L"whenChanged"
	};
	LPWSTR ouAttrs[] = {
		(LPWSTR)L"name", (LPWSTR)L"distinguishedName",
		(LPWSTR)L"description", (LPWSTR)L"whenCreated",
		(LPWSTR)L"whenChanged", (LPWSTR)L"managedBy",
		(LPWSTR)L"objectGUID", (LPWSTR)L"gpLink"
	};
	LPWSTR gpoAttrs[] = {
		(LPWSTR)L"displayName", (LPWSTR)L"distinguishedName",
		(LPWSTR)L"gPCFileSysPath", (LPWSTR)L"whenCreated",
		(LPWSTR)L"whenChanged", (LPWSTR)L"objectGUID",
		(LPWSTR)L"flags", (LPWSTR)L"versionNumber"
	};
	LPWSTR quickUserAttrs[] = {
		(LPWSTR)L"samAccountName", (LPWSTR)L"distinguishedName",
		(LPWSTR)L"userAccountControl", (LPWSTR)L"pwdLastSet",
		(LPWSTR)L"lastLogon", (LPWSTR)L"adminCount",
		(LPWSTR)L"objectSid", (LPWSTR)L"description"
	};
	LPWSTR constrainedAttrs[] = {
		(LPWSTR)L"samAccountName", (LPWSTR)L"distinguishedName",
		(LPWSTR)L"userAccountControl", (LPWSTR)L"servicePrincipalName",
		(LPWSTR)L"msDS-AllowedToDelegateTo", (LPWSTR)L"objectSid",
		(LPWSTR)L"pwdLastSet", (LPWSTR)L"adminCount"
	};
	LPWSTR dcAttrs[] = {
		(LPWSTR)L"cn", (LPWSTR)L"samAccountName", (LPWSTR)L"distinguishedName",
		(LPWSTR)L"dNSHostName", (LPWSTR)L"operatingSystem",
		(LPWSTR)L"operatingSystemVersion", (LPWSTR)L"lastLogon",
		(LPWSTR)L"userAccountControl", (LPWSTR)L"objectSid"
	};
	LPWSTR lapsAttrs[] = {
		(LPWSTR)L"cn", (LPWSTR)L"samAccountName", (LPWSTR)L"distinguishedName",
		(LPWSTR)L"dNSHostName", (LPWSTR)L"ms-Mcs-AdmPwd",
		(LPWSTR)L"ms-Mcs-AdmPwdExpirationTime", (LPWSTR)L"operatingSystem"
	};
	LPWSTR defaultAttrs[] = {
		(LPWSTR)L"samAccountName", (LPWSTR)L"distinguishedName",
		(LPWSTR)L"cn", (LPWSTR)L"description", (LPWSTR)L"objectSid",
		(LPWSTR)L"objectGUID", (LPWSTR)L"whenCreated"
	};

	if (!customFilter.empty()) {
		Log(L"Running custom filter: " + customFilter);
		ADSearch(baseDN, (LPWSTR)customFilter.c_str(), defaultAttrs, 7, (LPWSTR)L"CUSTOM", dc);
		return;
	}

	LONGLONG staleCutoff = DaysAgoFileTime(90);
	wchar_t staleFilter[256];
	swprintf(staleFilter, 256,
		L"(&(samAccountType=805306368)(lastLogon<=%I64d)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
		staleCutoff);

	std::map<std::string, std::function<void()>> modules = {
		{"users",       [&]() { ADSearch(baseDN, (LPWSTR)L"(samAccountType=805306368)", userAttrs, 27, (LPWSTR)L"USER", dc); }},
		{"groups",      [&]() { ADSearch(baseDN, (LPWSTR)L"(objectClass=group)", groupAttrs, 14, (LPWSTR)L"GROUP", dc); }},
		{"computers",   [&]() { ADSearch(baseDN, (LPWSTR)L"(objectClass=computer)", computerAttrs, 16, (LPWSTR)L"COMPUTER", dc); }},
		{"spns",        [&]() { ADSearch(baseDN, (LPWSTR)L"(&(samAccountType=805306368)(servicePrincipalName=*))", spnAttrs, 8, (LPWSTR)L"KERBEROASTABLE", dc); }},
		{"asrep",       [&]() { ADSearch(baseDN, (LPWSTR)L"(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))", asrepAttrs, 6, (LPWSTR)L"ASREPROASTABLE", dc); }},
		{"admins",      [&]() { ADSearch(baseDN, (LPWSTR)L"(&(samAccountType=805306368)(adminCount=1))", adminAttrs, 10, (LPWSTR)L"ADMIN", dc); }},
		{"delegation",  [&]() { ADSearch(baseDN, (LPWSTR)L"(userAccountControl:1.2.840.113556.1.4.803:=524288)", delegationAttrs, 8, (LPWSTR)L"UNCONSTRAINED_DELEGATION", dc); }},
		{"constrained", [&]() { ADSearch(baseDN, (LPWSTR)L"(&(samAccountType=805306368)(msDS-AllowedToDelegateTo=*))", constrainedAttrs, 8, (LPWSTR)L"CONSTRAINED_DELEGATION", dc); }},
		{"trusts",      [&]() { ADSearch(baseDN, (LPWSTR)L"(objectClass=trustedDomain)", trustAttrs, 8, (LPWSTR)L"TRUST", dc); }},
		{"ous",         [&]() { ADSearch(baseDN, (LPWSTR)L"(objectClass=organizationalUnit)", ouAttrs, 8, (LPWSTR)L"OU", dc); }},
		{"gpos",        [&]() { ADSearch(baseDN, (LPWSTR)L"(objectClass=groupPolicyContainer)", gpoAttrs, 8, (LPWSTR)L"GPO", dc); }},
		{"gpomap",      [&]() { GPOMap(baseDN, dc); }},
		{"disabled",    [&]() { ADSearch(baseDN, (LPWSTR)L"(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=2))", quickUserAttrs, 8, (LPWSTR)L"DISABLED", dc); }},
		{"noexpiry",    [&]() { ADSearch(baseDN, (LPWSTR)L"(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=65536))", quickUserAttrs, 8, (LPWSTR)L"NOEXPIRY", dc); }},
		{"emptypass",   [&]() { ADSearch(baseDN, (LPWSTR)L"(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=32))", quickUserAttrs, 8, (LPWSTR)L"EMPTY_PASSWORD", dc); }},
		{"stale",       [&]() { ADSearch(baseDN, staleFilter, quickUserAttrs, 8, (LPWSTR)L"STALE_90DAYS", dc); }},
		{"dclist",      [&]() { ADSearch(baseDN, (LPWSTR)L"(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))", dcAttrs, 9, (LPWSTR)L"DOMAIN_CONTROLLER", dc); }},
		{"laps",        [&]() { ADSearch(baseDN, (LPWSTR)L"(&(objectClass=computer)(ms-Mcs-AdmPwd=*))", lapsAttrs, 7, (LPWSTR)L"LAPS_READABLE", dc); }},
		{"acls",        [&]() {
			if (!detail.empty()) ACLDetail(baseDN, dc, detail);
			else ACLEnum(baseDN, dc, trustee, target, dangerousOnly);
		}},
		{"sessions",    [&]() { SessionsEnum(baseDN, dc); }},
		{"localadmins", [&]() { LocalAdminsEnum(baseDN, dc); }},
		{"finegrained",  [&]() { FineGrainedEnum(baseDN, dc); }},
		{"shares",       [&]() { SharesEnum(baseDN, dc); }},
		{"passnotchanged",[&]() { PassNotChangedEnum(baseDN, dc); }},
		{"rbcd",         [&]() { RBCDEnum(baseDN, dc); }},
		{"maq",          [&]() { MAQEnum(baseDN, dc); }},
		{"all",         [&]() {
			ADSearch(baseDN, (LPWSTR)L"(samAccountType=805306368)", userAttrs, 27, (LPWSTR)L"USER", dc);
			ADSearch(baseDN, (LPWSTR)L"(objectClass=group)", groupAttrs, 14, (LPWSTR)L"GROUP", dc);
			ADSearch(baseDN, (LPWSTR)L"(objectClass=computer)", computerAttrs, 16, (LPWSTR)L"COMPUTER", dc);
			ADSearch(baseDN, (LPWSTR)L"(&(samAccountType=805306368)(servicePrincipalName=*))", spnAttrs, 8, (LPWSTR)L"KERBEROASTABLE", dc);
			ADSearch(baseDN, (LPWSTR)L"(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))", asrepAttrs, 6, (LPWSTR)L"ASREPROASTABLE", dc);
			ADSearch(baseDN, (LPWSTR)L"(&(samAccountType=805306368)(adminCount=1))", adminAttrs, 10, (LPWSTR)L"ADMIN", dc);
			ADSearch(baseDN, (LPWSTR)L"(userAccountControl:1.2.840.113556.1.4.803:=524288)", delegationAttrs, 8, (LPWSTR)L"UNCONSTRAINED_DELEGATION", dc);
			ADSearch(baseDN, (LPWSTR)L"(&(samAccountType=805306368)(msDS-AllowedToDelegateTo=*))", constrainedAttrs, 8, (LPWSTR)L"CONSTRAINED_DELEGATION", dc);
			ADSearch(baseDN, (LPWSTR)L"(objectClass=trustedDomain)", trustAttrs, 8, (LPWSTR)L"TRUST", dc);
			ADSearch(baseDN, (LPWSTR)L"(objectClass=organizationalUnit)", ouAttrs, 8, (LPWSTR)L"OU", dc);
			ADSearch(baseDN, (LPWSTR)L"(objectClass=groupPolicyContainer)", gpoAttrs, 8, (LPWSTR)L"GPO", dc);
			ADSearch(baseDN, (LPWSTR)L"(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=2))", quickUserAttrs, 8, (LPWSTR)L"DISABLED", dc);
			ADSearch(baseDN, (LPWSTR)L"(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=65536))", quickUserAttrs, 8, (LPWSTR)L"NOEXPIRY", dc);
			ADSearch(baseDN, (LPWSTR)L"(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=32))", quickUserAttrs, 8, (LPWSTR)L"EMPTY_PASSWORD", dc);
			ADSearch(baseDN, staleFilter, quickUserAttrs, 8, (LPWSTR)L"STALE_90DAYS", dc);
			ADSearch(baseDN, (LPWSTR)L"(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))", dcAttrs, 9, (LPWSTR)L"DOMAIN_CONTROLLER", dc);
			ADSearch(baseDN, (LPWSTR)L"(&(objectClass=computer)(ms-Mcs-AdmPwd=*))", lapsAttrs, 7, (LPWSTR)L"LAPS_READABLE", dc);
			GPOMap(baseDN, dc);
			ACLEnum(baseDN, dc, trustee, target, dangerousOnly);
			SessionsEnum(baseDN, dc);
			LocalAdminsEnum(baseDN, dc);
			FineGrainedEnum(baseDN, dc);
		}}
	};

	auto it = modules.find(cmd);
	if (it != modules.end())
		it->second();
	else
		LogResult(L"Unknown module: " + std::wstring(cmd.begin(), cmd.end()), L"-");
}

int main(int argc, char* argv[]) {
	// Enable ANSI color codes in Windows console
	HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
	DWORD dwMode = 0;
	if (GetConsoleMode(hOut, &dwMode))
		SetConsoleMode(hOut, dwMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);

	HRESULT coHr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
	if (FAILED(coHr) && coHr != RPC_E_CHANGED_MODE) {
		wchar_t buf[64];
		swprintf(buf, 64, L"CoInitializeEx failed: 0x%08X", coHr);
		std::wcout << buf << std::endl;
		return 1;
	}

	std::wcout << L"  [ MEIGAN ]  AD Enumeration  v0.1  by saretawa" << std::endl;
	std::wcout << L"" << std::endl;

	if (argc < 2) { PrintUsage(); CoUninitialize(); return 0; }

	std::string cmd = "";
	std::wstring dc = L"";
	std::wstring trustee = L"";
	std::wstring target = L"";
	std::wstring detail = L"";
	bool dangerousOnly = false;
	std::string outputFile = "";
	std::wstring customFilter = L"";

	for (int i = 1; i < argc; i++) {
		std::string arg = ToLower(argv[i]);

		if (arg == "--help" || arg == "-h") {
			PrintUsage(); CoUninitialize(); return 0;
		}
		else if (arg == "--verbose") {
			gVerbose = true;
		}
		else if (arg == "--dangerous") {
			dangerousOnly = true;
		}
		else if (arg == "--tree") {
			gShareTree = true;
		}
		else if (arg == "--dc" && i + 1 < argc) {
			std::string d = argv[++i];
			dc = std::wstring(d.begin(), d.end());
		}
		else if (arg == "--output" && i + 1 < argc) {
			outputFile = argv[++i];
		}
		else if (arg == "--filter" && i + 1 < argc) {
			std::string f = argv[++i];
			customFilter = std::wstring(f.begin(), f.end());
		}
		else if (arg == "--trustee" && i + 1 < argc) {
			std::string t = argv[++i];
			trustee = std::wstring(t.begin(), t.end());
		}
		else if (arg == "--target" && i + 1 < argc) {
			std::string t = argv[++i];
			target = std::wstring(t.begin(), t.end());
		}
		else if (arg == "--detail" && i + 1 < argc) {
			std::string t = argv[++i];
			detail = std::wstring(t.begin(), t.end());
		}
		else {
			cmd = arg;
		}
	}

	if (!outputFile.empty()) {
		gFileOut.open(outputFile);
		if (!gFileOut.is_open()) {
			LogResult(L"Failed to open output file", L"-");
			CoUninitialize(); return 1;
		}
		gOut = &gFileOut;
		std::wcout << L"[+] Output writing to: " << outputFile.c_str() << std::endl;
	}

	if (cmd.empty() && customFilter.empty()) { PrintUsage(); CoUninitialize(); return 0; }
	if (!dc.empty()) std::wcout << L"[+] Using DC: " << dc << std::endl;

	std::wstring baseDN = GetDomainInfo(true, dc);
	if (baseDN.empty()) {
		LogResult(L"Failed to resolve base DN - cannot continue", L"-");
		CoUninitialize(); return 1;
	}

	RunModule(cmd, baseDN, customFilter, dc, trustee, target, detail, dangerousOnly);

	if (gFileOut.is_open()) {
		gFileOut.close();
		std::wcout << L"[+] Output saved" << std::endl;
	}

	CoUninitialize();
	return 0;
}