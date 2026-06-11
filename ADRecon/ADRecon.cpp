#include <windows.h>
#include <activeds.h>
#include <adshlp.h>
#include <iostream>
#include <sddl.h>

#pragma comment(lib, "activeds.lib")
#pragma comment(lib, "adsiid.lib")
#pragma comment(lib, "advapi32.lib")

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
	return flags;
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
		st.wYear, st.wMonth, st.wDay,
		st.wHour, st.wMinute, st.wSecond);

	return std::wstring(buf);
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
		pGuid->Data1,
		pGuid->Data2,
		pGuid->Data3,
		pGuid->Data4[0], pGuid->Data4[1],
		pGuid->Data4[2], pGuid->Data4[3],
		pGuid->Data4[4], pGuid->Data4[5],
		pGuid->Data4[6], pGuid->Data4[7]);
	return std::wstring(buf);
}

std::wstring GetDomainInfo(bool printbasic) {
	IADs* pADs = nullptr;
	HRESULT hr = ADsGetObject(L"LDAP://rootDSE", IID_IADs, (void**)&pADs);

	if (FAILED(hr)) {
		std::wcout << L"[-] Failed to bind to rootDSE" << std::endl;
		return L"";
	}

	std::wstring baseDN;

	struct domainproperty {
		std::wstring propertyDescription;
		BSTR propertyname;
	};

	domainproperty defaultNamingContext{ L"Base DN:", SysAllocString(L"defaultNamingContext") };
	domainproperty dnsDomainName{ L"DNS Domain Name:", SysAllocString(L"ldapServiceName") };
	domainproperty pdcName{ L"PDC:", SysAllocString(L"dsServiceName") };

	for (auto& property : { defaultNamingContext, dnsDomainName, pdcName }) {
		VARIANT var;
		VariantInit(&var);
		pADs->Get(property.propertyname, &var);

		if (printbasic) {
			if (var.vt != VT_EMPTY && var.bstrVal != nullptr) {
				std::wcout << L"[+] " << property.propertyDescription.c_str()
					<< L" " << var.bstrVal << std::endl;
			}
			else {
				std::wcout << L"[+] " << property.propertyDescription.c_str()
					<< L" (not found)" << std::endl;
			}
		}

		if (property.propertyDescription == L"Base DN:") {
			if (var.vt != VT_EMPTY && var.bstrVal != nullptr)
				baseDN = std::wstring(var.bstrVal);
		}

		VariantClear(&var);
		SysFreeString(property.propertyname);
	}

	pADs->Release();
	return baseDN;
}

void GetUsers(std::wstring baseDN) {
	IDirectorySearch* pSearch = nullptr;
	std::wstring ldapPath = L"LDAP://" + baseDN;
	HRESULT hr = ADsGetObject(ldapPath.c_str(), IID_IDirectorySearch, (void**)&pSearch);

	if (FAILED(hr)) {
		std::wcout << L"[-] Failed to bind to LDAP" << std::endl;
		return;
	}

	ADS_SEARCHPREF_INFO prefs[2];
	prefs[0].dwSearchPref = ADS_SEARCHPREF_SEARCH_SCOPE;
	prefs[0].vValue.dwType = ADSTYPE_INTEGER;
	prefs[0].vValue.Integer = ADS_SCOPE_SUBTREE;
	prefs[1].dwSearchPref = ADS_SEARCHPREF_PAGESIZE;
	prefs[1].vValue.dwType = ADSTYPE_INTEGER;
	prefs[1].vValue.Integer = 1000;
	pSearch->SetSearchPreference(prefs, 2);

	LPWSTR filter = (LPWSTR)L"(samAccountType=805306368)";

	LPWSTR attrs[] = {
		(LPWSTR)L"samAccountName",
		(LPWSTR)L"distinguishedName",
		(LPWSTR)L"cn",
		(LPWSTR)L"description",
		(LPWSTR)L"memberOf",
		(LPWSTR)L"userAccountControl",
		(LPWSTR)L"lastLogon",
		(LPWSTR)L"pwdLastSet",
		(LPWSTR)L"whenCreated",
		(LPWSTR)L"whenChanged",
		(LPWSTR)L"mail",
		(LPWSTR)L"title",
		(LPWSTR)L"department",
		(LPWSTR)L"manager",
		(LPWSTR)L"adminCount",
		(LPWSTR)L"servicePrincipalName",
		(LPWSTR)L"objectSid",
		(LPWSTR)L"objectGUID",
		(LPWSTR)L"logonCount",
		(LPWSTR)L"badPwdCount",
		(LPWSTR)L"badPasswordTime",
		(LPWSTR)L"accountExpires",
		(LPWSTR)L"scriptPath",
		(LPWSTR)L"profilePath",
		(LPWSTR)L"homeDirectory",
		(LPWSTR)L"comment",
		(LPWSTR)L"info"
	};
	DWORD attrCount = 27;

	ADS_SEARCH_HANDLE hSearch;
	hr = pSearch->ExecuteSearch(filter, attrs, attrCount, &hSearch);
	if (FAILED(hr)) {
		std::wcout << L"[-] Search failed" << std::endl;
		pSearch->Release();
		return;
	}

	while (pSearch->GetNextRow(hSearch) != S_ADS_NOMORE_ROWS) {
		std::wcout << L"\n[USER]" << std::endl;
		ADS_SEARCH_COLUMN col;

		for (DWORD i = 0; i < attrCount; i++) {
			hr = pSearch->GetColumn(hSearch, attrs[i], &col);
			if (SUCCEEDED(hr)) {
				switch (col.dwADsType) {
				case ADSTYPE_CASE_IGNORE_STRING:
				case ADSTYPE_DN_STRING:
				case ADSTYPE_PRINTABLE_STRING:
				case ADSTYPE_NUMERIC_STRING:
					for (DWORD j = 0; j < col.dwNumValues; j++) {
						std::wcout << attrs[i] << L": "
							<< col.pADsValues[j].CaseIgnoreString << std::endl;
					}
					break;

				case ADSTYPE_INTEGER:
					if (wcscmp(attrs[i], L"userAccountControl") == 0) {
						DWORD uac = col.pADsValues->Integer;
						std::wcout << L"userAccountControl: " << uac
							<< L" (" << DecodeUAC(uac) << L")" << std::endl;
					}
					else {
						std::wcout << attrs[i] << L": "
							<< col.pADsValues->Integer << std::endl;
					}
					break;

				case ADSTYPE_LARGE_INTEGER:
					std::wcout << attrs[i] << L": "
						<< FileTimeToReadable(col.pADsValues->LargeInteger.QuadPart)
						<< std::endl;
					break;

				case ADSTYPE_BOOLEAN:
					std::wcout << attrs[i] << L": "
						<< (col.pADsValues->Boolean ? L"TRUE" : L"FALSE") << std::endl;
					break;

				case ADSTYPE_OCTET_STRING:
					if (wcscmp(attrs[i], L"objectSid") == 0) {
						std::wcout << attrs[i] << L": "
							<< DecodeSid(
								col.pADsValues->OctetString.lpValue,
								col.pADsValues->OctetString.dwLength)
							<< std::endl;
					}
					else if (wcscmp(attrs[i], L"objectGUID") == 0) {
						std::wcout << attrs[i] << L": "
							<< DecodeGUID(col.pADsValues->OctetString.lpValue)
							<< std::endl;
					}
					else {
						std::wcout << attrs[i] << L": [binary - "
							<< col.pADsValues->OctetString.dwLength
							<< L" bytes]" << std::endl;
					}
					break;

				case ADSTYPE_UTC_TIME:
					std::wcout << attrs[i] << L": "
						<< col.pADsValues->UTCTime.wYear << L"-"
						<< col.pADsValues->UTCTime.wMonth << L"-"
						<< col.pADsValues->UTCTime.wDay << std::endl;
					break;

				default:
					std::wcout << attrs[i] << L": [unhandled type "
						<< col.dwADsType << L"]" << std::endl;
					break;
				}
				pSearch->FreeColumn(&col);
			}
		}
	}

	pSearch->CloseSearchHandle(hSearch);
	pSearch->Release();
}

void GetGroups(std::wstring baseDN) {
	IDirectorySearch* pSearch = nullptr;
	std::wstring ldapPath = L"LDAP://" + baseDN;
	HRESULT hr = ADsGetObject(ldapPath.c_str(), IID_IDirectorySearch, (void**)&pSearch);

	if (FAILED(hr)) {
		std::wcout << L"[-] Failed to bind to LDAP" << std::endl;
		return;
	}

	ADS_SEARCHPREF_INFO prefs[2];
	prefs[0].dwSearchPref = ADS_SEARCHPREF_SEARCH_SCOPE;
	prefs[0].vValue.dwType = ADSTYPE_INTEGER;
	prefs[0].vValue.Integer = ADS_SCOPE_SUBTREE;
	prefs[1].dwSearchPref = ADS_SEARCHPREF_PAGESIZE;
	prefs[1].vValue.dwType = ADSTYPE_INTEGER;
	prefs[1].vValue.Integer = 1000;
	pSearch->SetSearchPreference(prefs, 2);

	LPWSTR filter = (LPWSTR)L"(objectClass=group)";

	LPWSTR attrs[] = {
		(LPWSTR)L"cn",
		(LPWSTR)L"sAMAccountName",
		(LPWSTR)L"distinguishedName",
		(LPWSTR)L"description",
		(LPWSTR)L"member",
		(LPWSTR)L"memberOf",
		(LPWSTR)L"managedBy",
		(LPWSTR)L"groupType",
		(LPWSTR)L"adminCount",
		(LPWSTR)L"objectSid",
		(LPWSTR)L"objectGUID",
		(LPWSTR)L"whenCreated",
		(LPWSTR)L"whenChanged",
		(LPWSTR)L"nTSecurityDescriptor"
	};
	DWORD attrCount = 14;

	ADS_SEARCH_HANDLE hSearch;
	hr = pSearch->ExecuteSearch(filter, attrs, attrCount, &hSearch);
	if (FAILED(hr)) {
		std::wcout << L"[-] Search failed" << std::endl;
		pSearch->Release();
		return;
	}

	while (pSearch->GetNextRow(hSearch) != S_ADS_NOMORE_ROWS) {
		std::wcout << L"\n[GROUP]" << std::endl;
		ADS_SEARCH_COLUMN col;

		for (DWORD i = 0; i < attrCount; i++) {
			hr = pSearch->GetColumn(hSearch, attrs[i], &col);
			if (SUCCEEDED(hr)) {
				switch (col.dwADsType) {
				case ADSTYPE_DN_STRING:
				case ADSTYPE_CASE_IGNORE_STRING:
				case ADSTYPE_PRINTABLE_STRING:
					for (DWORD j = 0; j < col.dwNumValues; j++) {
						std::wcout << attrs[i] << L": "
							<< col.pADsValues[j].CaseIgnoreString << std::endl;
					}
					break;

				case ADSTYPE_INTEGER:
					if (wcscmp(attrs[i], L"groupType") == 0) {
						std::wcout << L"groupType: "
							<< DecodeGroupType((LONG)col.pADsValues->Integer)
							<< std::endl;
					}
					else {
						std::wcout << attrs[i] << L": "
							<< col.pADsValues->Integer << std::endl;
					}
					break;

				case ADSTYPE_LARGE_INTEGER:
					std::wcout << attrs[i] << L": "
						<< FileTimeToReadable(col.pADsValues->LargeInteger.QuadPart)
						<< std::endl;
					break;

				case ADSTYPE_OCTET_STRING:
					if (wcscmp(attrs[i], L"objectSid") == 0) {
						std::wcout << attrs[i] << L": "
							<< DecodeSid(
								col.pADsValues->OctetString.lpValue,
								col.pADsValues->OctetString.dwLength)
							<< std::endl;
					}
					else if (wcscmp(attrs[i], L"objectGUID") == 0) {
						std::wcout << attrs[i] << L": "
							<< DecodeGUID(col.pADsValues->OctetString.lpValue)
							<< std::endl;
					}
					else {
						std::wcout << attrs[i] << L": [binary - "
							<< col.pADsValues->OctetString.dwLength
							<< L" bytes]" << std::endl;
					}
					break;

				case ADSTYPE_UTC_TIME:
					std::wcout << attrs[i] << L": "
						<< col.pADsValues->UTCTime.wYear << L"-"
						<< col.pADsValues->UTCTime.wMonth << L"-"
						<< col.pADsValues->UTCTime.wDay << std::endl;
					break;

				default:
					std::wcout << attrs[i] << L": [unhandled type "
						<< col.dwADsType << L"]" << std::endl;
					break;
				}
				pSearch->FreeColumn(&col);
			}
		}
	}

	pSearch->CloseSearchHandle(hSearch);
	pSearch->Release();
}



int main(int argc, char* argv[]) {
	CoInitialize(nullptr);

	std::wcout << L"[+] ADRecon started" << std::endl;
	std::wstring baseDN = GetDomainInfo(true);

	if (argc < 2) {
		std::wcout << L"\nUsage: ADRecon.exe [module]" << std::endl;
		std::wcout << L"  users     - enumerate domain users" << std::endl;
		std::wcout << L"  groups    - enumerate domain groups" << std::endl;
		std::wcout << L"  all       - run everything" << std::endl;
		CoUninitialize();
		return 0;
	}

	if (strcmp(argv[1], "users") == 0)       GetUsers(baseDN);
	else if (strcmp(argv[1], "groups") == 0) GetGroups(baseDN);
	else if (strcmp(argv[1], "all") == 0) {
		GetUsers(baseDN);
		GetGroups(baseDN);
	}
	else {
		std::wcout << L"[-] Unknown module" << std::endl;
	}

	CoUninitialize();
	return 0;
}