#include <windows.h>
#include <activeds.h>
#include <adshlp.h>
#include <iostream>
#include <fstream>
#include <sddl.h>
#include <map>
#include <functional>
#include <string>

#pragma comment(lib, "activeds.lib")
#pragma comment(lib, "adsiid.lib")
#pragma comment(lib, "advapi32.lib")

std::wostream* gOut = &std::wcout;
std::wofstream gFileOut;
bool gVerbose = false;

std::string ToLower(std::string str) {
	for (auto& c : str) c = tolower(c);
	return str;
}

void Log(const std::wstring& msg, const std::wstring& level = L"*") {
	// suppress [*] noise unless verbose
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
	// always prints regardless of verbose
	std::wcout << L"[" << level << L"] " << msg << std::endl;
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
		st.wYear, st.wMonth, st.wDay,
		st.wHour, st.wMinute, st.wSecond);

	return std::wstring(buf);
}

// Returns a FILETIME-compatible LONGLONG for N days ago
LONGLONG DaysAgoFileTime(int days) {
	SYSTEMTIME st;
	GetSystemTime(&st);
	FILETIME ft;
	SystemTimeToFileTime(&st, &ft);
	ULARGE_INTEGER uli;
	uli.LowPart = ft.dwLowDateTime;
	uli.HighPart = ft.dwHighDateTime;
	// subtract days in 100-nanosecond intervals
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

std::wstring GetDomainInfo(bool printbasic, std::wstring dc = L"") {
	std::wstring rootDSEPath = dc.empty() ? L"LDAP://rootDSE" : L"LDAP://" + dc + L"/rootDSE";
	Log(L"Binding to " + rootDSEPath + L"...");

	IADs* pADs = nullptr;
	HRESULT hr = ADsGetObject(rootDSEPath.c_str(), IID_IADs, (void**)&pADs);
	if (FAILED(hr)) {
		LogHR(L"Failed to bind to rootDSE", hr);
		return L"";
	}

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
	if (FAILED(hr)) {
		LogHR(L"Failed to bind", hr);
		return nullptr;
	}

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
				*gOut << attrs[i] << L": "
				<< col.pADsValues[j].CaseIgnoreString << std::endl;
			break;

		case ADSTYPE_INTEGER:
			if (wcscmp(attrs[i], L"userAccountControl") == 0)
				*gOut << L"userAccountControl: " << col.pADsValues->Integer
				<< L" (" << DecodeUAC(col.pADsValues->Integer) << L")" << std::endl;
			else if (wcscmp(attrs[i], L"groupType") == 0)
				*gOut << L"groupType: "
				<< DecodeGroupType((LONG)col.pADsValues->Integer) << std::endl;
			else if (wcscmp(attrs[i], L"trustType") == 0)
				*gOut << L"trustType: "
				<< DecodeTrustType(col.pADsValues->Integer) << std::endl;
			else if (wcscmp(attrs[i], L"trustDirection") == 0)
				*gOut << L"trustDirection: "
				<< DecodeTrustDirection(col.pADsValues->Integer) << std::endl;
			else if (wcscmp(attrs[i], L"trustAttributes") == 0)
				*gOut << L"trustAttributes: "
				<< DecodeTrustAttributes(col.pADsValues->Integer) << std::endl;
			else
				*gOut << attrs[i] << L": "
				<< col.pADsValues->Integer << std::endl;
			break;

		case ADSTYPE_LARGE_INTEGER:
			*gOut << attrs[i] << L": "
				<< FileTimeToReadable(col.pADsValues->LargeInteger.QuadPart)
				<< std::endl;
			break;

		case ADSTYPE_BOOLEAN:
			*gOut << attrs[i] << L": "
				<< (col.pADsValues->Boolean ? L"TRUE" : L"FALSE") << std::endl;
			break;

		case ADSTYPE_OCTET_STRING:
			if (wcscmp(attrs[i], L"objectSid") == 0)
				*gOut << attrs[i] << L": "
				<< DecodeSid(
					col.pADsValues->OctetString.lpValue,
					col.pADsValues->OctetString.dwLength) << std::endl;
			else if (wcscmp(attrs[i], L"objectGUID") == 0)
				*gOut << attrs[i] << L": "
				<< DecodeGUID(col.pADsValues->OctetString.lpValue) << std::endl;
			else
				*gOut << attrs[i] << L": [binary - "
				<< col.pADsValues->OctetString.dwLength << L" bytes]" << std::endl;
			break;

		case ADSTYPE_UTC_TIME:
			*gOut << attrs[i] << L": "
				<< col.pADsValues->UTCTime.wYear << L"-"
				<< col.pADsValues->UTCTime.wMonth << L"-"
				<< col.pADsValues->UTCTime.wDay << std::endl;
			break;

		default:
			*gOut << attrs[i] << L": [unhandled type "
				<< col.dwADsType << L"]" << std::endl;
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
	secPref.vValue.Integer = ADS_SECURITY_INFO_OWNER |
		ADS_SECURITY_INFO_GROUP |
		ADS_SECURITY_INFO_DACL;
	pSearch->SetSearchPreference(&secPref, 1);

	ADS_SEARCH_HANDLE hSearch;
	HRESULT hr = pSearch->ExecuteSearch(filter, attrs, attrCount, &hSearch);
	if (FAILED(hr)) {
		LogHR(L"ExecuteSearch failed", hr);
		pSearch->Release();
		return;
	}
	LogHR(L"ExecuteSearch", hr);

	int count = 0;
	HRESULT rowHr;

	while ((rowHr = pSearch->GetNextRow(hSearch)) != S_ADS_NOMORE_ROWS) {
		if (FAILED(rowHr)) {
			LogHR(L"GetNextRow failed", rowHr);
			break;
		}
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
	LPWSTR gpoAttrs[] = {
		(LPWSTR)L"displayName",
		(LPWSTR)L"distinguishedName"
	};

	ADS_SEARCH_HANDLE hSearch;
	HRESULT hr = pSearch->ExecuteSearch(
		(LPWSTR)L"(objectClass=groupPolicyContainer)",
		gpoAttrs, 2, &hSearch);

	if (SUCCEEDED(hr)) {
		HRESULT rowHr;
		while ((rowHr = pSearch->GetNextRow(hSearch)) != S_ADS_NOMORE_ROWS) {
			if (FAILED(rowHr)) break;
			std::wstring dn, name;
			ADS_SEARCH_COLUMN col;

			if (SUCCEEDED(pSearch->GetColumn(hSearch, (LPWSTR)L"distinguishedName", &col))) {
				dn = col.pADsValues->CaseIgnoreString;
				pSearch->FreeColumn(&col);
			}
			if (SUCCEEDED(pSearch->GetColumn(hSearch, (LPWSTR)L"displayName", &col))) {
				name = col.pADsValues->CaseIgnoreString;
				pSearch->FreeColumn(&col);
			}

			size_t start = dn.find(L"{");
			size_t end = dn.find(L"}");
			if (start != std::wstring::npos && end != std::wstring::npos)
				gpoNames[dn.substr(start, end - start + 1)] = name;
		}
		pSearch->CloseSearchHandle(hSearch);
	}

	LogResult(L"GPO map built - " + std::to_wstring(gpoNames.size()) + L" GPOs found", L"+");

	LPWSTR ouAttrs[] = {
		(LPWSTR)L"name",
		(LPWSTR)L"distinguishedName",
		(LPWSTR)L"gpLink"
	};

	LPWSTR filters[] = {
		(LPWSTR)L"(&(objectClass=organizationalUnit)(gpLink=*))",
		(LPWSTR)L"(&(objectClass=domainDNS)(gpLink=*))"
	};

	*gOut << L"\n[GPO MAPPING]" << std::endl;
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
				ouName = col.pADsValues->CaseIgnoreString;
				pSearch->FreeColumn(&col);
			}
			if (SUCCEEDED(pSearch->GetColumn(hSearch, (LPWSTR)L"distinguishedName", &col))) {
				ouDN = col.pADsValues->CaseIgnoreString;
				pSearch->FreeColumn(&col);
			}
			if (SUCCEEDED(pSearch->GetColumn(hSearch, (LPWSTR)L"gpLink", &col))) {
				gpLink = col.pADsValues->CaseIgnoreString;
				pSearch->FreeColumn(&col);
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
				if (it != gpoNames.end())
					gpoName = it->second;

				std::wstring enforcement = L"Not Enforced";
				size_t semicolon = gpLink.find(L";", end);
				size_t bracket = gpLink.find(L"]", end);
				if (semicolon != std::wstring::npos && semicolon < bracket) {
					std::wstring flag = gpLink.substr(semicolon + 1, bracket - semicolon - 1);
					if (flag == L"2") enforcement = L"ENFORCED";
					else if (flag == L"1") enforcement = L"DISABLED";
					else enforcement = L"Not Enforced";
				}

				*gOut << L"  -> GPO: " << gpoName
					<< L" " << guid
					<< L" [" << enforcement << L"]" << std::endl;

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

void PrintUsage() {
	std::wcout << L"\nUsage: ADRecon.exe [options] <module>" << std::endl;
	std::wcout << L"\nModules:" << std::endl;
	std::wcout << L"  users        - enumerate domain users" << std::endl;
	std::wcout << L"  groups       - enumerate domain groups" << std::endl;
	std::wcout << L"  computers    - enumerate domain computers" << std::endl;
	std::wcout << L"  spns         - enumerate kerberoastable accounts" << std::endl;
	std::wcout << L"  asrep        - enumerate asreproastable accounts" << std::endl;
	std::wcout << L"  admins       - enumerate privileged accounts" << std::endl;
	std::wcout << L"  delegation   - enumerate accounts with unconstrained delegation" << std::endl;
	std::wcout << L"  constrained  - enumerate accounts with constrained delegation" << std::endl;
	std::wcout << L"  trusts       - enumerate domain trusts" << std::endl;
	std::wcout << L"  ous          - enumerate organizational units" << std::endl;
	std::wcout << L"  gpos         - enumerate group policy objects" << std::endl;
	std::wcout << L"  gpomap       - show GPO to OU mappings" << std::endl;
	std::wcout << L"  disabled     - enumerate disabled accounts" << std::endl;
	std::wcout << L"  noexpiry     - enumerate accounts with non-expiring passwords" << std::endl;
	std::wcout << L"  emptypass    - enumerate accounts that don't require a password" << std::endl;
	std::wcout << L"  stale        - enumerate users inactive for 90+ days" << std::endl;
	std::wcout << L"  dclist       - enumerate domain controllers" << std::endl;
	std::wcout << L"  laps         - enumerate computers with readable LAPS passwords" << std::endl;
	std::wcout << L"  all          - run everything" << std::endl;
	std::wcout << L"\nOptions:" << std::endl;
	std::wcout << L"  --dc <hostname>      - specify domain controller" << std::endl;
	std::wcout << L"  --filter <filter>    - custom LDAP filter" << std::endl;
	std::wcout << L"  --output <file>      - write output to file" << std::endl;
	std::wcout << L"  --verbose            - show all debug/bind output" << std::endl;
	std::wcout << L"  --help, -h           - show this menu" << std::endl;
	std::wcout << L"\nExamples:" << std::endl;
	std::wcout << L"  ADRecon.exe users" << std::endl;
	std::wcout << L"  ADRecon.exe spns --output results.txt" << std::endl;
	std::wcout << L"  ADRecon.exe laps --dc DC01.corp.com" << std::endl;
	std::wcout << L"  ADRecon.exe stale --verbose" << std::endl;
	std::wcout << L"  ADRecon.exe --filter \"(objectClass=computer)\"" << std::endl;
}

void RunModule(std::string cmd, std::wstring baseDN, std::wstring customFilter, std::wstring dc) {
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

	// shared attr sets for new quick-win modules
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

	// build stale filter dynamically (90 days ago)
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
		// quick wins
		{"disabled",    [&]() { ADSearch(baseDN, (LPWSTR)L"(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=2))", quickUserAttrs, 8, (LPWSTR)L"DISABLED", dc); }},
		{"noexpiry",    [&]() { ADSearch(baseDN, (LPWSTR)L"(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=65536))", quickUserAttrs, 8, (LPWSTR)L"NOEXPIRY", dc); }},
		{"emptypass",   [&]() { ADSearch(baseDN, (LPWSTR)L"(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=32))", quickUserAttrs, 8, (LPWSTR)L"EMPTY_PASSWORD", dc); }},
		{"stale",       [&]() { ADSearch(baseDN, staleFilter, quickUserAttrs, 8, (LPWSTR)L"STALE_90DAYS", dc); }},
		{"dclist",      [&]() { ADSearch(baseDN, (LPWSTR)L"(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))", dcAttrs, 9, (LPWSTR)L"DOMAIN_CONTROLLER", dc); }},
		{"laps",        [&]() { ADSearch(baseDN, (LPWSTR)L"(&(objectClass=computer)(ms-Mcs-AdmPwd=*))", lapsAttrs, 7, (LPWSTR)L"LAPS_READABLE", dc); }},
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
		}}
	};

	auto it = modules.find(cmd);
	if (it != modules.end())
		it->second();
	else
		LogResult(L"Unknown module: " + std::wstring(cmd.begin(), cmd.end()), L"-");
}

int main(int argc, char* argv[]) {
	HRESULT coHr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
	if (FAILED(coHr) && coHr != RPC_E_CHANGED_MODE) {
		wchar_t buf[64];
		swprintf(buf, 64, L"CoInitializeEx failed: 0x%08X", coHr);
		std::wcout << buf << std::endl;
		return 1;
	}

	std::wcout << L"[+] ADRecon started" << std::endl;

	if (argc < 2) {
		PrintUsage();
		CoUninitialize();
		return 0;
	}

	std::string cmd = "";
	std::wstring dc = L"";
	std::string outputFile = "";
	std::wstring customFilter = L"";

	for (int i = 1; i < argc; i++) {
		std::string arg = ToLower(argv[i]);

		if (arg == "--help" || arg == "-h") {
			PrintUsage();
			CoUninitialize();
			return 0;
		}
		else if (arg == "--verbose")
			gVerbose = true;
		else if (arg == "--dc" && i + 1 < argc) {
			std::string d = argv[++i];
			dc = std::wstring(d.begin(), d.end());
		}
		else if (arg == "--output" && i + 1 < argc)
			outputFile = argv[++i];
		else if (arg == "--filter" && i + 1 < argc) {
			std::string f = argv[++i];
			customFilter = std::wstring(f.begin(), f.end());
		}
		else
			cmd = arg;
	}

	if (!outputFile.empty()) {
		gFileOut.open(outputFile);
		if (!gFileOut.is_open()) {
			LogResult(L"Failed to open output file", L"-");
			CoUninitialize();
			return 1;
		}
		gOut = &gFileOut;
		std::wcout << L"[+] Output writing to: " << outputFile.c_str() << std::endl;
	}

	if (cmd.empty() && customFilter.empty()) {
		PrintUsage();
		CoUninitialize();
		return 0;
	}

	if (!dc.empty())
		std::wcout << L"[+] Using DC: " << dc << std::endl;

	std::wstring baseDN = GetDomainInfo(true, dc);
	if (baseDN.empty()) {
		LogResult(L"Failed to resolve base DN - cannot continue", L"-");
		CoUninitialize();
		return 1;
	}

	RunModule(cmd, baseDN, customFilter, dc);

	if (gFileOut.is_open()) {
		gFileOut.close();
		std::wcout << L"[+] Output saved" << std::endl;
	}

	CoUninitialize();
	return 0;
}