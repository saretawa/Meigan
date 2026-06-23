# Meigan

Active Directory enumeration tool. Single C++ binary over ADSI/LDAP and NetAPI — object enumeration, attack-surface discovery, ACL auditing, and host-level recon. No external dependencies.

> For authorized use only.

## Build

```
cl /EHsc /std:c++17 Meigan.cpp
```

Links `activeds.lib`, `adsiid.lib`, `advapi32.lib`, `netapi32.lib` (via pragmas in source). Windows only.

## Usage

```
Meigan.exe <module> [options]
```

**Core:** `users` `groups` `computers` `dclist` `trusts` `ous`
**Attack surface:** `spns` `asrep` `admins` `delegation` `constrained` `laps` `shares`
**Weak config:** `disabled` `noexpiry` `emptypass` `stale` `passnotchanged` `finegrained`
**Delegation:** `rbcd` `maq`
**ACLs:** `acls` (auto-detects attack-path chains)
**Group Policy:** `gpos` `gpomap`
**Host-based:** `sessions` `localadmins`
**All:** `all`

**Global options:** `--dc <host>` `--output <file>` `--verbose` `--filter <ldap>` `--tree` `--help`
**ACL options:** `--trustee <name>` `--target <name>` `--detail <name>` `--dangerous`

## Examples

```
Meigan.exe spns                         Kerberoastable accounts
Meigan.exe laps                         Readable LAPS passwords
Meigan.exe acls --dangerous             GenericAll/WriteDACL/WriteOwner/DCSync only
Meigan.exe acls --target administrator  Who can compromise admin
Meigan.exe acls --detail bob            Full ACL breakdown for bob
Meigan.exe all --output recon.txt       Full dump to file
Meigan.exe users --dc DC01.corp.com     Target specific DC
```

Run `Meigan.exe --help` for the full module/option list.
