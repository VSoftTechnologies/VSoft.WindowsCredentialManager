unit VSoft.Windows.CredApi;

//Winapi.WinCred has errors in it's _CREDENTIAL translation.

interface

uses
  WinApi.Windows;

type
  _SecHandle = record
    dwLower: ULONG_PTR;
    dwUpper: ULONG_PTR;
  end;
  SecHandle = _SecHandle;
  PSecHandle = ^SecHandle;
  PCtxtHandle = PSecHandle;

 PTSTR = LPWSTR;
 PWSTR = WinApi.Windows.LPWSTR;

// Don't require ntstatus.h
const
  STATUS_LOGON_FAILURE          = NTSTATUS($C000006D);
  STATUS_WRONG_PASSWORD         = NTSTATUS($C000006A);     // ntsubauth
  STATUS_PASSWORD_EXPIRED       = NTSTATUS($C0000071);     // ntsubauth
  STATUS_PASSWORD_MUST_CHANGE   = NTSTATUS($C0000224);    // ntsubauth
  STATUS_ACCESS_DENIED          = NTSTATUS($C0000022);
  STATUS_DOWNGRADE_DETECTED     = NTSTATUS($C0000388);
  STATUS_AUTHENTICATION_FIREWALL_FAILED = NTSTATUS($C0000413);
  STATUS_ACCOUNT_DISABLED       = NTSTATUS($C0000072);     // ntsubauth
  STATUS_ACCOUNT_RESTRICTION    = NTSTATUS($C000006E);     // ntsubauth
  STATUS_ACCOUNT_LOCKED_OUT     = NTSTATUS($C0000234);    // ntsubauth
  STATUS_ACCOUNT_EXPIRED        = NTSTATUS($C0000193);    // ntsubauth
  STATUS_LOGON_TYPE_NOT_GRANTED = NTSTATUS($C000015B);
  STATUS_NO_SUCH_LOGON_SESSION  = NTSTATUS($C000005F);
  STATUS_NO_SUCH_USER           = NTSTATUS($C0000064);     // ntsubauth

// Don't require lmerr.h

  NERR_BASE            = 2100;
  NERR_PasswordExpired = NERR_BASE + 142; // The password of this user has expired.


//macros
function CREDUIP_IS_USER_PASSWORD_ERROR(_Status: NTSTATUS): BOOL;

function CREDUIP_IS_DOWNGRADE_ERROR(_Status: NTSTATUS): BOOL;

function CREDUIP_IS_EXPIRED_ERROR(_Status: NTSTATUS): BOOL;

function CREDUI_IS_AUTHENTICATION_ERROR(_Status: NTSTATUS): BOOL;

function CREDUI_NO_PROMPT_AUTHENTICATION_ERROR(_Status: NTSTATUS): BOOL;

//-----------------------------------------------------------------------------
// Structures
//-----------------------------------------------------------------------------

//
// Credential Attribute
//

const
  // Maximum length of the various credential string fields (in characters)
  CRED_MAX_STRING_LENGTH = 256;
  // Maximum length of the UserName field.  The worst case is <User>@<DnsDomain>
  CRED_MAX_USERNAME_LENGTH = 256 + 1 + 256;
  // Maximum length of the TargetName field for CRED_TYPE_GENERIC (in characters)
  CRED_MAX_GENERIC_TARGET_NAME_LENGTH = 32767;
  // Maximum length of the TargetName field for CRED_TYPE_DOMAIN_* (in characters)
  //      Largest one is <DfsRoot>\<DfsShare>
  CRED_MAX_DOMAIN_TARGET_NAME_LENGTH = 256 + 1 + 80;
  // Maximum size of the Credential Attribute Value field (in bytes)
  CRED_MAX_VALUE_SIZE = 256;
  // Maximum number of attributes per credential
  CRED_MAX_ATTRIBUTES = 64;

type
  PCREDENTIAL_ATTRIBUTEW = ^CREDENTIAL_ATTRIBUTEW;
  _CREDENTIAL_ATTRIBUTEW = record
    Keyword: LPWSTR;
    Flags: DWORD;
    ValueSize: DWORD;
    Value: LPBYTE;
  end;

  CREDENTIAL_ATTRIBUTEW = _CREDENTIAL_ATTRIBUTEW;
  //delphi types
  TCredentialAttributeW = CREDENTIAL_ATTRIBUTEW;
  PCredentialAttributeW = PCREDENTIAL_ATTRIBUTEW;

//
// Special values of the TargetName field
//

const
  CRED_SESSION_WILDCARD_NAME_W    = '*Session';
  CRED_TARGETNAME_DOMAIN_NAMESPACE_W = 'Domain';
  CRED_UNIVERSAL_WILDCARD_W = '*';
  CRED_TARGETNAME_LEGACYGENERIC_NAMESPACE_W = 'LegacyGeneric';
  CRED_TARGETNAME_NAMESPACE_SEPERATOR_W =  ':';
  CRED_TARGETNAME_ATTRIBUTE_SEPERATOR_W = '=';
  CRED_TARGETNAME_DOMAIN_EXTENDED_USERNAME_SEPARATOR_W = '|';
  CRED_TARGETNAME_ATTRIBUTE_TARGET_W = 'target';
  CRED_TARGETNAME_ATTRIBUTE_NAME_W  = 'name';
  CRED_TARGETNAME_ATTRIBUTE_BATCH_W = 'batch';
  CRED_TARGETNAME_ATTRIBUTE_INTERACTIVE_W = 'interactive';
  CRED_TARGETNAME_ATTRIBUTE_SERVICE_W = 'service';
  CRED_TARGETNAME_ATTRIBUTE_NETWORK_W = 'network';
  CRED_TARGETNAME_ATTRIBUTE_NETWORKCLEARTEXT_W = 'networkcleartext';
  CRED_TARGETNAME_ATTRIBUTE_REMOTEINTERACTIVE_W = 'remoteinteractive';
  CRED_TARGETNAME_ATTRIBUTE_CACHEDINTERACTIVE_W = 'cachedinteractive';


  CRED_SESSION_WILDCARD_NAME = CRED_SESSION_WILDCARD_NAME_W;
  CRED_TARGETNAME_DOMAIN_NAMESPACE = CRED_TARGETNAME_DOMAIN_NAMESPACE_W;
  CRED_UNIVERSAL_WILDCARD = CRED_UNIVERSAL_WILDCARD_W;
  CRED_TARGETNAME_NAMESPACE_SEPERATOR = CRED_TARGETNAME_NAMESPACE_SEPERATOR_W;
  CRED_TARGETNAME_ATTRIBUTE_SEPERATOR = CRED_TARGETNAME_ATTRIBUTE_SEPERATOR_W;
  CRED_TARGETNAME_ATTRIBUTE_NAME = CRED_TARGETNAME_ATTRIBUTE_NAME_W;
  CRED_TARGETNAME_ATTRIBUTE_TARGET = CRED_TARGETNAME_ATTRIBUTE_TARGET_W;
  CRED_TARGETNAME_ATTRIBUTE_BATCH = CRED_TARGETNAME_ATTRIBUTE_BATCH_W;
  CRED_TARGETNAME_ATTRIBUTE_INTERACTIVE = CRED_TARGETNAME_ATTRIBUTE_INTERACTIVE_W;
  CRED_TARGETNAME_ATTRIBUTE_SERVICE = CRED_TARGETNAME_ATTRIBUTE_SERVICE_W;
  CRED_TARGETNAME_ATTRIBUTE_NETWORK = CRED_TARGETNAME_ATTRIBUTE_NETWORK_W;
  CRED_TARGETNAME_ATTRIBUTE_NETWORKCLEARTEXT = CRED_TARGETNAME_ATTRIBUTE_NETWORKCLEARTEXT_W;
  CRED_TARGETNAME_ATTRIBUTE_REMOTEINTERACTIVE = CRED_TARGETNAME_ATTRIBUTE_REMOTEINTERACTIVE_W;
  CRED_TARGETNAME_ATTRIBUTE_CACHEDINTERACTIVE = CRED_TARGETNAME_ATTRIBUTE_CACHEDINTERACTIVE_W;


//
// Add\Extract Logon type from flags
//
  CRED_LOGON_TYPES_MASK  = $F000;  // Mask to get logon types

//TODO : implement these as functions
//#define CredAppendLogonTypeToFlags(Flags, LogonType)      (Flags) |= ((LogonType) << 12)
//#define CredGetLogonTypeFromFlags(Flags)                  ((SECURITY_LOGON_TYPE)(((Flags) & CRED_LOGON_TYPES_MASK) >> 12))
//#define CredRemoveLogonTypeFromFlags(Flags)               (Flags) &= ~CRED_LOGON_TYPES_MASK


//
// Values of the Credential Flags field.
//
  CRED_FLAGS_PASSWORD_FOR_CERT  = $0001;
  CRED_FLAGS_PROMPT_NOW         = $0002;
  CRED_FLAGS_USERNAME_TARGET    = $0004;
  CRED_FLAGS_OWF_CRED_BLOB      = $0008;
  CRED_FLAGS_REQUIRE_CONFIRMATION = $0010;

//
//  Valid only for return and only with CredReadDomainCredentials().
//  Indicates credential was returned due to wildcard match
//  of targetname with credential.
//

  CRED_FLAGS_WILDCARD_MATCH = $0020;

//
// Valid only for return
// Indicates that the credential is VSM protected
//

  CRED_FLAGS_VSM_PROTECTED      = $0040;
  CRED_FLAGS_NGC_CERT           = $0080;


//
// Mask of all valid flags
//
  CRED_FLAGS_VALID_FLAGS        = $F0FF;

//
//  Bit mask for only those flags which can be passed to the credman
//  APIs.
//
  CRED_FLAGS_VALID_INPUT_FLAGS   = $F09F;

//
// Values of the Credential Type field.
//
  CRED_TYPE_GENERIC                 = 1;
  CRED_TYPE_DOMAIN_PASSWORD         = 2;
  CRED_TYPE_DOMAIN_CERTIFICATE      = 3;
  CRED_TYPE_DOMAIN_VISIBLE_PASSWORD = 4;
  CRED_TYPE_GENERIC_CERTIFICATE     = 5;
  CRED_TYPE_DOMAIN_EXTENDED         = 6;
  CRED_TYPE_MAXIMUM                 = 7;       // Maximum supported cred type
  CRED_TYPE_MAXIMUM_EX =  (CRED_TYPE_MAXIMUM+1000);  // Allow new applications to run on old OSes


//
// Maximum size of the CredBlob field (in bytes)
//
  CRED_MAX_CREDENTIAL_BLOB_SIZE   = (5*512);

//
// Values of the Credential Persist field
//
  CRED_PERSIST_NONE               = 0;
  CRED_PERSIST_SESSION            = 1;
  CRED_PERSIST_LOCAL_MACHINE      = 2;
  CRED_PERSIST_ENTERPRISE         = 3;

type
  PCREDENTIALW = ^CREDENTIALW;
  _CREDENTIALW = record
    Flags: DWORD;
    &Type: DWORD;
    TargetName: LPWSTR;
    Comment: LPWSTR;
    LastWritten: FILETIME;
    CredentialBlobSize: DWORD;
    CredentialBlob: LPBYTE;
    Persist: DWORD;
    AttributeCount: DWORD;
    Attributes: PCREDENTIAL_ATTRIBUTEW;
    TargetAlias: LPWSTR;
    UserName: LPWSTR;
  end;

  CREDENTIALW = _CREDENTIALW;
  TCredentialW = CREDENTIALW;

  CREDENTIAL = CREDENTIALW;
  PCREDENTIAL = PCREDENTIALW;
  TCredential = TCredentialW;

const
//
// Value of the Flags field in CREDENTIAL_TARGET_INFORMATION
//

  CRED_TI_SERVER_FORMAT_UNKNOWN   = $0001;  // Don't know if server name is DNS or netbios format
  CRED_TI_DOMAIN_FORMAT_UNKNOWN   = $0002;  // Don't know if domain name is DNS or netbios format
  CRED_TI_ONLY_PASSWORD_REQUIRED  = $0004;  // Server only requires a password and not a username
  CRED_TI_USERNAME_TARGET         = $0008;  // TargetName is username
  CRED_TI_CREATE_EXPLICIT_CRED    = $0010;  // When creating a cred, create one named TargetInfo->TargetName
  CRED_TI_WORKGROUP_MEMBER        = $0020;  // Indicates the machine is a member of a workgroup
  CRED_TI_DNSTREE_IS_DFS_SERVER   = $0040;  // used to tell credman that the DNSTreeName could be DFS server
  CRED_TI_VALID_FLAGS             = $F07F;


type
//
// credential target
//
  PCREDENTIAL_TARGET_INFORMATIONW = ^CREDENTIAL_TARGET_INFORMATIONW;
  _CREDENTIAL_TARGET_INFORMATIONW = record
    TargetName: LPWSTR;
    NetbiosServerName: LPWSTR;
    DnsServerName: LPWSTR;
    NetbiosDomainName: LPWSTR;
    DnsDomainName: LPWSTR;
    DnsTreeName: LPWSTR;
    PackageName: LPWSTR;
    Flags: ULONG;
    CredTypeCount: DWORD;
    CredTypes: LPDWORD;
  end;
  CREDENTIAL_TARGET_INFORMATIONW = _CREDENTIAL_TARGET_INFORMATIONW;
  CREDENTIAL_TARGET_INFORMATION = CREDENTIAL_TARGET_INFORMATIONW;
  PCREDENTIAL_TARGET_INFORMATION = PCREDENTIAL_TARGET_INFORMATIONW;

  TCredentialTargetInformation = CREDENTIAL_TARGET_INFORMATION;
  PCredentialTargetInformation = PCREDENTIAL_TARGET_INFORMATION;

const
//
// Certificate credential information
//
// The cbSize should be the size of the structure, sizeof(CERT_CREDENTIAL_INFO),
// rgbHashofCert is the hash of the cert which is to be used as the credential.
//
  CERT_HASH_LENGTH        = 20;  // SHA1 hashes are used for cert hashes

type
  PCERT_CREDENTIAL_INFO = ^CERT_CREDENTIAL_INFO;
  _CERT_CREDENTIAL_INFO = record
    cbSize: ULONG;
    rgbHashOfCert: array [0..CERT_HASH_LENGTH - 1] of UCHAR;
  end;
  CERT_CREDENTIAL_INFO = _CERT_CREDENTIAL_INFO;
  TCertCredentialInfo = CERT_CREDENTIAL_INFO;
  PCertCredentialInfo = PCERT_CREDENTIAL_INFO;

//
// Username Target credential information
//
// This credential can be pass to LsaLogonUser to ask it to find a credential with a
// TargetName of UserName.
//
  PUSERNAME_TARGET_CREDENTIAL_INFO = ^USERNAME_TARGET_CREDENTIAL_INFO;
  _USERNAME_TARGET_CREDENTIAL_INFO = record
    UserName: LPWSTR;
  end;
  USERNAME_TARGET_CREDENTIAL_INFO = _USERNAME_TARGET_CREDENTIAL_INFO;
  TUsernameTargetCredentialInfo = USERNAME_TARGET_CREDENTIAL_INFO;
  PUsernameTargetCredentialInfo = PUSERNAME_TARGET_CREDENTIAL_INFO;

//
// Marshaled credential blob information.
//

  PBINARY_BLOB_CREDENTIAL_INFO = ^_BINARY_BLOB_CREDENTIAL_INFO;
  _BINARY_BLOB_CREDENTIAL_INFO = record
    cbBlob : ULONG;
    pbBlob : LPBYTE;
  end;
  BINARY_BLOB_CREDENTIAL_INFO = _BINARY_BLOB_CREDENTIAL_INFO;
  TBinaryBlobCredentialInfo = BINARY_BLOB_CREDENTIAL_INFO;
  IBinaryBlobCredentialInfo = PBINARY_BLOB_CREDENTIAL_INFO;

//
// Credential type for credential marshaling routines
//

 PCRED_MARSHAL_TYPE = ^_CRED_MARSHAL_TYPE;
{$MINENUMSIZE 4} //DWORD
  _CRED_MARSHAL_TYPE = (
    CertCredential = 1,
    UsernameTargetCredential,
    BinaryBlobCredential,
    UsernameForPackedCredentials,  // internal only, reserved
    BinaryBlobForSystem
  );
{$MINENUMSIZE 1}

  CRED_MARSHAL_TYPE = _CRED_MARSHAL_TYPE;
  TCredMarshalType = CRED_MARSHAL_TYPE;
  PCredMarshalType = PCRED_MARSHAL_TYPE;

//
// Protection type for credential providers secret protection routines
//

  PCRED_PROTECTION_TYPE = ^_CRED_PROTECTION_TYPE;
  _CRED_PROTECTION_TYPE = (
    CredUnprotected,
    CredUserProtection,
    CredTrustedProtection,
    CredForSystemProtection
  );

 CRED_PROTECTION_TYPE = _CRED_PROTECTION_TYPE;
 TCredProtectionType = CRED_PROTECTION_TYPE;
 PCredProtectionType = PCRED_PROTECTION_TYPE;

const
//
// Values for authentication buffers packing
//
  CRED_PACK_PROTECTED_CREDENTIALS     = $1;
  CRED_PACK_WOW_BUFFER                = $2;
  CRED_PACK_GENERIC_CREDENTIALS       = $4;
  CRED_PACK_ID_PROVIDER_CREDENTIALS   = $8;

type
//
// Credential UI info
//
  PCREDUI_INFOW = ^CREDUI_INFOW;
  _CREDUI_INFOW = record
    cbSize: DWORD;
    hwndParent: HWND;
    pszMessageText: LPCWSTR;
    pszCaptionText: LPCWSTR;
    hbmBanner: HBITMAP;
  end;
  CREDUI_INFOW = _CREDUI_INFOW;
  TCredUIInfo = CREDUI_INFOW;
  PCREDUI_INFO = PCREDUI_INFOW;
  PCredUIInfo = PCREDUI_INFO;

//-----------------------------------------------------------------------------
// Values
//-----------------------------------------------------------------------------

// String length limits:
const
  CREDUI_MAX_MESSAGE_LENGTH        = 1024;
  CREDUI_MAX_CAPTION_LENGTH        = 128;
  CREDUI_MAX_GENERIC_TARGET_LENGTH = CRED_MAX_GENERIC_TARGET_NAME_LENGTH;
  CREDUI_MAX_DOMAIN_TARGET_LENGTH  = CRED_MAX_DOMAIN_TARGET_NAME_LENGTH;

//
//  Username can be in <domain>\<user> or <user>@<domain>
//  Length in characters, not including NULL termination.
//
const
  CREDUI_MAX_USERNAME_LENGTH       = CRED_MAX_USERNAME_LENGTH;
  CREDUI_MAX_PASSWORD_LENGTH       = 512 div 2;

//  Packed credential returned by SspiEncodeAuthIdentityAsStrings().
//  Length in characters, not including NULL termination.
//
const
  CREDUI_MAX_PACKED_CREDENTIALS_LENGTH  =    ((MAXWORD div 2) - 2);


// maximum length in bytes for binary credential blobs
const
  CREDUI_MAX_CREDENTIALS_BLOB_SIZE    =  (MAXWORD);

//
// Flags for CredUIPromptForCredentials and/or CredUICmdLinePromptForCredentials
//
const
  CREDUI_FLAGS_INCORRECT_PASSWORD     = $00001;     // indicates the username is valid, but password is not
  CREDUI_FLAGS_DO_NOT_PERSIST         = $00002;     // Do not show "Save" checkbox, and do not persist credentials
  CREDUI_FLAGS_REQUEST_ADMINISTRATOR  = $00004;     // Populate list box with admin accounts
  CREDUI_FLAGS_EXCLUDE_CERTIFICATES   = $00008;     // do not include certificates in the drop list
  CREDUI_FLAGS_REQUIRE_CERTIFICATE    = $00010;
  CREDUI_FLAGS_SHOW_SAVE_CHECK_BOX    = $00040;
  CREDUI_FLAGS_ALWAYS_SHOW_UI         = $00080;
  CREDUI_FLAGS_REQUIRE_SMARTCARD      = $00100;
  CREDUI_FLAGS_PASSWORD_ONLY_OK       = $00200;
  CREDUI_FLAGS_VALIDATE_USERNAME      = $00400;
  CREDUI_FLAGS_COMPLETE_USERNAME      = $00800;     //
  CREDUI_FLAGS_PERSIST                = $01000;     // Do not show "Save" checkbox, but persist credentials anyway
  CREDUI_FLAGS_SERVER_CREDENTIAL      = $04000;
  CREDUI_FLAGS_EXPECT_CONFIRMATION    = $20000;     // do not persist unless caller later confirms credential via CredUIConfirmCredential() api
  CREDUI_FLAGS_GENERIC_CREDENTIALS    = $40000;     // Credential is a generic credential
  CREDUI_FLAGS_USERNAME_TARGET_CREDENTIALS =  $80000; // Credential has a username as the target
  CREDUI_FLAGS_KEEP_USERNAME         =  $100000;    // don't allow the user to change the supplied username


//
// Mask of flags valid for CredUIPromptForCredentials
//
const
  CREDUI_FLAGS_PROMPT_VALID = CREDUI_FLAGS_INCORRECT_PASSWORD or
                              CREDUI_FLAGS_DO_NOT_PERSIST or
                              CREDUI_FLAGS_REQUEST_ADMINISTRATOR or
                              CREDUI_FLAGS_EXCLUDE_CERTIFICATES or
                              CREDUI_FLAGS_REQUIRE_CERTIFICATE or
                              CREDUI_FLAGS_SHOW_SAVE_CHECK_BOX or
                              CREDUI_FLAGS_ALWAYS_SHOW_UI or
                              CREDUI_FLAGS_REQUIRE_SMARTCARD or
                              CREDUI_FLAGS_PASSWORD_ONLY_OK or
                              CREDUI_FLAGS_VALIDATE_USERNAME or
                              CREDUI_FLAGS_COMPLETE_USERNAME or
                              CREDUI_FLAGS_PERSIST or
                              CREDUI_FLAGS_SERVER_CREDENTIAL or
                              CREDUI_FLAGS_EXPECT_CONFIRMATION or
                              CREDUI_FLAGS_GENERIC_CREDENTIALS or
                              CREDUI_FLAGS_USERNAME_TARGET_CREDENTIALS or
                              CREDUI_FLAGS_KEEP_USERNAME;

//
// Flags for CredUIPromptForWindowsCredentials and CPUS_CREDUI Usage Scenarios
//
const
  CREDUIWIN_GENERIC                       = $00000001;  // Plain text username/password is being requested
  CREDUIWIN_CHECKBOX                      = $00000002;  // Show the Save Credential checkbox
  CREDUIWIN_AUTHPACKAGE_ONLY              = $00000010;  // Only Cred Providers that support the input auth package should enumerate
  CREDUIWIN_IN_CRED_ONLY                  = $00000020;  // Only the incoming cred for the specific auth package should be enumerated
  CREDUIWIN_ENUMERATE_ADMINS              = $00000100;  // Cred Providers should enumerate administrators only
  CREDUIWIN_ENUMERATE_CURRENT_USER        = $00000200;  // Only the incoming cred for the specific auth package should be enumerated
  CREDUIWIN_SECURE_PROMPT                 = $00001000;  // The Credui prompt should be displayed on the secure desktop
  CREDUIWIN_PREPROMPTING                  = $00002000;  // CredUI is invoked by SspiPromptForCredentials and the client is prompting before a prior handshake
  CREDUIWIN_PACK_32_WOW                   = $10000000;  // Tell the credential provider it should be packing its Auth Blob 32 bit even though it is running 64 native
  CREDUIWIN_IGNORE_CLOUDAUTHORITY_NAME    = $00040000;  // Tell the credential provider it should not pack AAD authority name
  CREDUIWIN_DOWNLEVEL_HELLO_AS_SMART_CARD = $80000000;  // Force collected Hello credentials to be packed in a smart card auth buffer.


  CREDUIWIN_VALID_FLAGS  = CREDUIWIN_GENERIC or
        CREDUIWIN_CHECKBOX               or
        CREDUIWIN_AUTHPACKAGE_ONLY       or
        CREDUIWIN_IN_CRED_ONLY           or
        CREDUIWIN_ENUMERATE_ADMINS       or
        CREDUIWIN_ENUMERATE_CURRENT_USER or
        CREDUIWIN_SECURE_PROMPT          or
        CREDUIWIN_PREPROMPTING           or
        CREDUIWIN_PACK_32_WOW            or
        CREDUIWIN_IGNORE_CLOUDAUTHORITY_NAME    or
        CREDUIWIN_DOWNLEVEL_HELLO_AS_SMART_CARD;


//-----------------------------------------------------------------------------
// Functions
//-----------------------------------------------------------------------------


//
// Values of flags to CredWrite and CredWriteDomainCredentials
//
const
  CRED_PRESERVE_CREDENTIAL_BLOB = $1;

function CredWrite(Credential: PCredential; Flags: DWORD): BOOL; stdcall;

function CredRead(TargetName: LPCTSTR; Type_: DWORD; Flags: DWORD; var Credential: PCREDENTIAL): BOOL; stdcall;

function CredEnumerate(Filter: LPCTSTR; Flags: DWORD; var Count: DWORD; var Credential: PCREDENTIAL): BOOL; stdcall;

function CredWriteDomainCredentials(TargetInfo: PCREDENTIAL_TARGET_INFORMATION; Credential: PCREDENTIAL; Flags: DWORD): BOOL; stdcall;

//
// Values of flags to CredReadDomainCredentials
//
const
  CRED_CACHE_TARGET_INFORMATION = $1;

function CredReadDomainCredentials(TargetInfo: PCREDENTIAL_TARGET_INFORMATION; Flags: DWORD; var Count: DWORD; var Credential: PCREDENTIAL): BOOL; stdcall;

function CredDelete(TargetName: LPCTSTR; Type_: DWORD; Flags: DWORD): BOOL; stdcall;

function CredRename(OldTargetName: LPCTSTR; NewTargetName: LPCTSTR; Type_: DWORD; Flags: DWORD): BOOL; stdcall;

//
// Values of flags to CredGetTargetInfo
//

const
  CRED_ALLOW_NAME_RESOLUTION = $1;

function CredGetTargetInfo(TargetName: LPCTSTR; Flags: DWORD; var TargetInfo: PCREDENTIAL_TARGET_INFORMATION): BOOL; stdcall;

function CredMarshalCredential(CredType: CRED_MARSHAL_TYPE; Credential: PVOID; var MarshaledCredential: LPTSTR): BOOL; stdcall;

function CredUnmarshalCredential(MarshaledCredential: LPCTSTR; CredType: PCRED_MARSHAL_TYPE; var Credential: PVOID): BOOL; stdcall;

function CredIsMarshaledCredential(MarshaledCredential: LPCTSTR): BOOL; stdcall;

function CredGetSessionTypes(MaximumPersistCount: DWORD; MaximumPersist: LPDWORD): BOOL; stdcall;

procedure CredFree(Buffer: PVOID); stdcall;

function CredUIPromptForCredentials(pUiInfo: PCREDUI_INFO; pszTargetName: LPCTSTR; pContext: PCtxtHandle; dwAuthError: DWORD; pszUserName: PTSTR; ulUserNameBufferSize: ULONG; pszPassword: PTSTR; ulPasswordBufferSize: ULONG; var save: BOOL; dwFlags: DWORD): DWORD; stdcall;

function CredUIParseUserName(pszUserName: LPCTSTR; pszUser: PTSTR; ulUserBufferSize: ULONG; pszDomain: PTSTR; ulDomainBufferSize: ULONG): DWORD; stdcall;

function CredUICmdLinePromptForCredentials(pszTargetName: LPCTSTR; pContext: PCtxtHandle; dwAuthError: DWORD; UserName: PTSTR; ulUserBufferSize: ULONG; pszPassword: PTSTR; ulPasswordBufferSize: ULONG; pfSave: PBOOL; dwFlags: DWORD): DWORD; stdcall;


//
// Call this API with bConfirm set to TRUE to confirm that the credential (previously created
// via CredUIGetCredentials or CredUIPromptForCredentials worked, or with bConfirm set to FALSE
// to indicate it didn't

function CredUIConfirmCredentials(pszTargetName: LPCTSTR; bConfirm: BOOL): DWORD; stdcall;

function CredUIStoreSSOCredW(pszRealm, pszUsername, pszPassword: LPCWSTR; bPersist: BOOL): DWORD; stdcall;

function CredUIReadSSOCredW(pszRealm: LPCWSTR; out ppszUsername: PWSTR): DWORD; stdcall;


implementation


const
  credapi = 'advapi32.dll';
  credui = 'credui.dll';

function HRESULT_FROM_NT(x: NTSTATUS): HRESULT;
begin
  Result := HRESULT(x or FACILITY_NT_BIT);
end;

function HRESULT_FROM_WIN32(x: DWORD): HRESULT;
begin
  if HRESULT(x) <= 0 then
    Result := HRESULT(x)
  else
    Result := HRESULT((x and $0000FFFF) or (FACILITY_WIN32 shl 16) or $80000000);
end;


function CREDUIP_IS_USER_PASSWORD_ERROR(_Status: NTSTATUS): BOOL;
begin
  Result := (DWORD(_Status) = ERROR_LOGON_FAILURE) or
            (_Status = HRESULT_FROM_WIN32(ERROR_LOGON_FAILURE)) or
            (_Status = STATUS_LOGON_FAILURE) or
            (_Status = HRESULT_FROM_NT(STATUS_LOGON_FAILURE)) or
            (DWORD(_Status) = ERROR_ACCESS_DENIED) or
            (_Status = HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED)) or
            (_Status = STATUS_ACCESS_DENIED) or
            (_Status = HRESULT_FROM_NT(STATUS_ACCESS_DENIED)) or
            (DWORD(_Status) = ERROR_INVALID_PASSWORD) or
            (_Status = HRESULT_FROM_WIN32(ERROR_INVALID_PASSWORD)) or
            (_Status = STATUS_WRONG_PASSWORD) or
            (_Status = HRESULT_FROM_NT(STATUS_WRONG_PASSWORD)) or
            (_Status = SEC_E_NO_CREDENTIALS) or
            (_Status = SEC_E_LOGON_DENIED);
end;

function CREDUIP_IS_DOWNGRADE_ERROR(_Status: NTSTATUS): BOOL;
begin
  Result :=
    (DWORD(_Status) = ERROR_DOWNGRADE_DETECTED) or
    (_Status = HRESULT_FROM_WIN32(ERROR_DOWNGRADE_DETECTED)) or
    (_Status = STATUS_DOWNGRADE_DETECTED) or
    (_Status = HRESULT_FROM_NT(STATUS_DOWNGRADE_DETECTED))
end;

function CREDUIP_IS_EXPIRED_ERROR(_Status: NTSTATUS): BOOL;
begin
  Result :=
    (DWORD(_Status) = ERROR_PASSWORD_EXPIRED) or
    (_Status = HRESULT_FROM_WIN32( ERROR_PASSWORD_EXPIRED)) or
    (_Status = STATUS_PASSWORD_EXPIRED) or
    (_Status = HRESULT_FROM_NT( STATUS_PASSWORD_EXPIRED)) or
    (DWORD(_Status) = ERROR_PASSWORD_MUST_CHANGE) or
    (_Status = HRESULT_FROM_WIN32( ERROR_PASSWORD_MUST_CHANGE)) or
    (_Status = STATUS_PASSWORD_MUST_CHANGE) or
    (_Status = HRESULT_FROM_NT( STATUS_PASSWORD_MUST_CHANGE)) or
    (_Status = NERR_PasswordExpired) or
    (_Status = HRESULT_FROM_WIN32(NERR_PasswordExpired));
end;

function CREDUI_IS_AUTHENTICATION_ERROR(_Status: NTSTATUS): BOOL;
begin
  Result := CREDUIP_IS_USER_PASSWORD_ERROR(_Status) or CREDUIP_IS_DOWNGRADE_ERROR(_Status) or CREDUIP_IS_EXPIRED_ERROR(_Status);
end;

function CREDUI_NO_PROMPT_AUTHENTICATION_ERROR(_Status: NTSTATUS): BOOL;
begin
  Result :=
    (_Status = NTSTATUS(ERROR_AUTHENTICATION_FIREWALL_FAILED)) or
    (_Status = HRESULT_FROM_WIN32(ERROR_AUTHENTICATION_FIREWALL_FAILED)) or
    (_Status = STATUS_AUTHENTICATION_FIREWALL_FAILED) or
    (_Status = HRESULT_FROM_NT(STATUS_AUTHENTICATION_FIREWALL_FAILED)) or
    (DWORD(_Status) = ERROR_ACCOUNT_DISABLED) or
    (_Status = HRESULT_FROM_WIN32(ERROR_ACCOUNT_DISABLED)) or
    (_Status = STATUS_ACCOUNT_DISABLED) or
    (_Status = HRESULT_FROM_NT(STATUS_ACCOUNT_DISABLED)) or
    (DWORD(_Status) = ERROR_ACCOUNT_RESTRICTION) or
    (_Status = HRESULT_FROM_WIN32(ERROR_ACCOUNT_RESTRICTION)) or
    (_Status = STATUS_ACCOUNT_RESTRICTION) or
    (_Status = HRESULT_FROM_NT(STATUS_ACCOUNT_RESTRICTION)) or
    (DWORD(_Status) = ERROR_ACCOUNT_LOCKED_OUT) or
    (_Status = HRESULT_FROM_WIN32(ERROR_ACCOUNT_LOCKED_OUT)) or
    (_Status = STATUS_ACCOUNT_LOCKED_OUT) or
    (_Status = HRESULT_FROM_NT(STATUS_ACCOUNT_LOCKED_OUT)) or
    (DWORD(_Status) = ERROR_ACCOUNT_EXPIRED) or
    (_Status = HRESULT_FROM_WIN32(ERROR_ACCOUNT_EXPIRED)) or
    (_Status = STATUS_ACCOUNT_EXPIRED) or
    (_Status = HRESULT_FROM_NT(STATUS_ACCOUNT_EXPIRED)) or
    (DWORD(_Status) = ERROR_LOGON_TYPE_NOT_GRANTED) or
    (_Status = HRESULT_FROM_WIN32(ERROR_LOGON_TYPE_NOT_GRANTED)) or
    (_Status = STATUS_LOGON_TYPE_NOT_GRANTED) or
    (_Status = HRESULT_FROM_NT(STATUS_LOGON_TYPE_NOT_GRANTED));
end;

//TODO : Dynamically load?

function CredWrite; external credapi name 'CredWriteW';
function CredRead; external credapi name 'CredReadW';
function CredEnumerate; external credapi name 'CredEnumerate';
function CredWriteDomainCredentials; external credapi name 'CredWriteDomainCredentials';
function CredReadDomainCredentials; external credapi name 'CredReadDomainCredentials';
function CredDelete; external credapi name 'CredDeleteW';
function CredRename; external credapi name 'CredRenameW';
function CredGetTargetInfo; external credapi name 'CredGetTargetInfoW';
function CredMarshalCredential; external credapi name 'CredMarshalCredential';
function CredUnmarshalCredential; external credapi name 'CredUnmarshalCredential';
function CredIsMarshaledCredential; external credapi name 'CredIsMarshaledCredential';
function CredGetSessionTypes; external credapi name 'CredGetSessionTypes';
procedure CredFree; external credapi name 'CredFree';
function CredUIPromptForCredentials; external credui name 'CredUIPromptForCredentials';
function CredUIParseUserName; external credui name 'CredUIParseUserName';
function CredUICmdLinePromptForCredentials; external credui name 'CredUICmdLinePromptForCredentials';
function CredUIConfirmCredentials; external credui name 'CredUIConfirmCredentials';
function CredUIStoreSSOCredW; external credui name 'CredUIStoreSSOCredW';
function CredUIReadSSOCredW; external credui name 'CredUIReadSSOCredW';
end.
