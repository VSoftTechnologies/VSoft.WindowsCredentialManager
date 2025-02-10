unit VSoft.Windows.CredentialManager;

//inspired by https://github.com/meziantou/Meziantou.Framework

interface



type
  TCredentialType = (
    Generic = 1,
    DomainPassword = 2//,
//    DomainCertificate,
//    DomainVisiblePassword,
//    GenericCertificate,
//    DomainExtended,
//    Maximum,
//    MaximumEx = Maximum + 1000
    );

//  TCredentialSaveOption = (
//    /// <summary>The "Save credentials?" dialog box is not selected, indicating that the user doesn't want their credentials saved.</summary>
//    Unselected,
//
//    /// <summary>The "Save credentials?" dialog box is selected, indicating that the user wants their credentials saved.</summary>
//    Selected,
//
//    /// <summary>The "Save credentials?" dialog box is not displayed at all.</summary>
//    Hidden
//    );


  TCredentialPersistence = (
    Session = 1,
    LocalMachine,
    Enterprise
  );



  ICredential = interface
  ['{96DBCAAF-D0BF-4E6B-9392-D498624BC895}']
    function GetApplicationName : string;
    function GetUserName : string;
    function GetSecret : string;
    function GetComment : string;
    function GetCredentialType : TCredentialType;

    function ToString : string;

    property ApplicationName : string read GetApplicationName;
    property Comment : string read GetComment;
    property UserName : string read GetUserName;
    property Secret : string read GetSecret;

    property CredentialType : TCredentialType read GetCredentialType;
  end;


  TCredentialManager = class
  public
    class function ReadCredential(const applicationName : string; credentialType : TCredentialType = TCredentialType.Generic ) : ICredential;overload;static;
    class procedure WriteCredential(const applicationName: string; const userName : string; const secret : string; persistence : TCredentialPersistence);overload;static;
    class procedure WriteCredential(const applicationName: string; const userName : string; const secret : string; persistence : TCredentialPersistence; credentialType : TCredentialType);overload;static;
    class procedure WriteCredential(const applicationName: string; const userName : string; const secret : string;  const comment : string; persistence : TCredentialPersistence);overload;static;
    class procedure WriteCredential(const applicationName: string; const userName : string; const secret : string;  const comment : string; persistence : TCredentialPersistence; credentialType : TCredentialType);overload;static;
    class procedure DeleteCredential(const applicationName : string);overload;static;
    class procedure DeleteCredential(const applicationName : string; type_ : TCredentialType );overload;static;

  end;


implementation

uses
//  {$IF CompilerVersion > 32.0}
//  WinApi.WinCred,
//  {$ELSE}
  VSoft.Windows.CredApi,
//  {$ENDIF}
  WinApi.Windows,
  System.SysUtils;


type
  TCredentialWrapper = class(TInterfacedObject,ICredential)
  private
    FApplicationName : string;
    FUserName : string;
    FSecret : string;
    FComment : string;
    FCredentialType : TCredentialType;

  protected
    function GetApplicationName : string;
    function GetUserName : string;
    function GetSecret : string;
    function GetComment : string;
    function GetCredentialType : TCredentialType;
  public
    constructor Create(cred : PCREDENTIAL);
    function ToString : string;override;
  end;



{ TCredentialManager }

class procedure TCredentialManager.DeleteCredential(const applicationName: string; type_: TCredentialType);
begin
 if applicationName = '' then
    raise EArgumentNilException.Create('applicationName is required');

 if not CredDelete(PChar(applicationName), DWORD(type_),0) then
    RaiseLastOSError;
end;

class procedure TCredentialManager.DeleteCredential(const applicationName: string);
begin
  DeleteCredential(applicationName, TCredentialType.Generic);
end;

class function TCredentialManager.ReadCredential(const applicationName: string; credentialType: TCredentialType): ICredential;
var
  cred : PCREDENTIAL;
begin
  result := nil;
  if CredRead(PChar(applicationName), DWORD(credentialType), 0, cred)  then
  begin
      try
        result := TCredentialWrapper.Create(cred);
      finally
          CredFree(cred);
      end;
  end;
end;

class procedure TCredentialManager.WriteCredential(const applicationName, userName, secret: string; persistence: TCredentialPersistence);
begin
  WriteCredential(applicationName, userName, secret, persistence, TCredentialType.Generic);
end;

class procedure TCredentialManager.WriteCredential(const applicationName, userName, secret: string; persistence: TCredentialPersistence; credentialType: TCredentialType);
begin
  WriteCredential(applicationName, userName, secret, '', persistence, credentialType);
end;

class procedure TCredentialManager.WriteCredential(const applicationName, userName, secret, comment: string; persistence: TCredentialPersistence);
begin
  WriteCredential(applicationName, userName, secret, comment, persistence, TCredentialType.Generic);
end;

class procedure TCredentialManager.WriteCredential(const applicationName, userName, secret, comment: string; persistence: TCredentialPersistence; credentialType: TCredentialType);
var
  newCred : CREDENTIAL;
begin
  if applicationName = '' then
    raise EArgumentNilException.Create('applicationName is required');
  if userName = '' then
    raise EArgumentNilException.Create('userName is required');
  if secret = '' then
    raise EArgumentNilException.Create('secret is required');

  if (Length(secret) > 2560) then
    raise EArgumentOutOfRangeException.Create('The secret message has exceeded 2560 bytes.');

  if (comment <> '') then
  begin
    // CRED_MAX_STRING_LENGTH 256
    if Length(comment) > 255 then
      raise EArgumentOutOfRangeException.Create('The comment message has exceeded 256 characters.');
  end;
  ZeroMemory(@newCred, SizeOf(CREDENTIAL));
  newCred.AttributeCount := 0;
  newCred.Attributes := nil;
  newCred.Comment := PChar(comment);
  newCred.&Type := DWORD(Ord(credentialType));
  newCred.TargetAlias := nil;
  newCred.TargetName := PChar(applicationName);
  newCred.CredentialBlob := Pointer(PChar(secret));
  newCred.CredentialBlobSize := Length(secret) * SizeOf(Char);
  newCred.Persist := DWORD(Ord(persistence));
  newCred.UserName := PChar(userName);


  if not CredWrite(@newCred,0) then
    RaiseLastOSError;

end;

{ TCredentialWrapper }

constructor TCredentialWrapper.Create(cred: PCREDENTIAL);
begin
  FCredentialType := TCredentialType(cred.&Type);
  SetString(FApplicationName,cred.TargetName, Length(cred.TargetName));
  SetString(FUserName,cred.UserName, Length(cred.UserName));
  SetString(FComment,cred.Comment, Length(cred.Comment));
  SetString(FSecret, PChar(cred.CredentialBlob), cred.CredentialBlobSize div 2);
end;

function TCredentialWrapper.GetApplicationName: string;
begin
  result := FApplicationName;
end;

function TCredentialWrapper.GetComment: string;
begin
  result := FComment;
end;

function TCredentialWrapper.GetCredentialType: TCredentialType;
begin
  result := FCredentialType;
end;

function TCredentialWrapper.GetSecret: string;
begin
  result := FSecret;
end;

function TCredentialWrapper.GetUserName: string;
begin
  result := FUserName;
end;

function TCredentialWrapper.ToString: string;
begin
   result := 'CredentialType: ' + IntToStr(Ord(FCredentialType)) + ', ApplicationName: ' + FApplicationName + ', UserName: ' + FUserName + ', Secret: ' + FSecret + ', Comment: ' + FComment;
end;

end.
