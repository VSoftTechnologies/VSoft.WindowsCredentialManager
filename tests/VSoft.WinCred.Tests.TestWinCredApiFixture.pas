unit VSoft.WinCred.Tests.TestWinCredApiFixture;

interface

uses
  DUnitX.TestFramework;

type
  [TestFixture]
  TTestWinCredApi = class
  public
    [Test]
    procedure TestWriteCredentialSession;

  end;

implementation

uses
  VSoft.Windows.CredentialManager;

procedure TTestWinCredApi.TestWriteCredentialSession;
var
  cred : ICredential;
begin
  TCredentialManager.WriteCredential('dunitx','vincent', 'foobar','this is a comment',TCredentialPersistence.Session,TCredentialType.Generic);
  cred := TCredentialManager.ReadCredential('dunitx',TCredentialType.Generic);
  Log(cred.ToString);
  TCredentialManager.DeleteCredential('dunitx');
end;


initialization
  TDUnitX.RegisterTestFixture(TTestWinCredApi);

end.
