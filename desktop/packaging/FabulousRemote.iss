; Inno Setup script for the Fabulous Remote desktop client (preview).
; Built by desktop/packaging/build.py:  ISCC /DAppVersion=x.y.z /DRepoRoot=... FabulousRemote.iss
;
; Security posture: per-user install (no administrator rights), no Windows service, no
; auto-start, no firewall rules, standard uninstaller. The only thing written outside the
; install folder is the per-user server address (%APPDATA%\Fabulous Remote\config.json).

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#ifndef RepoRoot
  #define RepoRoot "..\.."
#endif

[Setup]
AppId={{6E2B7B6C-3C9A-4E7B-9C1D-5F0A2B8D4E11}
AppName=Fabulous Remote
AppVersion={#AppVersion}
AppVerName=Fabulous Remote {#AppVersion} (Preview)
AppPublisher=Fabulous Remote
VersionInfoVersion={#AppVersion}
DefaultDirName={localappdata}\Programs\Fabulous Remote
DefaultGroupName=Fabulous Remote
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
OutputDir={#RepoRoot}\dist\installer
OutputBaseFilename=FabulousRemote-Setup-{#AppVersion}-preview
SetupIconFile={#RepoRoot}\build\desktop\FabulousRemote.ico
UninstallDisplayIcon={app}\FabulousRemote.exe
UninstallDisplayName=Fabulous Remote (Preview)
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
CloseApplications=yes

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Shortcuts:"; Flags: unchecked

[Files]
Source: "{#RepoRoot}\dist\desktop\FabulousRemote\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\Fabulous Remote"; Filename: "{app}\FabulousRemote.exe"
Name: "{autodesktop}\Fabulous Remote"; Filename: "{app}\FabulousRemote.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\FabulousRemote.exe"; Description: "Start Fabulous Remote"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
; The only file written outside the install folder.
Type: files; Name: "{userappdata}\Fabulous Remote\config.json"
Type: dirifempty; Name: "{userappdata}\Fabulous Remote"

[Code]
var
  ServerPage: TInputQueryWizardPage;

procedure InitializeWizard;
begin
  ServerPage := CreateInputQueryPage(wpSelectDir, 'Server address',
    'Which Fabulous Remote server should this computer use?',
    'Use the https address from your administrator. http is accepted only for a server on this computer.');
  ServerPage.Add('Server address:', False);
  ServerPage.Values[0] := ExpandConstant('{param:SERVER|http://127.0.0.1:8765}');
end;

function IsAcceptableUrl(Url: String): Boolean;
var
  Lower: String;
begin
  Lower := Lowercase(Trim(Url));
  Result := (Pos('https://', Lower) = 1) or (Pos('http://127.0.0.1', Lower) = 1) or
            (Pos('http://localhost', Lower) = 1);
  Result := Result and (Pos('"', Lower) = 0) and (Pos('\', Lower) = 0) and (Pos(' ', Trim(Lower)) = 0);
end;

function InitializeSetup(): Boolean;
var
  Server: String;
begin
  // Unattended installs (/VERYSILENT /SERVER=...) must fail fast on a bad address instead of
  // stopping on a wizard page nobody can see.
  Result := True;
  Server := ExpandConstant('{param:SERVER|}');
  if (Server <> '') and not IsAcceptableUrl(Server) then
  begin
    SuppressibleMsgBox('The /SERVER address must use https:// (http:// only for this computer).',
      mbError, MB_OK, IDOK);
    Result := False;
  end;
end;

function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;
  if (CurPageID = ServerPage.ID) and not IsAcceptableUrl(ServerPage.Values[0]) then
  begin
    MsgBox('Enter an https:// address (http:// only for this computer, e.g. http://127.0.0.1:8765).',
      mbError, MB_OK);
    Result := False;
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  ConfigDir: String;
begin
  if CurStep = ssPostInstall then
  begin
    ConfigDir := ExpandConstant('{userappdata}\Fabulous Remote');
    ForceDirectories(ConfigDir);
    SaveStringToFile(ConfigDir + '\config.json',
      '{"api_url": "' + Trim(ServerPage.Values[0]) + '"}', False);
  end;
end;
