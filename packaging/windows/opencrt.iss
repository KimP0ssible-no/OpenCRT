; Inno Setup 6 script for the Windows installer.
; Build: cargo build --release, then
;   iscc packaging\windows\opencrt.iss
; The installer is written to packaging\windows\Output\.

#define AppVersion "0.3.1"
; Where the executables are (iscc /DBinDir=... for a cross-compiled build).
#ifndef BinDir
  #define BinDir "..\..\target\release"
#endif

[Setup]
AppId={{6F1D4C2E-8E0B-4E6B-9C5A-0C4C3D7A1E21}
AppName=OpenCRT
AppVersion={#AppVersion}
AppPublisher=OpenCRT
DefaultDirName={autopf}\OpenCRT
DefaultGroupName=OpenCRT
DisableProgramGroupPage=yes
OutputBaseFilename=opencrt-{#AppVersion}-x64-setup
SetupIconFile=..\icons\opencrt.ico
UninstallDisplayIcon={app}\opencrt.exe
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequiredOverridesAllowed=dialog
Compression=lzma2
SolidCompression=yes
WizardStyle=modern

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; Flags: unchecked
Name: "urls"; Description: "Open ssh://, telnet:// and rlogin:// links with OpenCRT"

[Registry]
Root: HKA; Subkey: "Software\Classes\ssh"; ValueType: string; ValueData: "URL:SSH"; Flags: uninsdeletekey; Tasks: urls
Root: HKA; Subkey: "Software\Classes\ssh"; ValueType: string; ValueName: "URL Protocol"; ValueData: ""; Tasks: urls
Root: HKA; Subkey: "Software\Classes\ssh\DefaultIcon"; ValueType: string; ValueData: "{app}\opencrt.exe,0"; Tasks: urls
Root: HKA; Subkey: "Software\Classes\ssh\shell\open\command"; ValueType: string; ValueData: """{app}\opencrt.exe"" /T ""%1"""; Tasks: urls
Root: HKA; Subkey: "Software\Classes\telnet"; ValueType: string; ValueData: "URL:Telnet"; Flags: uninsdeletekey; Tasks: urls
Root: HKA; Subkey: "Software\Classes\telnet"; ValueType: string; ValueName: "URL Protocol"; ValueData: ""; Tasks: urls
Root: HKA; Subkey: "Software\Classes\telnet\DefaultIcon"; ValueType: string; ValueData: "{app}\opencrt.exe,0"; Tasks: urls
Root: HKA; Subkey: "Software\Classes\telnet\shell\open\command"; ValueType: string; ValueData: """{app}\opencrt.exe"" /T ""%1"""; Tasks: urls
Root: HKA; Subkey: "Software\Classes\rlogin"; ValueType: string; ValueData: "URL:RLogin"; Flags: uninsdeletekey; Tasks: urls
Root: HKA; Subkey: "Software\Classes\rlogin"; ValueType: string; ValueName: "URL Protocol"; ValueData: ""; Tasks: urls
Root: HKA; Subkey: "Software\Classes\rlogin\DefaultIcon"; ValueType: string; ValueData: "{app}\opencrt.exe,0"; Tasks: urls
Root: HKA; Subkey: "Software\Classes\rlogin\shell\open\command"; ValueType: string; ValueData: """{app}\opencrt.exe"" /T ""%1"""; Tasks: urls

[Files]
Source: "{#BinDir}\opencrt.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#BinDir}\opencrt-rdp.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#BinDir}\ocrt.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\LICENSE"; DestDir: "{app}"; DestName: "LICENSE.txt"; Flags: ignoreversion
Source: "..\..\NOTICE"; DestDir: "{app}"; DestName: "NOTICE.txt"; Flags: ignoreversion
Source: "..\..\SLINT-LICENSE.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\crates\opencrt\ui\fonts\OFL.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\target\THIRD-PARTY-NOTICES.html"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\target\THIRD-PARTY-NOTICES-RDP.html"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\OpenCRT"; Filename: "{app}\opencrt.exe"
Name: "{autodesktop}\OpenCRT"; Filename: "{app}\opencrt.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\opencrt.exe"; Description: "Launch OpenCRT"; Flags: nowait postinstall skipifsilent
; The in-app update runs setup silently with /RELAUNCH=1 and has quit by then:
; start OpenCRT again, as the user rather than the administrator. Other silent
; installs (winget, scripts) leave it closed.
Filename: "{app}\opencrt.exe"; Flags: nowait skipifnotsilent runasoriginaluser; Check: Relaunch

[Code]
function Relaunch: Boolean;
begin
  Result := ExpandConstant('{param:RELAUNCH|0}') = '1';
end;
