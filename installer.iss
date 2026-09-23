#define AppVersion "0.1.2"

[Setup]
AppId={{A68C05AD-1DBD-4595-A92A-5B02787874C0}
AppName=betterNJUVPN
AppVersion={#AppVersion}
AppVerName=betterNJUVPN {#AppVersion}
DefaultDirName={localappdata}\Programs\betterNJUVPN
DefaultGroupName=betterNJUVPN
DisableDirPage=no
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
OutputDir=dist\releases
OutputBaseFilename=betterNJUVPN-{#AppVersion}-setup-win-x64
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
SetupIconFile=assets\betterNJUVPN.ico
UninstallDisplayName=betterNJUVPN
CloseApplications=yes
RestartApplications=no

[Languages]
Name: "chinesesimp"; MessagesFile: "compiler:Languages\ChineseSimplified.isl"

[Tasks]
Name: "desktopicon"; Description: "创建桌面快捷方式"; GroupDescription: "附加选项："; Flags: unchecked
Name: "trustca"; Description: "信任本程序生成的本地 HTTPS 证书（当前用户）"; GroupDescription: "附加选项："

[Files]
Source: "dist\portable\betterNJUVPN\betterNJUVPN.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "dist\portable\betterNJUVPN\betterNJUVPN-cli.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "dist\portable\betterNJUVPN\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "dist\portable\betterNJUVPN\RELEASE_NOTES.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "dist\portable\betterNJUVPN\config.example.json"; DestDir: "{app}"; Flags: ignoreversion
Source: "dist\portable\betterNJUVPN\assets\betterNJUVPN.ico"; DestDir: "{app}\assets"; Flags: ignoreversion
Source: "dist\portable\betterNJUVPN\tools\mihomo\mihomo-windows-amd64-compatible.exe"; DestDir: "{app}\tools\mihomo"; Flags: ignoreversion
Source: "dist\portable\betterNJUVPN\tools\mihomo\LICENSE"; DestDir: "{app}\tools\mihomo"; Flags: ignoreversion

[Icons]
Name: "{group}\betterNJUVPN"; Filename: "{app}\betterNJUVPN.exe"; WorkingDir: "{app}"; IconFilename: "{app}\assets\betterNJUVPN.ico"
Name: "{group}\卸载 betterNJUVPN"; Filename: "{uninstallexe}"
Name: "{autodesktop}\betterNJUVPN"; Filename: "{app}\betterNJUVPN.exe"; WorkingDir: "{app}"; IconFilename: "{app}\assets\betterNJUVPN.ico"; Tasks: desktopicon

[Run]
Filename: "{app}\betterNJUVPN-cli.exe"; Parameters: "trust-ca"; WorkingDir: "{app}"; Description: "生成并信任本地 HTTPS 证书"; Flags: waituntilterminated skipifsilent; Tasks: trustca
Filename: "{app}\betterNJUVPN.exe"; Description: "启动 betterNJUVPN"; Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "{app}\betterNJUVPN-cli.exe"; Parameters: "uninstall-cleanup"; WorkingDir: "{app}"; Flags: runhidden waituntilterminated; RunOnceId: "CleanupLocalState"

[UninstallDelete]
Type: filesandordirs; Name: "{app}\data"
Type: files; Name: "{app}\config.json"
