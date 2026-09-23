#requires -Version 7
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
Push-Location $root
try {
    $version = '0.1.3'
    $packageName = "betterNJUVPN-$version"
    & (Join-Path $root 'build.ps1') -PackageName $packageName
    if ($LASTEXITCODE -ne 0) { throw '构建失败' }
    $stage = Join-Path $root "dist\portable\$packageName"
    $releaseDir = Join-Path $root 'dist\releases'
    New-Item -ItemType Directory -Path $releaseDir -Force | Out-Null
    if ((Test-Path -LiteralPath (Join-Path $stage 'config.json')) -or (Test-Path -LiteralPath (Join-Path $stage 'data'))) {
        throw '发布目录不能包含本机配置或数据'
    }
    $zip = Join-Path $releaseDir "betterNJUVPN-$version-portable-win-x64.zip"
    if (Test-Path -LiteralPath $zip) { Remove-Item -LiteralPath $zip -Force }
    $zipRoot = Join-Path $root ('dist\release-stage-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $zipRoot -Force | Out-Null
    try {
        Copy-Item -LiteralPath $stage -Destination (Join-Path $zipRoot 'betterNJUVPN') -Recurse
        Compress-Archive -Path (Join-Path $zipRoot 'betterNJUVPN') -DestinationPath $zip -CompressionLevel Optimal
    } finally {
        if ([IO.Path]::GetFullPath($zipRoot).StartsWith([IO.Path]::GetFullPath((Join-Path $root 'dist\release-stage-')), [StringComparison]::OrdinalIgnoreCase)) {
            Remove-Item -LiteralPath $zipRoot -Recurse -Force
        }
    }
    $isccCandidates = @(
        (Join-Path $root '.local\tools\inno-compiler\ISCC.exe'),
        (Join-Path ${env:ProgramFiles} 'Inno Setup 7\ISCC.exe'),
        (Join-Path ${env:ProgramFiles(x86)} 'Inno Setup 6\ISCC.exe')
    )
    $iscc = $isccCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $iscc) { throw '找不到 Inno Setup ISCC.exe；便携 ZIP 已生成，安装包尚未生成' }
    & $iscc "/DSourceDir=dist\portable\$packageName" (Join-Path $root 'installer.iss')
    if ($LASTEXITCODE -ne 0) { throw '安装包编译失败' }
    Get-ChildItem -LiteralPath $releaseDir -Filter "betterNJUVPN-$version-*" | Select-Object Name,Length
} finally {
    Pop-Location
}
