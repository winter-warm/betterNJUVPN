#requires -Version 7
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$env:GOCACHE = Join-Path $root '.gocache'
$distRoot = Join-Path $root 'dist\portable'
$package = Join-Path $distRoot 'betterNJUVPN'
$stage = Join-Path $distRoot ('.stage-' + [guid]::NewGuid().ToString('N'))

Push-Location $root
try {
    New-Item -ItemType Directory -Path $distRoot -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $stage 'tools\mihomo'), (Join-Path $stage 'assets') -Force | Out-Null
    & go build -ldflags '-H=windowsgui' -o (Join-Path $stage 'betterNJUVPN.exe') .
    if ($LASTEXITCODE -ne 0) { throw 'GUI 构建失败' }
    & go build -o (Join-Path $stage 'betterNJUVPN-cli.exe') .
    if ($LASTEXITCODE -ne 0) { throw 'CLI 构建失败' }

    Copy-Item -LiteralPath (Join-Path $root 'README.md'), (Join-Path $root 'RELEASE_NOTES.md'), (Join-Path $root 'config.example.json') -Destination $stage
    Copy-Item -LiteralPath (Join-Path $root 'tools\mihomo\mihomo-windows-amd64-compatible.exe'), (Join-Path $root 'tools\mihomo\LICENSE') -Destination (Join-Path $stage 'tools\mihomo')
    Copy-Item -LiteralPath (Join-Path $root 'assets\betterNJUVPN.ico') -Destination (Join-Path $stage 'assets')

    if (Test-Path -LiteralPath $package) {
        if ([IO.Path]::GetFullPath($package) -ne [IO.Path]::GetFullPath((Join-Path $root 'dist\portable\betterNJUVPN'))) { throw '分发目录路径异常' }
        $privateItems = @('config.json', 'data') | Where-Object { Test-Path -LiteralPath (Join-Path $package $_) }
        if ($privateItems.Count -gt 0) {
            $backup = Join-Path $root ('.local\previous-package-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
            if (Test-Path -LiteralPath $backup) { throw '本地备份目录已存在' }
            New-Item -ItemType Directory -Path $backup -Force | Out-Null
            foreach ($name in $privateItems) { Move-Item -LiteralPath (Join-Path $package $name) -Destination $backup }
            Write-Host "旧分发目录中的本机数据已移至 $backup"
        }
        Remove-Item -LiteralPath $package -Recurse -Force
    }
    Move-Item -LiteralPath $stage -Destination $package
    Write-Host "已构建: $package"
} finally {
    Pop-Location
}
