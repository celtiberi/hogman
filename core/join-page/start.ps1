# Join a Hogman pen on Windows (PowerShell 5.1 and PowerShell 7+).
#
#   $s = curl.exe -fsSL --proto '=https' --proto-redir '=https' 'https://<your pen>/start.ps1' | Out-String
#   if ($LASTEXITCODE -eq 0) { & ([scriptblock]::Create($s)) -ExpectedHost '<your pen>' '<invite link>' }
#
# It's safe to read this first: it's short. It validates your invite link,
# downloads hogman.exe for this computer from the address in that link,
# verifies it against the SHA-256 published there, saves it as
# %USERPROFILE%\hogman.exe (keep it: it updates, shares things and leaves
# the pen later), and runs it.
#
# Your invite link is only sent to the pen host it belongs to -- never to any
# third party. Treat the command like a password and don't share it.
#
# Note: keep this file 7-bit ASCII so Windows PowerShell 5.1 captures it
# cleanly from curl.exe regardless of console codepage.
param(
    [string]$ExpectedHost = "",
    [Parameter(Position = 0)]
    [string]$Link = "",
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$HogmanArgs = @()
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Say([string]$Message) {
    [Console]::Out.WriteLine($Message)
}

function Die([string]$Message) {
    [Console]::Error.WriteLine("")
    [Console]::Error.WriteLine("ERROR: $Message")
    exit 1
}

function Get-FileSHA256Hex([string]$Path) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $stream = [System.IO.File]::OpenRead($Path)
    try {
        $hash = $sha.ComputeHash($stream)
        return ([System.BitConverter]::ToString($hash) -replace '-', '').ToLowerInvariant()
    } finally {
        $stream.Dispose()
        $sha.Dispose()
    }
}

function Have-InteractiveConsole {
    try {
        return ([Environment]::UserInteractive -and (-not [Console]::IsInputRedirected))
    } catch {
        return $false
    }
}

function Get-HogmanArch {
    try {
        $osArch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToLowerInvariant()
        switch ($osArch) {
            "x64"   { return "amd64" }
            "arm64" { return "arm64" }
        }
    } catch {
        # Fall back to environment variables below on older .NET runtimes.
    }
    $raw = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
    switch (($raw + "").ToUpperInvariant()) {
        "AMD64" { return "amd64" }
        "ARM64" { return "arm64" }
        default { Die "this Windows architecture ($raw) isn't supported yet: use 64-bit Windows (AMD64 or ARM64)" }
    }
}

$curlCmd = Get-Command curl.exe -ErrorAction SilentlyContinue
if (-not $curlCmd) {
    Die "curl.exe is required (included in Windows 10 1803+ and Windows 11)"
}
$curlExe = $curlCmd.Source

$arch = Get-HogmanArch
$file = "hogman-windows-$arch.exe"

$homeDir = $env:USERPROFILE
if ([string]::IsNullOrWhiteSpace($homeDir)) {
    $homeDir = $HOME
}
if ([string]::IsNullOrWhiteSpace($homeDir)) {
    Die "could not determine your user home directory (USERPROFILE)"
}
$destPath = Join-Path $homeDir "hogman.exe"

$appData = $env:APPDATA
if ([string]::IsNullOrWhiteSpace($appData)) {
    $appData = Join-Path $homeDir "AppData\Roaming"
}
$configBase = Join-Path $appData "hogman"

if ([string]::IsNullOrWhiteSpace($ExpectedHost) -and -not [string]::IsNullOrWhiteSpace($env:HOGMAN_EXPECTED_HOST)) {
    $ExpectedHost = $env:HOGMAN_EXPECTED_HOST.Trim()
}

function Parse-ExpectedSHA256([string]$SumsPath, [string]$TargetFile) {
    $want = ""
    $lines = Get-Content -LiteralPath $SumsPath
    foreach ($rawLine in $lines) {
        $line = ($rawLine + "").TrimEnd("`r")
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        if ($line -match '^([0-9a-fA-F]{64}) [ \*](.+)$') {
            $digest = $Matches[1].ToLowerInvariant()
            $name = $Matches[2]
            if ($name -eq $TargetFile) {
                if ($want -ne "") {
                    Die "SHA256SUMS lists $TargetFile more than once; refusing download"
                }
                $want = $digest
            }
        }
    }
    return $want
}

function Install-StagedBinary([string]$SourceBin, [string]$TargetPath) {
    $targetDir = Split-Path -Parent $TargetPath
    $stagePath = Join-Path $targetDir (".hogman.tmp." + [System.IO.Path]::GetRandomFileName() + ".exe")
    $moved = $false
    try {
        Copy-Item -LiteralPath $SourceBin -Destination $stagePath -Force
        try {
            Move-Item -LiteralPath $stagePath -Destination $TargetPath -Force
            $moved = $true
        } catch {
            # On Windows a running hogman.exe cannot be overwritten in place,
            # but it can be renamed aside to hogman.exe.old before moving the new binary in.
            $oldPath = $TargetPath + ".old"
            if (Test-Path -LiteralPath $oldPath) {
                try { Remove-Item -LiteralPath $oldPath -Force -ErrorAction Stop } catch {}
            }
            Move-Item -LiteralPath $TargetPath -Destination $oldPath -Force
            try {
                Move-Item -LiteralPath $stagePath -Destination $TargetPath -Force
                $moved = $true
            } catch {
                try { Move-Item -LiteralPath $oldPath -Destination $TargetPath -Force } catch {}
                throw
            }
            try { Remove-Item -LiteralPath $oldPath -Force -ErrorAction SilentlyContinue } catch {}
        }
    } finally {
        if (-not $moved -and (Test-Path -LiteralPath $stagePath)) {
            try { Remove-Item -LiteralPath $stagePath -Force -ErrorAction SilentlyContinue } catch {}
        }
    }
}

function Download-AndInstall([string]$SrcLabel, [string]$SumsUrl, [string]$BinUrl) {
    $tmpRoot = if ($env:TEMP) { $env:TEMP } else { [System.IO.Path]::GetTempPath() }
    $tmpDir = Join-Path $tmpRoot ("hogman-" + [System.IO.Path]::GetRandomFileName())
    New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null
    try {
        Say ""
        Say "* Downloading hogman for Windows $arch from $SrcLabel"
        $sumsPath = Join-Path $tmpDir "SHA256SUMS"
        $binPath = Join-Path $tmpDir "hogman.exe"

        & $curlExe -fsSL --proto '=https' --proto-redir '=https' -o $sumsPath $SumsUrl | Out-Null
        if ($LASTEXITCODE -ne 0) { return 1 }

        $want = Parse-ExpectedSHA256 -SumsPath $sumsPath -TargetFile $file
        if ([string]::IsNullOrWhiteSpace($want)) { return 2 }

        & $curlExe -fsSL --proto '=https' --proto-redir '=https' -o $binPath $BinUrl | Out-Null
        if ($LASTEXITCODE -ne 0) { return 3 }

        $got = Get-FileSHA256Hex -Path $binPath
        if ($got -ne $want) {
            Die "the download doesn't match its published SHA-256 (want $want, got $got); not running it"
        }
        Say "  checked: SHA-256 matches"

        try {
            Install-StagedBinary -SourceBin $binPath -TargetPath $destPath
        } catch {
            return 4
        }
        Say "  saved as $destPath (keep it: it updates, shares and leaves later)"
        return 0
    } finally {
        if (Test-Path -LiteralPath $tmpDir) {
            try { Remove-Item -LiteralPath $tmpDir -Recurse -Force -ErrorAction SilentlyContinue } catch {}
        }
    }
}

# Check if this computer already belongs to any Hogman pens.
$hasPens = $false
$hostInPens = $false
$firstPenHost = ""
if (Test-Path -LiteralPath $configBase) {
    $configs = Get-ChildItem -LiteralPath $configBase -Directory -ErrorAction SilentlyContinue
    foreach ($dir in $configs) {
        $cfgPath = Join-Path $dir.FullName "config.json"
        if (-not (Test-Path -LiteralPath $cfgPath)) { continue }
        $hasPens = $true
        try {
            $rawCfg = [System.IO.File]::ReadAllText($cfgPath)
            if ($rawCfg -match '"login_server"\s*:\s*"https://([a-zA-Z0-9.:-]+)(?:/|")') {
                $lsHost = $Matches[1]
                if ($firstPenHost -eq "") { $firstPenHost = $lsHost }
                if ($ExpectedHost -ne "" -and $lsHost.ToLowerInvariant() -eq $ExpectedHost.ToLowerInvariant()) {
                    $hostInPens = $true
                }
            }
        } catch {
            # Ignore unreadable or malformed config.json when scanning existing pens.
        }
    }
}

# If run with no link on a machine that already has pens (and not explicitly
# pinned to a brand-new pen host via -ExpectedHost / HOGMAN_EXPECTED_HOST),
# install hogman.exe and run `hogman.exe update` instead of asking for an invite link (I-9).
if ([string]::IsNullOrWhiteSpace($Link) -and $hasPens -and ([string]::IsNullOrWhiteSpace($ExpectedHost) -or $hostInPens)) {
    Say "* Existing Hogman pen(s) found on this computer -- installing $destPath and running update"
    $installed = $false
    if (-not [string]::IsNullOrWhiteSpace($ExpectedHost)) {
        if ($ExpectedHost -notmatch '^[a-zA-Z0-9.:-]+$') {
            Die "unexpected host: $ExpectedHost"
        }
        $rc = Download-AndInstall -SrcLabel $ExpectedHost `
            -SumsUrl "https://$ExpectedHost/join/dl/SHA256SUMS" `
            -BinUrl "https://$ExpectedHost/join/dl/$file"
        if ($rc -eq 0) { $installed = $true }
    } else {
        if (-not [string]::IsNullOrWhiteSpace($firstPenHost)) {
            $rc = Download-AndInstall -SrcLabel $firstPenHost `
                -SumsUrl "https://$firstPenHost/join/dl/SHA256SUMS" `
                -BinUrl "https://$firstPenHost/join/dl/$file"
            if ($rc -eq 0) { $installed = $true }
        }
        if (-not $installed) {
            $ghBase = "https://github.com/celtiberi/hogman/releases/latest/download"
            $rc = Download-AndInstall -SrcLabel "GitHub Releases" `
                -SumsUrl "$ghBase/hogman-SHA256SUMS" `
                -BinUrl "$ghBase/$file"
            if ($rc -eq 0) { $installed = $true }
        }
    }
    if (-not $installed) {
        Die "could not download $file; try downloading it from https://hogman.network/dl/$file and running: $destPath update"
    }
    $legacyPath = Join-Path $homeDir "hogman-join.exe"
    if (Test-Path -LiteralPath $legacyPath) {
        Say "  note: once updated, you can delete $legacyPath"
    }
    Say "  (to join another pen later, run: $destPath '<invite link>')"
    & $destPath update
    exit $LASTEXITCODE
}

if ([string]::IsNullOrWhiteSpace($Link)) {
    if (-not (Have-InteractiveConsole)) {
        Die "no terminal to ask for your invite link on; pass the link on the command line"
    }
    $Link = Read-Host "Paste your invite link (the full link you were sent, including everything after the #)"
    if ([string]::IsNullOrWhiteSpace($Link)) {
        Die "no link given"
    }
}
$Link = $Link -replace '[\s\r\n\t]+', ''

# https://<host>/join#t=... (an invite) or #k=... (a device link).
if ($Link -notmatch '^https://') {
    Die "that doesn't look like a Hogman invite link (it starts https:// and contains /join#)"
}
if ($Link -notmatch '^https://([a-zA-Z0-9.:-]+)/join#(t|k)=([^&\s]+)(&.*)?$') {
    Die "that doesn't look like a Hogman invite link (expected https://<host>/join#t=... or #k=...)"
}
$linkHost = $Matches[1]

if (-not [string]::IsNullOrWhiteSpace($ExpectedHost) -and $linkHost.ToLowerInvariant() -ne $ExpectedHost.ToLowerInvariant()) {
    Die "refusing link for $linkHost (expected $ExpectedHost)"
}

$rc = Download-AndInstall -SrcLabel $linkHost `
    -SumsUrl "https://$linkHost/join/dl/SHA256SUMS" `
    -BinUrl "https://$linkHost/join/dl/$file"
switch ($rc) {
    0 { }
    1 { Die "couldn't reach https://$linkHost" }
    2 { Die "there's no hogman for Windows $arch yet" }
    4 { Die "could not write $destPath (check permissions on $homeDir)" }
    default { Die "the download failed; try again" }
}

if ($HogmanArgs.Count -gt 0) {
    & $destPath @HogmanArgs $Link
} else {
    & $destPath $Link
}
exit $LASTEXITCODE
