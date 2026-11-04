# Add Release-16 documents to docs/specs/src and to docs/specs/pinned.json without touching the entries already there.
#   powershell -File tools/spec/add_specs.ps1 24.526 29.525 29.573 ...
param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Specs)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$root = Split-Path -Parent $root
$dst = Join-Path $root "docs\specs\src"
$pins = Join-Path $root "docs\specs\pinned.json"
New-Item -ItemType Directory -Force $dst | Out-Null
$manifest = @(Get-Content $pins -Raw | ConvertFrom-Json)
foreach ($spec in $Specs) {
    $n = $spec.Replace(".", "")
    $dir = "$($spec.Split('.')[0])_series"
    $page = "https://www.3gpp.org/ftp/Specs/archive/$dir/$spec/"
    $links = @((Invoke-WebRequest -UseBasicParsing $page).Links | Where-Object { $_.href -match "$n-g[a-z0-9]{2}\.zip" } | Select-Object -ExpandProperty href)
    if ($links.Count -eq 0) { Write-Output "$spec : no Rel-16 zip found"; continue }
    $url = $links[$links.Count - 1]; $file = Split-Path $url -Leaf
    $zip = Join-Path $dst $file
    if (-not (Test-Path $zip)) { Invoke-WebRequest -UseBasicParsing $url -OutFile $zip }
    $out = Join-Path $dst ($file -replace "\.zip$", "")
    if (-not (Test-Path $out)) { Expand-Archive -Force $zip -DestinationPath $out }
    $code = [IO.Path]::GetFileNameWithoutExtension($file).Substring($n.Length + 1)
    $dig = { param($c) if ($c -match "[0-9]") { [int][string]$c } else { [int][char]$c - [int][char]'a' + 10 } }
    $ver = "{0}.{1}.{2}" -f (& $dig $code[0]), (& $dig $code[1]), (& $dig $code[2])
    $sha = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLower()
    $manifest = @($manifest | Where-Object { $_.spec -ne "TS $spec" })
    $manifest += [pscustomobject]@{ spec = "TS $spec"; version = $ver; release = 16; file = $file; url = $url; sha256 = $sha; bytes = (Get-Item $zip).Length; fetched = (Get-Date -Format "yyyy-MM-dd") }
    Write-Output ("{0,-8} v{1,-8} {2,10:N0} bytes  {3}  {4}" -f $spec, $ver, (Get-Item $zip).Length, $file, $sha.Substring(0, 16))
}
$manifest | ConvertTo-Json -Depth 3 | Out-File -Encoding utf8 $pins
Write-Output "pinned.json holds $($manifest.Count) documents"
