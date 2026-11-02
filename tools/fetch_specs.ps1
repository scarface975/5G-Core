# Download the pinned 3GPP Release-16 documents (latest 'g' version of each) into docs/specs/src and write a manifest
# with version, URL and SHA-256 to docs/specs/pinned.json.   Usage: powershell -File tools/fetch_specs.ps1
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$dst = Join-Path $root "docs\specs\src"
New-Item -ItemType Directory -Force $dst | Out-Null

# spec number -> (series directory)
$specs = [ordered]@{
  "23.003"="23_series"; "23.501"="23_series"; "23.502"="23_series"; "23.503"="23_series";
  "29.244"="29_series"; "29.502"="29_series"; "29.518"="29_series"; "24.008"="24_series"; "29.281"="29_series"; "29.500"="29_series"; "29.501"="29_series"; "29.503"="29_series";
  "29.504"="29_series"; "29.505"="29_series"; "29.507"="29_series"; "29.509"="29_series"; "29.510"="29_series";
  "29.512"="29_series"; "29.519"="29_series"; "29.571"="29_series";
  "33.220"="33_series"; "33.501"="33_series"; "38.415"="38_series";
}
$manifest = @()
foreach ($spec in $specs.Keys) {
  $dir = $specs[$spec]; $n = $spec.Replace(".", "")
  $page = "https://www.3gpp.org/ftp/Specs/archive/$dir/$spec/"
  $links = @((Invoke-WebRequest -UseBasicParsing $page).Links | Where-Object { $_.href -match "$n-g[a-z0-9]{2}\.zip" } | Select-Object -ExpandProperty href)
  if ($links.Count -eq 0) { Write-Output "$spec : NO Rel-16 zip found"; continue }
  $url = $links[$links.Count - 1]; $file = Split-Path $url -Leaf
  $zip = Join-Path $dst $file
  if (-not (Test-Path $zip)) { Invoke-WebRequest -UseBasicParsing $url -OutFile $zip }
  $out = Join-Path $dst ($file -replace "\.zip$", "")
  if (-not (Test-Path $out)) { Expand-Archive -Force $zip -DestinationPath $out }
  # 3GPP version code: 3 chars, each 0-9 / a-z (a=10 ...), e.g. gf0 -> 16.15.0
  $code = [IO.Path]::GetFileNameWithoutExtension($file).Substring($n.Length + 1)
  $dig = { param($c) if ($c -match "[0-9]") { [int][string]$c } else { [int][char]$c - [int][char]'a' + 10 } }
  $ver = "{0}.{1}.{2}" -f (& $dig $code[0]), (& $dig $code[1]), (& $dig $code[2])
  $sha = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLower()
  $manifest += [pscustomobject]@{ spec = "TS $spec"; version = $ver; release = 16; file = $file; url = $url; sha256 = $sha; bytes = (Get-Item $zip).Length; fetched = (Get-Date -Format "yyyy-MM-dd") }
  Write-Output ("{0,-8} v{1,-8} {2,10:N0} bytes  {3}" -f $spec, $ver, (Get-Item $zip).Length, $file)
}
$manifest | ConvertTo-Json -Depth 3 | Out-File -Encoding utf8 (Join-Path $root "docs\specs\pinned.json")
Write-Output "pinned $($manifest.Count) documents -> docs/specs/pinned.json"

