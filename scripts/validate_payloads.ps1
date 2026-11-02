# Dump the JSON our NFs really produce, then validate it against the official 3GPP OpenAPI schemas.
# Needs: docs/specs/src/openapi (python tools/spec/spec_text.py; python tools/spec/extract_openapi.py), pip install jsonschema pyyaml
$root = (Resolve-Path "$PSScriptRoot\..").Path
$drive = $root.Substring(0, 1).ToLower()
$wslRoot = "/mnt/$drive" + $root.Substring(2).Replace('\', '/')
$dir = Join-Path $root "build\payloads"
Remove-Item -Recurse -Force $dir -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $dir | Out-Null
wsl -d Ubuntu -- bash "$wslRoot/scripts/dump_payloads.sh" "$wslRoot/build/payloads"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
python (Join-Path $root "tools\validate_openapi.py") $dir
exit $LASTEXITCODE
