# SPDX-License-Identifier: GPL-3.0-only
param(
    [string]$Sdk = $env:ANDROID_SDK_ROOT,
    [string]$Keystore = $env:MG4_KEYSTORE,
    [string]$KeyAlias = $env:MG4_KEY_ALIAS
)
$ErrorActionPreference = 'Stop'
if (!$Sdk) { $Sdk = $env:ANDROID_HOME }
if (!$Sdk) { throw 'Set ANDROID_SDK_ROOT to your Android SDK directory.' }
if (!$Keystore -or !(Test-Path -LiteralPath $Keystore)) { throw 'Set MG4_KEYSTORE to the matching platform signing keystore.' }
if (!$KeyAlias) { $KeyAlias = 'platform' }
if (!$env:MG4_STORE_PASSWORD -or !$env:MG4_KEY_PASSWORD) { throw 'Set MG4_STORE_PASSWORD and MG4_KEY_PASSWORD.' }
$root = $PSScriptRoot
$tools = Join-Path $Sdk 'build-tools\31.0.0'
$sdkPlatform = Join-Path $Sdk 'platforms\android-28\android.jar'
foreach ($required in @($sdkPlatform,"$tools\aapt.exe","$tools\lib\d8.jar","$tools\zipalign.exe","$tools\lib\apksigner.jar")) {
    if (!(Test-Path -LiteralPath $required)) { throw "Missing prerequisite: $required" }
}
$build = Join-Path $root ('build\' + [guid]::NewGuid().ToString('N'))
$classes = Join-Path $build 'classes'
$generated = Join-Path $build 'generated'
$dist = Join-Path $root 'dist'
New-Item -ItemType Directory -Force $classes,$generated,$dist | Out-Null
$oldTemp = $env:TEMP
$oldTmp = $env:TMP
function Check-Native([string]$Step) { if ($LASTEXITCODE -ne 0) { throw "$Step failed (exit $LASTEXITCODE)" } }
try {
    $env:TEMP = $build
    $env:TMP = $build
    $platform = Join-Path $build 'android-28.jar'
    Copy-Item -LiteralPath $sdkPlatform -Destination $platform
    $aapt = Join-Path $tools 'aapt.exe'
    & $aapt package -f -m -J $generated -M "$root\AndroidManifest.xml" -S "$root\res" -I $platform
    Check-Native 'Resource generation'
    $sources = @(Get-ChildItem "$root\src",$generated -Recurse -Filter '*.java' | ForEach-Object FullName)
    & javac -source 8 -target 8 -encoding UTF-8 -classpath $platform -d $classes $sources
    Check-Native 'Compilation'
    & $aapt package -f -M "$root\AndroidManifest.xml" -S "$root\res" -I $platform -F "$build\unsigned.apk"
    Check-Native 'Resource packaging'
    & jar cf "$build\classes.jar" -C $classes .
    Check-Native 'Class archive'
    & java -cp "$tools\lib\d8.jar" com.android.tools.r8.D8 --min-api 23 --lib $platform --output $build "$build\classes.jar"
    Check-Native 'DEX conversion'
    Push-Location $build
    try { & $aapt add "$build\unsigned.apk" 'classes.dex'; Check-Native 'DEX packaging' } finally { Pop-Location }
    & "$tools\zipalign.exe" -f 4 "$build\unsigned.apk" "$build\aligned.apk"
    Check-Native 'Alignment'
    $output = Join-Path $dist 'MG4-Wireless-ADB.apk'
    & java -jar "$tools\lib\apksigner.jar" sign --ks $Keystore --ks-key-alias $KeyAlias --ks-pass env:MG4_STORE_PASSWORD --key-pass env:MG4_KEY_PASSWORD --out $output "$build\aligned.apk"
    Check-Native 'Signing'
    & java -jar "$tools\lib\apksigner.jar" verify --verbose --print-certs $output
    Check-Native 'Signature verification'
    Get-FileHash -LiteralPath $output -Algorithm SHA256
} finally {
    $env:TEMP = $oldTemp
    $env:TMP = $oldTmp
}
