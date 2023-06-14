dotnet publish tests\Library.Fuzz -c release -o out -r win10-x64 --self-contained
sharpfuzz out\Library.dll

mkdir corpus
$outputPath = "output.txt"

.\libfuzzer-dotnet-windows --target_path=out\Library.Fuzz.exe corpus 2>&1 `
| Tee-Object -FilePath $outputPath

$output = Get-Content -Path $outputPath -Raw
$crasher = "Cooking MC's"
$exception = "Like a pound of bacon"

if (-not $output.Contains($crasher)) {
    Write-Error "Crasher is missing from the libFuzzer output"
    exit 1
}

if (-not $output.Contains($exception)) {
    Write-Error "Exception is missing from the libFuzzer output"
    exit 1
}

Write-Host "$crasher $($exception.ToLower())"
exit 0
