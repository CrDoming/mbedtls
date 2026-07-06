$vcvarsallPath = "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat"
$clPath = "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\cl.exe"

cmd /c """$vcvarsallPath"" amd64 & set" | ForEach-Object {
    if ($_ -match "^([^=]*)=(.*)$") {
        Set-Item -Force -Path "env:\$($matches[1])" -Value "$($matches[2])"
    }
}

$env:HOSTCC = $clPath