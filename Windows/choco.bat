rem Chocolatey now requires PowerShell v3 (or higher) and .NET 4.0 (or higher) due to recent upgrades to TLS 1.2. 
rem Please ensure .NET 4+ and PowerShell v3+ are installed prior to attempting FLARE VM installation. 
rem Below are links to download .NET 4.5 and WMF 5.1 (PowerShell 5.1).
rem .NET 4.5 https://www.microsoft.com/en-us/download/details.aspx?id=30653
rem WMF 5.1 https://www.microsoft.com/en-us/download/details.aspx?id=54616


@"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command " [System.Net.ServicePointManager]::SecurityProtocol = 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))" && SET "PATH=%PATH%;%ALLUSERSPROFILE%\chocolatey\bin"
choco upgrade chocolatey
choco install -y dotnetfx dotnet4.7.2 vcredist-all wixtoolset msxml4.sp3 msxml6.sp1

pip3 install pillow pywintrace
