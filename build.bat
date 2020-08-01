@echo off
if not exist "%cd%\WpdPack\" (
	echo.
	echo ------------ Downloading WinPcap 4.1.2 Developer's Pack ------------
	echo.
	powershell -Command "Invoke-WebRequest https://www.winpcap.org/install/bin/WpdPack_4_1_2.zip  -OutFile WpdPack_4_1_2.zip
	powershell Expand-Archive WpdPack_4_1_2.zip -destinationpath %cd%
	DEL /F /S /Q /A *.zip
)
echo.
echo ------------------------ Compiling  Sniffer ------------------------
echo.
"%VS160COMNTOOLS%VsDevCmd.bat" & cl /EHsc /O2 snifdump.cpp /I .\WpdPack\Include /DWIN32 /DHAVE_REMOTE WpdPack\Lib\wpcap.lib Ws2_32.lib & DEL /F /S /Q /A *.obj