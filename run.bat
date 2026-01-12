@echo off
REM VulnLinksFinder - Script de ejecución rápida

setlocal enabledelayedexpansion

echo.
echo ================================================================================
echo  VulnLinksFinder - Verificador de Rutas Vulnerables
echo ================================================================================
echo.

REM Argumentos
if "%~1"=="" (
    echo Uso:
    echo   %0 [URL o archivo] [opciones adicionales]
    echo.
    echo Ejemplos:
    echo   %0 "http://example.com"
    echo   %0 urls.txt -t 10
    echo   %0 "http://site1.com,http://site2.com" -o resultados.json -f json
    echo.
    exit /b 1
)

python linkScanner.py %*
