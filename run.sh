#!/bin/bash
# VulnLinksFinder - Script de ejecución rápida para Linux/Mac

if [ $# -eq 0 ]; then
    echo ""
    echo "================================================================================"
    echo " VulnLinksFinder - Verificador de Rutas Vulnerables"
    echo "================================================================================"
    echo ""
    echo "Uso:"
    echo "  ./run.sh [URL o archivo] [opciones adicionales]"
    echo ""
    echo "Ejemplos:"
    echo "  ./run.sh \"http://example.com\""
    echo "  ./run.sh urls.txt -t 10"
    echo "  ./run.sh \"http://site1.com,http://site2.com\" -o resultados.json -f json"
    echo ""
    exit 1
fi

python3 linkScanner.py "$@"
