# VulnLinksFinder

**Herramienta profesional para verificación de rutas vulnerables en sitios web**

Verifica automáticamente si las rutas vulnerables contenidas en `Privat.txt` existen realmente en un sitio web, notificando las que responden con código HTTP 200.

## 🚀 Características

- ✅ Verificación paralela de URLs (multi-threading)
- ✅ Soporte para múltiples sitios simultáneamente
- ✅ Métodos HTTP: GET y HEAD (HEAD más rápido)
- ✅ Reintentos automáticos
- ✅ Timeout configurable
- ✅ Exportación a TXT, JSON y CSV
- ✅ Filtrado por códigos de estado HTTP
- ✅ Soporte para proxies
- ✅ Control SSL/TLS
- ✅ User-Agent personalizable
- ✅ Modo verbose y silencioso
- ✅ Estadísticas detalladas de ejecución

## 📋 Requisitos

- Python 3.8+
- pip

## ⚙️ Instalación

1. **Clonar o descargar el proyecto**
```bash
cd d:\!PROJECTS\tools\vulnLinksFinder
```

2. **Instalar dependencias**
```bash
pip install -r requirements.txt
```

## 📖 Uso

### Sintaxis General
```bash
python main.py [-u URL | -l ARCHIVO] [opciones]
```

### Ejemplos Básicos

**Verificar una sola URL:**
```bash
python main.py -u "http://example.com"
```

**Verificar múltiples URLs:**
```bash
python main.py -u "http://site1.com,http://site2.com,http://site3.com"
```

**Verificar desde archivo:**
```bash
python main.py -l urls.txt
```

**Exportar resultados:**
```bash
python main.py -u "http://example.com" -o results.txt
```

### Opciones Detalladas

#### Entrada (Requerido - usar una de estas)

| Opción | Descripción |
|--------|-------------|
| `-u, --url URL` | URL o URLs separadas por coma |
| `-l, --list ARCHIVO` | Archivo con lista de URLs (una por línea) |

#### Salida y Formato

| Opción | Descripción | Default |
|--------|-------------|---------|
| `-o, --output ARCHIVO` | Archivo para exportar resultados | No exportar |
| `-f, --format {txt,json,csv}` | Formato de exportación | txt |
| `--all-results` | Exportar todos los resultados (no solo HTTP 200) | Solo 200 |

#### Rendimiento

| Opción | Descripción | Default |
|--------|-------------|---------|
| `-t, --threads N` | Número de hilos paralelos | 5 |
| `--timeout N` | Timeout para requests (segundos) | 10 |
| `--delay N` | Delay entre requests (segundos) | 0 |
| `--retries N` | Reintentos por URL | 1 |
| `--method {GET,HEAD}` | Método HTTP | HEAD |

#### Configuración HTTP

| Opción | Descripción |
|--------|-------------|
| `--user-agent TEXTO` | User-Agent personalizado |
| `--no-ssl` | Desactivar verificación SSL/TLS |
| `--follow-redirects` | Seguir redirecciones | 
| `--proxy URL` | Proxy a usar (ej: http://proxy:8080) |

#### Filtrado y Visualización

| Opción | Descripción |
|--------|-------------|
| `--filter CÓDIGOS` | Filtrar por códigos HTTP separados por coma (ej: "200,404") |
| `-v, --verbose` | Modo verbose (mostrar detalles durante ejecución) |
| `-q, --quiet` | Modo silencioso (solo resultados finales) |

#### Configuración de Archivos

| Opción | Descripción | Default |
|--------|-------------|---------|
| `--vuln-file ARCHIVO` | Archivo con rutas vulnerables | Privat.txt |

## 📊 Ejemplos Avanzados

### 1. Verificación rápida con múltiples hilos
```bash
python main.py -l urls.txt -t 20 --method HEAD
```

### 2. Exportar a JSON con todos los resultados
```bash
python main.py -u "http://example.com" -o results.json -f json --all-results
```

### 3. Verificación con proxy y reintentos
```bash
python main.py -l urls.txt --proxy "http://proxy:8080" --retries 3 -o results.csv -f csv
```

### 4. Verificación con filtro personalizado (encontrar 200, 403 y 404)
```bash
python main.py -u "http://example.com" --filter "200,403,404" -o results.txt --all-results
```

### 5. Verificación verbose con delay entre requests
```bash
python main.py -l urls.txt -v --delay 0.5 --timeout 15
```

### 6. Ignorar errores SSL
```bash
python main.py -u "https://example.com" --no-ssl
```

### 7. Usar método GET (más lento pero más confiable)
```bash
python main.py -l urls.txt --method GET --timeout 20
```

## 📁 Estructura de Archivos

```
vulnLinksFinder/
├── main.py                    # Archivo principal
├── requirements.txt           # Dependencias
├── README.md                 # Este archivo
├── Privat.txt               # Rutas vulnerables (archivo adjunto)
├── list.txt                 # Archivo de ejemplo con URLs
├── vuln_checker/
│   ├── __init__.py
│   ├── url_extractor.py     # Carga de URLs y rutas
│   ├── http_checker.py      # Verificación HTTP
│   └── output_manager.py    # Exportación de resultados
└── results/                 # Directorio para guardar resultados
    ├── output.txt
    ├── results.json
    └── results.csv
```

## 📝 Archivo de URLs

Crear un archivo `urls.txt` con URLs (una por línea):

```
http://site1.com
http://site2.com
https://site3.org
site4.com
```

Las URLs se normalizarán automáticamente (se agregará `http://` si es necesario).

## 📋 Formato de Salida

### TXT
```
Reporte de Vulnerabilidades
Fecha: 2026-01-12 15:30:45
================================================================================

1. URL: http://example.com/shell.php
   Status: 200
   Ruta vulnerable: shell.php
   Tiempo respuesta: 0.25s

2. URL: http://example.com/admin.php
   Status: 200
   Ruta vulnerable: admin.php
   Tiempo respuesta: 0.18s
```

### JSON
```json
{
  "generated": "2026-01-12T15:30:45.123456",
  "total": 2,
  "results": [
    {
      "url": "http://example.com/shell.php",
      "status_code": 200,
      "status": "ok",
      "vuln_path": "shell.php",
      "response_time": 0.25,
      "error": null
    }
  ]
}
```

### CSV
```csv
url,status_code,status,vuln_path,response_time,error
http://example.com/shell.php,200,ok,shell.php,0.25,
http://example.com/admin.php,200,ok,admin.php,0.18,
```

## 🔍 Interpretación de Resultados

| Código | Significado |
|--------|------------|
| 200 | ✅ **VULNERABLE** - Recurso encontrado y accesible |
| 301/302 | 🔄 Redirección (se sigue automáticamente) |
| 401/403 | 🔒 Acceso denegado (existe pero no accesible) |
| 404 | ❌ No encontrado |
| 500 | ⚠️ Error del servidor |
| timeout | ⏱️ Sin respuesta en el tiempo límite |
| error | ❌ Error de conexión |

## ⚡ Consejos de Rendimiento

1. **Aumentar hilos para muchas URLs:**
   ```bash
   python main.py -l urls.txt -t 20 -t 50
   ```

2. **Usar HEAD en lugar de GET (más rápido):**
   ```bash
   python main.py -l urls.txt --method HEAD
   ```

3. **Reducir timeout si hay respuestas lentas:**
   ```bash
   python main.py -l urls.txt --timeout 5
   ```

4. **Usar modo silencioso para no ralentizar:**
   ```bash
   python main.py -l urls.txt -q -o results.json
   ```

## 🔐 Consideraciones de Seguridad

- ⚠️ **Uso legal**: Solo usar en sitios que tengas permiso para auditar
- 🛡️ **Respeta límites de rate**: Usa `--delay` para no saturar servidores
- 🔒 **SSL**: Desactiva verificación SSL solo cuando sea necesario
- 🔑 **Proxies**: Usa proxies anónimos si auditas sitios de terceros
- 📝 **Registros**: Los resultados contienen URLs vulnerables - mantenlos seguros

## 🐛 Solución de Problemas

**Error: "Archivo no encontrado: Privat.txt"**
- Asegúrate que `Privat.txt` está en el directorio raíz del proyecto

**Error: "Módulo no encontrado"**
- Ejecuta: `pip install -r requirements.txt`

**URLs muy lentas de verificar**
- Aumenta hilos: `-t 20`
- Reduce timeout: `--timeout 5`
- Usa modo HEAD: `--method HEAD`

**No se encuentran vulnerabilidades**
- Verifica que las URLs sean correctas: `-v` para verbose
- Comprueba la conectividad: `ping domain.com`
- Prueba desactivar SSL: `--no-ssl`

## 📚 Dependencias

- `requests`: Librería HTTP
- `urllib3`: Soporte para HTTP
- `colorama`: Colores en terminal (Windows compatible)

## 📄 Licencia

Proyecto de auditoría de seguridad. Uso responsable.

## ✨ Versión

**v1.0.0** - 2026-01-12

---

**Creado con ❤️ para auditorías de seguridad éticas**
