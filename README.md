# PC Inspector

Una utilidad portátil de inspección de hardware para Windows, escrita en
PowerShell puro y sin dependencias externas. Diseñada para evaluar un PC
antes de comprarlo de segunda mano. Piénsala como una combinación ligera
de CPU-Z, CrystalDiskInfo, HWiNFO y Speccy en un solo script.

## Características principales

- **Script único y portátil**: sin instalación, sin modificaciones al
  registro, sin dependencias externas.
- **Windows 10 / Windows 11**, PowerShell 5.1+ y PowerShell 7+.
- **No requiere permisos de administrador.** Los datos privilegiados
  (desgaste SMART, horas de encendido, zonas térmicas) se degradan de
  forma controlada a `Unknown (requires Administrator)` en lugar de fallar.
- **Nunca se cuelga.** Cada consulta está protegida con respaldos en
  cascada: CIM → WMI → cmdlet → registro → COM; los valores desconocidos
  siempre se muestran como `Unknown`.
- Interfaz de consola profesional con caracteres Unicode de cuadro,
  colores e indicador de progreso.
- **Exportación a JSON, TXT y HTML** del informe completo. El HTML es una
  página autónoma con tema claro/oscuro automático, tarjetas de resumen y
  secciones plegables.
- **Decodificación de atributos SMART** (ATA): valor, peor valor, umbral y
  valor raw de cada atributo, con nombres legibles y detección de sectores
  reasignados/pendientes.
- **Benchmark opcional de CPU y disco** (`-Benchmark`): SHA-256 mono y
  multihilo, y lectura/escritura secuencial + lectura aleatoria 4K con E/S
  sin búfer (evita la caché de Windows).
- **Detección de enlace PCIe**: generación y líneas (ej. `Gen4 x4`) de GPUs
  y unidades NVMe, más la generación PCIe estimada de la placa base.
- **Detección de canales de RAM** mejorada (Single/Dual/Quad channel a
  partir de las etiquetas SMBIOS de banco/slot).
- **Identificación SSD/NVMe** mejorada: distingue NVMe, SATA SSD, SSD
  externo por USB, HDD y eMMC combinando bus, PNPDeviceID, tipo de medio y
  velocidad de giro.
- **Chequeo de salud** automático (advertencias) y **análisis de comprador**
  con observaciones objetivas.
- Código de salida `0` en caso de éxito.

## Uso

```powershell
# Inspección completa, solo salida por consola
.\PC-Inspector.ps1

# Inspección + informes TXT
.\PC-Inspector.ps1 -Txt

# Inspección + informes JSON, TXT y HTML (guardados junto al script)
.\PC-Inspector.ps1 -Json -Txt -Html

# Inspección con benchmark de CPU y disco + informe HTML
.\PC-Inspector.ps1 -Benchmark -Html

# También se aceptan flags estilo GNU
powershell -ExecutionPolicy Bypass -File .\PC-Inspector.ps1 --json --html --benchmark

# Directorio de exportación personalizado, sin colores, bordes ASCII
.\PC-Inspector.ps1 -Json -OutputPath D:\Reports -NoColor -Ascii
```

> Ejecutar como Administrador es opcional, pero desbloquea datos
> adicionales: nivel de desgaste del SSD, horas de encendido,
> temperaturas de disco y zonas térmicas ACPI.

### Parámetros

| Parámetro     | Alias      | Descripción                                   |
|---------------|------------|-----------------------------------------------|
| `-Json`       | `--json`   | Exporta el informe completo en formato JSON   |
| `-Txt`        | `--txt`    | Exporta el informe completo en texto plano    |
| `-Html`       | `--html`   | Exporta el informe completo como página HTML autónoma |
| `-Benchmark`  | `--benchmark` | Ejecuta el benchmark opcional de CPU y disco |
| `-OutputPath` |            | Directorio de exportación (por defecto: carpeta del script) |
| `-NoColor`    | `--nocolor`| Desactiva la salida a color (también respeta la variable de entorno `NO_COLOR`) |
| `-Ascii`      | `--ascii`  | Usa bordes ASCII en lugar de caracteres Unicode |

## Qué inspecciona

| Sección      | Detalles |
|--------------|---------|
| Sistema      | Fabricante, modelo, número de serie, SKU, edición y build de Windows, fecha de instalación, activación, tiempo de actividad, Secure Boot, UEFI/Legacy, TPM, BitLocker, compatibilidad con Windows 11 |
| CPU          | Modelo, generación (estimada), socket, núcleos/hilos, frecuencias, caché L1/L2/L3, virtualización/SLAT, AES-NI, AVX/AVX2/AVX-512, versiones de SSE, revisión de microcódigo |
| Placa base   | Fabricante, modelo, número de serie, chipset (estimado), fabricante/versión/fecha de BIOS, versión SMBIOS, generación PCIe estimada |
| RAM          | Total instalado, máximo soportado, slots (totales/usados/libres), configuración de canales (Single/Dual/Quad detectada desde SMBIOS), y por cada módulo: fabricante, número de parte, serie, capacidad, velocidad, voltaje, generación DDR, ECC, rank, factor de forma |
| Almacenamiento | Por cada disco: modelo, firmware, número de serie, capacidad, estilo de partición, tipo de bus, NVMe/SATA SSD/HDD/USB/eMMC, RPM, letras de unidad, estado SMART, atributos SMART decodificados (con umbral y raw), enlace PCIe (NVMe), salud estimada, vida útil del SSD, horas de encendido, temperatura; volúmenes y estado de TRIM |
| GPU          | Por cada GPU: fabricante, modelo, VRAM (precisa vía registro), enlace PCIe (generación y líneas), versión/fecha del driver, integrada o dedicada |
| Red          | Ethernet/Wi-Fi/Bluetooth, MAC, velocidad de enlace, driver, IPv4/IPv6, gateway, DNS |
| USB          | Controladoras, versiones de USB soportadas, dispositivos conectados |
| PCI          | Todos los dispositivos PCI con su driver y estado |
| Pantalla     | Modelo de monitor, fabricante, año, tamaño diagonal, resolución y frecuencia de actualización activas |
| Batería      | Capacidad de diseño vs. capacidad de carga completa, nivel de desgaste, ciclos de carga, estimación de salud |
| Audio        | Dispositivos con sus drivers |
| Sensores     | Zonas térmicas ACPI, temperatura de disco, ventiladores (donde estén disponibles) |
| Benchmark (opcional) | CPU: SHA-256 mono y multihilo con factor de escalado; Disco: escritura/lectura secuencial (bloques de 1 MB) y lectura aleatoria 4K con E/S sin búfer, sobre la unidad del directorio temporal |

## Chequeo de salud

Genera advertencias automáticas para: BIOS antigua, RAM en canal único
(un solo módulo, o varios módulos en el mismo canal) o lenta, ausencia de
SSD, disco de arranque en HDD, problemas SMART (incluidos sectores
reasignados/pendientes y atributos bajo su umbral de fallo), temperaturas
altas, virtualización desactivada, poco espacio en disco, drivers de GPU
desactualizados, GPU con enlace PCIe por debajo de su capacidad, SSD con
rendimiento anómalo en el benchmark, desgaste de batería, licencia de
Windows inactiva, instalaciones en Legacy BIOS y dispositivos PCI con
problemas de driver.

## Análisis de comprador

Observaciones objetivas y basadas en hechos para apoyar una decisión de
compra: slots de RAM libres, presencia de NVMe y su enlace PCIe, modo de
canales de la RAM, generación PCIe de la placa, tipo de disco de
arranque, preparación UEFI/TPM para Windows 11, antigüedad de la BIOS,
retención de capacidad de la batería y resultados del benchmark.

## Códigos de salida

| Código | Significado |
|--------|-------------|
| 0      | La inspección se completó correctamente |
| 1      | Fallo fatal e inesperado |

## Licencia

MIT
