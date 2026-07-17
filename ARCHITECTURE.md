# Arquitectura de PC Inspector

Este documento explica cómo está armado `PC-Inspector.ps1` por dentro: qué hace cada bloque de código, cómo se comunican entre sí, y qué patrones de diseño se repiten. El objetivo es que cualquiera pueda entender el script en 10-15 minutos y sentirse cómodo mandando un PR (agregar un nuevo dato, arreglar un fallback, sumar una advertencia al health check, etc.).

El script es un único archivo de ~2700 líneas de PowerShell puro. No hay módulos externos ni dependencias: todo vive en `PC-Inspector.ps1`. (La única excepción parcial es el benchmark de disco, que compila en tiempo de ejecución un helper C# embebido con `Add-Type` para hacer E/S sin búfer; si esa compilación falla, el benchmark se degrada con un mensaje explícito.)

## Índice

1. [Flujo general](#flujo-general)
2. [Parámetros y compatibilidad GNU](#parámetros-y-compatibilidad-gnu)
3. [Estado global del script](#estado-global-del-script)
4. [Helpers núcleo](#helpers-núcleo)
5. [Pipeline de salida (consola + TXT)](#pipeline-de-salida-consola--txt)
6. [Cachés perezosas compartidas](#cachés-perezosas-compartidas)
7. [Colectores de secciones](#colectores-de-secciones)
8. [Health Check y Buyer Analysis](#health-check-y-buyer-analysis)
9. [Resumen y exportación](#resumen-y-exportación)
10. [Función `Main`](#función-main)
11. [Patrones de diseño que se repiten](#patrones-de-diseño-que-se-repiten)
12. [Cómo agregar un dato nuevo](#cómo-agregar-un-dato-nuevo)

---

## Flujo general

```
param() → GNU args → estado global
        → Invoke-PCInspector (Main)
              ├─ recorre $plan (13 secciones + Benchmark si se pidió -Benchmark)
              │  y llama a cada Get-XxxInfo
              ├─ renderiza cada sección con Write-KVBlock
              ├─ Get-HealthChecks   → advertencias automáticas
              ├─ Get-BuyerAnalysis  → observaciones objetivas
              ├─ Out-SummarySection
              └─ Export-Reports (JSON/TXT/HTML si se pidió)
```

Cada `Get-XxxInfo` (System, CPU, Motherboard, RAM, Storage, GPU, Network, USB, PCI, Display, Battery, Audio, Sensors, y opcionalmente Benchmark) es independiente y devuelve un `[ordered]@{}` (diccionario ordenado). Ese diccionario es la única interfaz entre "recolectar datos" y "mostrarlos": el mismo objeto se usa para pintar la consola, para el TXT, para el JSON y para el HTML.

## Parámetros y compatibilidad GNU

```powershell
param(
    [switch]$Json, [switch]$Txt, [string]$OutputPath,
    [switch]$NoColor, [switch]$Ascii,
    [Parameter(ValueFromRemainingArguments = $true)][string[]]$ExtraArgs
)
```

PowerShell usa `-Json`, `-Txt`, etc. (con guion simple). Para que también funcione `--json` estilo Unix, cualquier argumento que no calce con un parámetro nombrado cae en `$ExtraArgs`, y un bloque `switch -Regex` lo traduce al switch real:

```powershell
switch -Regex ($arg) {
    '^--?json$'         { $Json = $true }
    '^--?txt$'          { $Txt = $true }
    '^--?html?$'        { $Html = $true }
    '^--?bench(mark)?$' { $Benchmark = $true }
    '^--?no-?color$'    { $NoColor = $true }
    ...
}
```

Esto es lo que permite que `.\PC-Inspector.ps1 -Json` y `--json` hagan exactamente lo mismo.

## Estado global del script

Todo lo compartido entre funciones vive en variables `$Script:*`, declaradas al principio:

| Variable | Para qué sirve |
|---|---|
| `$Script:Version` | Versión mostrada en el banner y en el JSON exportado |
| `$Script:NoColor` | Si `-NoColor` o la variable de entorno `NO_COLOR` están activos |
| `$Script:TxtBuffer` | `StringBuilder` que va acumulando todo lo que se imprime, para el export TXT |
| `$Script:Raw` | Diccionario de hechos "en bruto" (números, booleanos) que las secciones posteriores necesitan. Se explica en detalle más abajo |
| `$Script:IsCore` | `$true` si corre en PowerShell 7+ (Core), `$false` en Windows PowerShell 5.1 |
| `$Script:DriverIndex` | Caché perezosa de todos los drivers instalados (se llena una sola vez) |
| `$Script:G` | Diccionario con los glifos de caja (Unicode o ASCII según `-Ascii`) |
| `$Script:PcieGenMap` | Mapa de la codificación de velocidad PCIe (1-6) a `Gen1`-`Gen6` |
| `$Script:BoardPcieGen` | Caché del resultado de `Get-BoardPcieGeneration` |
| `$Script:SmartAttrNames` | Mapa de IDs de atributos SMART ATA a nombres legibles |

**`$Script:Raw` es la pieza clave para entender el script.** Cada colector, además de devolver el diccionario "bonito" para mostrar, va guardando datos crudos ahí (`$Script:Raw.HasSSD`, `$Script:Raw.RamGB`, `$Script:Raw.CpuCores`, etc.). Ese diccionario es lo que después consumen `Get-HealthChecks` y `Get-BuyerAnalysis` para razonar sobre la máquina sin tener que volver a parsear texto formateado. Es básicamente el "modelo de datos" interno del programa, separado de la capa de presentación.

## Helpers núcleo

Bloque `Core helpers`, funciones chicas y reutilizables en todo el resto del script:

- **`Test-IsAdmin`**: chequea si el proceso corre elevado (`WindowsPrincipal.IsInRole(Administrator)`). Se usa por todo el script para decidir si un dato debería estar disponible o degradar a "Unknown (requires Administrator)".
- **`Invoke-Safe`**: envuelve un `scriptblock` en `try/catch` y devuelve un valor por defecto si falla. Es el mecanismo base de "nunca te cuelgues": casi cualquier llamada riesgosa del script pasa por acá.
- **`Get-CimSafe`**: consulta WMI/CIM con fallback en cascada. Primero intenta `Get-CimInstance` (moderno); si falla, intenta `Get-WmiObject` (compatibilidad con sistemas viejos o políticas que bloquean CIM); si ambos fallan, devuelve `$null` en vez de tirar una excepción. Prácticamente todos los colectores parten de un `Get-CimSafe`.
- **`Get-PropValue`**: dado un objeto y una lista de nombres de propiedad candidatos, devuelve el primero que no sea `$null` ni string vacío. Sirve para manejar los casos donde distintas versiones de Windows exponen el mismo dato con nombres distintos (ej. `DriverVersionString` vs `DriverVersion`).
- **`Format-Value`**: convierte cualquier valor crudo en un string confiable para mostrar. Si es `$null`/vacío devuelve `"Unknown"`. Además filtra "basura" típica de tablas SMBIOS mal rellenadas por el fabricante (`"To Be Filled By O.E.M."`, `"Default string"`, `"System Serial Number"`, etc.) y las convierte también en `"Unknown"` en vez de mostrarlas tal cual.
- **`Format-Bytes`**: pasa bytes a KB/MB/GB/TB legible.
- **`ConvertTo-DateTimeSafe`** / **`Format-Date`**: WMI a veces devuelve fechas como objeto `[datetime]` y a veces como string DMTF (`20240101000000.000000+000`, típico del fallback vía `Get-WmiObject`). Estas funciones normalizan ambos casos a un `[datetime]` real o `$null`.
- **`Format-Uptime`**: convierte un `[timespan]` a `"Xd Yh Zm"`.
- **`Get-Ordinal`**: convierte un número a ordinal en inglés (`1` → `1st`, `12` → `12th`). Se usa para mostrar la generación estimada de CPU ("Intel 12th Gen").

## Pipeline de salida (consola + TXT)

El diseño clave acá: **todo lo que se imprime en consola pasa por `Out-Line`, que a la vez lo agrega al buffer de texto**. Así el reporte de consola y el TXT exportado nunca pueden desincronizarse, porque es literalmente la misma fuente.

- **`Out-Line`**: imprime una línea (con color, salvo `-NoColor`) y la agrega a `$Script:TxtBuffer`.
- **`Get-ValueColor`**: decide el color de un valor según su contenido (verde si dice "Healthy/OK/Enabled...", amarillo si "Warning/Degraded...", rojo si "Critical/Failed...", gris si "Unknown..."). Es puro pattern-matching sobre el texto ya formateado.
- **`Out-KV`**: imprime un par `Label: Value` alineado (columna fija de ~28 caracteres), coloreando el valor con `Get-ValueColor`.
- **`Out-SectionHeader`**: dibuja el marco de caja (`╔═══╗`) con el título de la sección en mayúsculas.
- **`Get-SingularLabel`**: cuando hay que renderizar una lista (ej. `"Modules"`, `"Disks"`, `"GPUs"`), esta función devuelve el singular correcto para numerar cada ítem (`"Module 1"`, `"Disk 2"`, etc.), con un mapa de excepciones para plurales irregulares.
- **`Write-KVBlock`**: el renderer genérico y recursivo. Recibe el diccionario `[ordered]@{}` de cualquier sección y lo recorre:
  - Si un valor es otro diccionario → lo indenta y se llama a sí mismo recursivamente.
  - Si es una lista de diccionarios (ej. la lista de módulos de RAM o discos) → numera cada ítem y recursa.
  - Si es una lista simple → la junta con comas.
  - Si es un valor simple → lo imprime con `Out-KV`.

  Gracias a esto, **ningún colector necesita saber cómo se dibuja nada**: solo arma un diccionario ordenado y `Write-KVBlock` lo pinta solo, sin importar cuántos niveles de anidamiento tenga.

## Cachés perezosas compartidas

- **`Get-DriverIndex`**: la primera vez que se llama, hace un único `Get-CimSafe 'Win32_PnPSignedDriver'` y arma un diccionario indexado por `DeviceID`. Las llamadas siguientes reutilizan `$Script:DriverIndex` en vez de volver a consultar WMI (esa consulta es lenta y se necesita para GPU, red, PCI, etc.).
- **`Get-DriverInfoFor`**: dado un `DeviceID`, busca en el índice y devuelve versión/fecha/proveedor del driver.

## Detección de enlace PCIe

Windows expone la velocidad y el ancho del enlace PCIe de cada dispositivo como propiedades PnP (`DEVPKEY_PciDevice_CurrentLinkSpeed/Width` y `MaxLinkSpeed/Width`), consultables sin admin con `Get-PnpDeviceProperty`.

- **`Get-PcieLinkInfo`**: dado un `PNPDeviceID`, devuelve generación y líneas actuales y máximas (`Gen3 x4 (device capable of Gen4 x4)`). Detalles importantes:
  - La velocidad viene codificada según la spec PCIe (`1` = Gen1 2.5 GT/s ... `6` = Gen6 64 GT/s), mapeada con `$Script:PcieGenMap`.
  - `MaxLinkSpeed/Width` describen la **capacidad del dispositivo**, no la del slot: un SSD Gen4 en una placa Gen3 reporta máximo Gen4 pero negocia Gen3. El texto lo deja claro ("device capable of").
  - Los discos NVMe no llevan estas propiedades en su nodo de disco (`SCSI\...`); la función sube por la cadena de padres PnP (`DEVPKEY_Device_Parent`, hasta 3 saltos) hasta encontrar el nodo `PCI\` de la controladora.
- **`Get-BoardPcieGeneration`** (cacheada en `$Script:BoardPcieGen`): estima la generación PCIe de la placa. Primero pregunta a los *root ports* PCIe (su máximo sí describe el slot); si la plataforma no rellena esas propiedades (típico en AMD), cae a la velocidad **negociada** más alta observada en endpoints (GPU, controladoras de almacenamiento/red), etiquetada como "the board may support more".

## Colectores de secciones

Cada sección tiene su propia función `Get-XxxInfo`, ubicada en el bloque `SECTION COLLECTORS`. Todas siguen el mismo patrón: consultar WMI/CIM (con fallbacks), interpretar los códigos numéricos que WMI devuelve, degradar con gracia si falta un permiso, y devolver un `[ordered]@{}`.

### Sistema (`Get-SystemInfo`)
Junta `Win32_ComputerSystem`, `Win32_ComputerSystemProduct`, `Win32_OperatingSystem`, `Win32_BIOS` y `Win32_Processor`. Funciones de apoyo:
- `Get-SecureBootState`: intenta `Confirm-SecureBootUEFI` (requiere admin); si falla, lee el espejo en el registro (`HKLM:\...\SecureBoot\State`), que no requiere admin.
- `Get-FirmwareMode`: determina UEFI vs Legacy BIOS vía `PEFirmwareType` en el registro.
- `Get-TpmInfo`: intenta `Win32_Tpm` (namespace WMI de seguridad, normalmente admin-only); si falla, busca el dispositivo TPM como `Win32_PnPEntity` y extrae la versión del nombre con regex; si eso también falla, solo confirma presencia vía registro.
- `Get-BitLockerState`: `Get-BitLockerVolume` requiere admin, así que si falla cae a una consulta COM (`Shell.Application`) que no lo requiere, y traduce los códigos numéricos (`0`-`6`) al estado en texto.
- `Get-ActivationStatus`: lee `SoftwareLicensingProduct` filtrando por el GUID de aplicación de Windows y traduce `LicenseStatus` (0-6) a texto.
- `Test-Win11Compatibility`: evalúa los 6 requisitos base de Windows 11 (TPM 2.0, UEFI, Secure Boot capaz, CPU 2+ núcleos/1+ GHz, 64-bit, 4+ GB RAM, 64+ GB de disco) y arma un veredicto (`Pass`/`Fail`/`Unknown`) que después reutilizan el health check y el buyer analysis vía `$Script:Raw.Win11Verdict`.

### CPU (`Get-CpuInfo`)
- `Get-CpuGeneration`: adivina la generación del CPU a partir del nombre comercial, con regex específicas para Intel Core (`i5-12400` → "12th Gen"), Intel Core Ultra, AMD Ryzen (con mapa de arquitectura Zen por serie), EPYC, Xeon, Celeron/Pentium/Atom y Snapdragon.
- `Get-CpuFeatureSet`: detecta soporte de SSE/AVX/AES-NI. En PowerShell 7+ usa las clases `System.Runtime.Intrinsics.X86.*` del .NET moderno (respuesta exacta). En PowerShell 5.1 no existen esas clases, así que declara en runtime un P/Invoke a `kernel32!IsProcessorFeaturePresent` vía `Add-Type` y consulta las constantes de característica del CPU (nota: AES-NI no tiene constante de Win32, por eso queda "Unknown" en 5.1).
- Cálculo de caché L1/L2/L3 a partir de `Win32_CacheMemory`, clasificando por `Purpose`/`Level` porque varía entre fabricantes.
- Virtualización: si `VirtualizationFirmwareEnabled` viene en `$false` pero Hyper-V ya está corriendo (`HypervisorPresent`), lo reporta como habilitado igual, porque el hypervisor "esconde" el flag de firmware una vez activo. Mismo criterio se aplica a SLAT/VMX, que WMI suele reportar `False` erróneamente cuando Hyper-V o el aislamiento de núcleo están activos.
- `Get-MicrocodeRevision`: lee el binario `Update Revision`/`Update Signature` de `HKLM:\HARDWARE\DESCRIPTION\System\CentralProcessor\0` directamente (sin pasar por `Get-PropValue`, para no perder el tipo `byte[]`) y lo interpreta como Intel (8 bytes, revisión en el dword alto) o AMD (4 bytes).

### Placa base (`Get-MotherboardInfo`)
Combina `Win32_BaseBoard` y `Win32_BIOS`. `Get-ChipsetGuess` intenta extraer el chipset a partir del texto del modelo de placa con regex (`X570`, `B450M`, `TRX40`, etc.), porque WMI no expone el chipset directamente.

### RAM (`Get-RamInfo`)
- `Get-DdrGeneration`: traduce `SMBIOSMemoryType`/`MemoryType` (códigos SMBIOS 20-35) a DDR/DDR2/.../DDR5/LPDDR; si el código no está mapeado, estima la generación a partir de la velocidad (heurística de rangos JEDEC).
- Por cada módulo instalado calcula: rank (`Attributes`), si es ECC (comparando `TotalWidth` vs `DataWidth`), voltaje, form factor (mapa de códigos SMBIOS).
- `Get-MemoryChannelId` extrae el canal de cada módulo desde `BankLabel`/`DeviceLocator` con varias familias de patrones reales de SMBIOS (`ChannelA-DIMM0`, `P0 CHANNEL A`, `CH A`, `DIMM_A1`, slots `A1`/`B2`, y `BANK n` emparejando bancos consecutivos). Con los canales distintos se arma la configuración (`Dual channel (channels populated: A, B)`), se detecta el caso "varios módulos en el mismo canal" (advertencia del health check) y, si las etiquetas no dicen nada, se cae a la heurística por número de módulos, marcada como estimación.
- Slots libres = slots totales (`Win32_PhysicalMemoryArray.MemoryDevices`) menos módulos instalados.
- Guarda en `$Script:Raw`: `RamGB`, `MemoryModules`, `RamSpeed`, `DdrGen`, `TotalSlots`, `FreeSlots`, `MaxRamGB`, `ChannelCount`. Todo esto es lo que después usa el buyer analysis para decir "puedes expandir sin sacar módulos" o similar.

### Almacenamiento (`Get-StorageInfo`)
La sección más compleja. Cruza tres fuentes por número de disco: `Win32_DiskDrive` (WMI clásico), `Get-PhysicalDisk`/`Get-StorageReliabilityCounter` (Storage Management, moderno, requiere admin para SMART detallado) y `Get-Disk`.

**Clasificación por capas**: cada disco se identifica combinando, en orden de confianza: `BusType` de `Get-PhysicalDisk` (acepta tanto el string como el código numérico de `MSFT_PhysicalDisk`, ej. 17 = NVMe), el `PNPDeviceID` (los NVMe exponen `VEN_NVME` incluso sin Storage Management), `MediaType`, `SpindleSpeed` (0 RPM = sólido) y, como último recurso, el nombre del modelo. El resultado distingue `NVMe SSD`, `SATA SSD`, `External SSD (USB)`, `HDD`, `External HDD (USB)` y `eMMC / SD storage`. A los NVMe internos se les añade la fila `PCIe Link` vía `Get-PcieLinkInfo`.

**Atributos SMART decodificados**: `Get-SmartDataIndex` consulta una sola vez `MSStorageDriver_FailurePredictData` y `..._FailurePredictThresholds` (`root\wmi`, normalmente solo admin) indexando por `InstanceName` (que coincide con el `PNPDeviceID`). `Convert-SmartVendorData` parsea el blob de 512 bytes del formato ATA: 30 entradas de 12 bytes desde el offset 2 (`id, flags[2], value, worst, raw[6 LE]`); el blob de umbrales comparte el layout con el umbral en el byte 1. Cada atributo presente se muestra como `value X, worst Y, threshold Z, raw N`, con nombre legible (`$Script:SmartAttrNames`) e interpretación de unidades para los conocidos (horas, temperatura, LBAs). Además alimenta el health check: contadores de defectos crecidos (ids 5, 184, 187, 196, 197, 198 con raw > 0) o cualquier atributo con `value <= threshold` se agregan a `$Script:Raw.SmartIssues` como críticos. Los NVMe no exponen estas clases (su salud viene de los reliability counters) y sin admin se degrada a `"Unknown (requires Administrator)"`.

Identifica cuál es el disco de arranque cruzando la letra de `$env:SystemDrive` con `Get-Partition`. Lee salud SMART combinando `Win32_DiskDrive.Status` con `MSStorageDriver_FailurePredictStatus` (namespace `root/wmi`). El desgaste del SSD, horas de encendido y temperatura vienen de `Get-StorageReliabilityCounter`, que casi siempre requiere administrador. Si no está disponible, degrada explícitamente a `"Unknown (requires Administrator)"`. `Get-TrimState` corre `fsutil behavior query DisableDeleteNotify` y parsea la salida de texto para saber si TRIM está activo.

### GPU (`Get-GpuInfo`)
- `Get-GpuVram`: `Win32_VideoController.AdapterRAM` es un entero de 32 bits, así que se satura en 4 GB para tarjetas modernas. Por eso primero intenta leer el valor real de 64 bits (`HardwareInformation.qwMemorySize`) directo del registro del driver, buscando la clave cuya `DriverDesc` coincida con el nombre de la GPU; si no lo encuentra, cae al valor de WMI y avisa si probablemente está capado.
- `Test-GpuIntegrated`: clasifica integrada/dedicada con reglas por fabricante (NVIDIA siempre dedicada; Intel dedicada solo si el nombre dice "Arc"; AMD integrada si el nombre calza con los patrones típicos de gráficos Vega/Radeon Graphics integrados; Qualcomm/Adreno integrada).
- Cada GPU con `PNPDeviceID` PCI muestra su `PCIe Link` (vía `Get-PcieLinkInfo`). Si una GPU dedicada negocia menos líneas de las que soporta, se guarda una nota en `$Script:Raw.GpuLinkNotes` que el health check convierte en un INFO (con la salvedad de que algunas GPUs bajan el enlace en reposo).

### Red (`Get-NetworkInfo`)
Camino principal: `Get-NetAdapter` + `Get-NetIPConfiguration` (cmdlets modernos de NetTCPIP), filtrando solo interfaces físicas (`HardwareInterface`). Si esos cmdlets no existen (sistemas más viejos o sin el módulo), cae a un fallback 100% CIM con `Win32_NetworkAdapter` + `Win32_NetworkAdapterConfiguration`. El tipo de adaptador (Ethernet/Wi-Fi/Bluetooth) se infiere de `PhysicalMediaType` y de palabras clave en la descripción. Bluetooth se detecta buscando entre los `Win32_PnPEntity` de clase `Bluetooth`, filtrando por regex los que son solo perfiles/servicios/enumeradores (no el radio en sí).

### USB (`Get-UsbInfo`)
Deduce la versión de USB soportada (1.1/2.0/3.x/USB4) a partir del nombre del controlador (`EHCI` = 2.0, `xHCI`/"eXtensible" = 3.x, etc.). Lista los dispositivos USB conectados filtrando hubs raíz y controladores genéricos para no ensuciar la lista con ruido.

### PCI (`Get-PciInfo`)
Lista todos los `Win32_PnPEntity` cuyo `DeviceID` empieza con `PCI\`. El estado "Problem" se determina por `ConfigManagerErrorCode` distinto de cero (el código estándar de Windows para "este dispositivo tiene un problema"). Usa `Get-DriverInfoFor` (la caché de drivers) para mostrar versión y fecha del driver de cada dispositivo.

### Pantalla (`Get-DisplayInfo`)
Usa las clases WMI del namespace `root/wmi`: `WmiMonitorID` (identidad EDID) y `WmiMonitorBasicDisplayParams` (tamaño físico). Estas clases devuelven texto como array de códigos de caracteres (`byte[]`) en vez de string, así que `ConvertFrom-MonitorCharArray` reconstruye el string filtrando los ceros de relleno. El tamaño diagonal se calcula con Pitágoras a partir del alto y ancho físico en centímetros reportado por EDID.

### Batería, Audio y Sensores
- **Batería**: capacidad de diseño vs. capacidad de carga completa para estimar desgaste, ciclos de carga si están disponibles.
- **Audio**: dispositivos de audio con su driver asociado.
- **Sensores** (`Get-SensorInfo`): lee `MSAcpi_ThermalZoneTemperature` (namespace `root/wmi`), donde la temperatura viene en décimas de Kelvin. La conversión es `(raw / 10) - 273.15`. Se descartan lecturas fuera de un rango físicamente razonable (-50°C a 150°C), que suelen ser sensores rotos o placeholders del fabricante. Guarda la temperatura máxima en `$Script:Raw.CpuTempC` para que el health check pueda usarla. Ventiladores vía `Win32_Fan`, con nota explícita de que la velocidad en RPM casi nunca la expone WMI en hardware de consumo.

### Benchmark (`Get-BenchmarkInfo`, solo con `-Benchmark`)

Sección opcional que se agrega al final del `$plan`. Dos partes:

- **CPU (`Invoke-CpuBenchmark`)**: mide el throughput sostenido de SHA-256 sobre un búfer de 4 MB en memoria. Se usa hashing porque ejecuta código nativo del runtime (CNG), así que mide la CPU y no al intérprete de PowerShell. En 5.1 se usa `SHA256Cng` explícitamente (el `SHA256.Create()` de .NET Framework devuelve la implementación managed, mucho más lenta); en 7+ `Create()` ya es nativo. Primero un hilo (~1.5 s), después un runspace por procesador lógico vía `RunspacePool`, reportando MB/s totales y el factor de escalado.
- **Disco (`Invoke-DiskBenchmark` + `Initialize-DiskBenchNative`)**: benchmark honesto de la unidad que aloja el directorio temporal (normalmente la de arranque). `Initialize-DiskBenchNative` compila con `Add-Type` un helper C# que abre el archivo con `FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH` y un búfer alineado a sector con `VirtualAlloc` — sin eso, la caché de archivos de Windows infla los números hasta hacerlos inútiles. Mide escritura secuencial (256 MB en bloques de 1 MB, datos aleatorios para que la compresión de la controladora no haga trampa), lectura secuencial y lectura aleatoria 4K QD1 (2 s, reportada en IOPS). El archivo temporal se borra siempre en el `finally`; si no hay espacio o la compilación falla, la sección lo dice explícitamente en vez de fallar.

Los resultados van a `$Script:Raw` (`CpuStMBps`, `CpuMtMBps`, `DiskSeqRead`, `DiskSeqWrite`, `DiskRandIops`) para que el health check pueda avisar de SSDs rindiendo a nivel de HDD y el buyer analysis los incluya.

## Health Check y Buyer Analysis

Estas dos funciones **no vuelven a consultar Windows**: solo leen `$Script:Raw`, el diccionario de hechos que cada colector fue llenando. Por eso corren después de que las 13 secciones ya se recolectaron.

- **`Get-HealthChecks`**: genera advertencias (`OK`/`INFO`/`WARN`/`CRIT`) comparando los valores en `$Script:Raw` contra umbrales fijos: BIOS con más de 3-5 años, un solo módulo de RAM (canal único), varios módulos compartiendo un solo canal, velocidad de RAM por debajo de lo típico para su generación, menos de 8 GB de RAM, ausencia de SSD, disco de arranque en HDD, problemas SMART (incluidos los atributos decodificados: sectores reasignados/pendientes o valores bajo su umbral), temperaturas de CPU/disco altas, virtualización desactivada, drivers de GPU con más de 900 días, GPU negociando menos líneas PCIe de las que soporta, resultados de benchmark anómalos (SSD leyendo a nivel de HDD, NVMe lento, IOPS 4K bajos), desgaste de batería (≥20% warning, ≥40% crítico), Windows no activado, Legacy BIOS, Secure Boot desactivado, no cumple Windows 11, y dispositivos PCI con problemas de driver.
- **`Get-BuyerAnalysis`**: arma una lista de observaciones neutras y objetivas (sin "bueno"/"malo") pensadas para apoyar una decisión de compra: slots de RAM libres, si el disco ya es NVMe y su enlace PCIe, generación PCIe de la placa, modo de canales de la RAM, tipo de disco de arranque, modo de firmware, presencia de TPM 2.0, antigüedad de BIOS, veredicto de compatibilidad con Windows 11, retención de batería, núcleos de CPU y resultados del benchmark si se ejecutó.

La separación entre estas dos funciones es intencional: el *health check* juzga ("esto es un problema"), el *buyer analysis* solo describe hechos ("esto es así, decide tú").

## Resumen y exportación

- **`Out-HealthSection`** / **`Out-AnalysisSection`**: renderizan las listas de arriba con color según severidad.
- **`Out-SummarySection`**: arma un resumen de una pantalla (fabricante+modelo, SO, CPU, RAM, disco de arranque, GPU) y cuenta cuántos issues de cada severidad hubo, además del tiempo total que tardó la inspección (`Stopwatch`).
- **`Export-Reports`**: si se pasó `-Json`, `-Txt` y/o `-Html`, escribe los archivos en `$OutputPath` (o la carpeta del script si no se especificó). El JSON incluye metadata (versión, timestamp, si corrió como admin) más el reporte completo, el health check y el buyer analysis, serializado con `ConvertTo-Json -Depth 12` (la profundidad alta es necesaria porque hay secciones con varios niveles de anidamiento, como RAM → Modules → cada módulo). El TXT es simplemente el contenido de `$Script:TxtBuffer` volcado a disco: exactamente lo mismo que se vio en consola, sin colores.

### Informe HTML

El HTML se genera desde **las mismas estructuras de datos** que la consola y el JSON, nunca desde texto formateado:

- **`Add-HtmlKVBlock`** es el gemelo HTML de `Write-KVBlock`: recorre el mismo `[ordered]@{}` con la misma recursión (diccionario anidado → sub-bloque, lista de diccionarios → ítems numerados, lista simple → valores unidos por comas). Si agregas un dato a un colector, aparece en el HTML solo, igual que en consola.
- **`Get-ValueCssClass`** reutiliza `Get-ValueColor` (el mismo pattern-matching de colores de consola) y lo traduce a clases CSS, así el HTML y la consola nunca disienten sobre qué es verde/amarillo/rojo.
- **`ConvertTo-HtmlReport`** arma la página completa: tarjetas de resumen (máquina, CPU, RAM, disco de arranque, GPU, veredicto de salud), health check y buyer analysis primero, y todas las secciones como `<details>` plegables (USB y PCI empiezan plegadas por ruidosas). Todo valor pasa por `Convert-HtmlText` (`WebUtility.HtmlEncode`). La página es autónoma: CSS embebido, sin JavaScript, sin recursos externos, con tema claro/oscuro automático vía `prefers-color-scheme`.

## Función Main

**`Invoke-PCInspector`** es el punto de entrada real. Hace, en orden:

1. Imprime el banner y avisa si no está corriendo como administrador.
2. Define `$plan`: un array de 13 objetos `@{ Key; Title; Fn }`, uno por sección (más `Benchmark` al final si se pasó `-Benchmark`), **en el orden en que deben ejecutarse y mostrarse** (System primero porque llena datos de `$Script:Raw` que otras secciones, como el veredicto de Windows 11, necesitan; Storage antes que Sensors porque la temperatura de disco se usa en Sensors; Benchmark al final porque es lo más lento).
3. Ejecuta cada `Fn` del plan dentro de un `try/catch` individual. Si una sección entera falla, el resto de la inspección continúa igual y esa sección queda como `"Unknown (collection failed: ...)"`, actualizando una barra de progreso (`Write-Progress`).
4. Renderiza las 13 secciones ya recolectadas con `Out-SectionHeader` + `Write-KVBlock`.
5. Corre `Get-HealthChecks` y `Get-BuyerAnalysis` (también protegidos con `try/catch`).
6. Imprime el resumen final y exporta si corresponde.

Al final del archivo, todo el `Invoke-PCInspector` está envuelto en un `try/catch` de última instancia: si algo explota de forma totalmente inesperada, se imprime el error y el script sale con código `1` en vez de mostrar una traza cruda de PowerShell.

## Patrones de diseño que se repiten

Vale la pena nombrarlos explícitamente porque se repiten decenas de veces y entenderlos de una acelera leer cualquier función nueva:

1. **Fallback en cascada**: CIM moderno → WMI clásico → cmdlet específico → registro → COM. Nunca se asume que una sola fuente de datos vaya a estar disponible.
2. **Degradación explícita, nunca silenciosa**: cuando algo requiere admin y no lo hay, el texto dice literalmente `"Unknown (requires Administrator)"` en vez de mostrar un campo vacío o un `$null` crudo.
3. **`$Script:Raw` como capa de hechos, separada de la capa de presentación**: los colectores no solo "imprimen bonito", también dejan datos crudos reutilizables para el health check y el buyer analysis.
4. **Todo pasa por `Invoke-Safe` o un `try/catch` propio**: ninguna llamada a WMI/registro/cmdlet externo puede tumbar el script completo.
5. **Un único renderer genérico (`Write-KVBlock`)**: los colectores nunca decidan cómo se ve algo en pantalla, solo devuelven datos estructurados.

## Cómo agregar un dato nuevo

Ejemplo: quieres agregar la velocidad de escritura secuencial de cada disco a la sección Storage.

1. Dentro de `Get-StorageInfo`, agrega la consulta (con `Invoke-Safe`/`Get-CimSafe` según corresponda).
2. Agrega la clave al `[ordered]@{}` que arma cada disco (ej. `'Sequential Write' = Format-Value $valor 'MB/s'`).
3. Si el dato es útil para el health check o el buyer analysis, guárdalo también en `$Script:Raw` (ej. `$Script:Raw.SeqWriteMBs`).
4. No necesitas tocar nada de renderizado: `Write-KVBlock` lo va a mostrar automáticamente. Tampoco necesitas tocar el export: `ConvertTo-Json` serializa el diccionario completo solo.
5. Si agregaste algo a `$Script:Raw`, opcionalmente suma una regla nueva en `Get-HealthChecks` o `Get-BuyerAnalysis` que lo use.

Ese es todo el ciclo: es el mismo patrón que siguen las 13 secciones existentes.
