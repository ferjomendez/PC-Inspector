# Arquitectura de PC Inspector

Este documento explica cómo está armado `PC-Inspector.ps1` por dentro: qué hace cada bloque de código, cómo se comunican entre sí, y qué patrones de diseño se repiten. El objetivo es que cualquiera pueda entender el script en 10-15 minutos y sentirse cómodo mandando un PR (agregar un nuevo dato, arreglar un fallback, sumar una advertencia al health check, etc.).

El script es un único archivo de ~1900 líneas de PowerShell puro. No hay módulos externos ni dependencias: todo vive en `PC-Inspector.ps1`.

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
              ├─ recorre $plan (13 secciones) y llama a cada Get-XxxInfo
              ├─ renderiza cada sección con Write-KVBlock
              ├─ Get-HealthChecks   → advertencias automáticas
              ├─ Get-BuyerAnalysis  → observaciones objetivas
              ├─ Out-SummarySection
              └─ Export-Reports (JSON/TXT si se pidió)
```

Cada `Get-XxxInfo` (System, CPU, Motherboard, RAM, Storage, GPU, Network, USB, PCI, Display, Battery, Audio, Sensors) es independiente y devuelve un `[ordered]@{}` (diccionario ordenado). Ese diccionario es la única interfaz entre "recolectar datos" y "mostrarlos": el mismo objeto se usa para pintar la consola, para el TXT y para el JSON.

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
    '^--?json$'      { $Json = $true }
    '^--?txt$'       { $Txt = $true }
    '^--?no-?color$' { $NoColor = $true }
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
- Por cada módulo instalado calcula: rank (`Attributes`), si es ECC (comparando `TotalWidth` vs `DataWidth`), voltaje, form factor (mapa de códigos SMBIOS), y detecta el canal de memoria parseando `BankLabel`/`DeviceLocator` en busca de un patrón `Channel-X`.
- Slots libres = slots totales (`Win32_PhysicalMemoryArray.MemoryDevices`) menos módulos instalados.
- Guarda en `$Script:Raw`: `RamGB`, `MemoryModules`, `RamSpeed`, `DdrGen`, `TotalSlots`, `FreeSlots`, `MaxRamGB`. Todo esto es lo que después usa el buyer analysis para decir "puedes expandir sin sacar módulos" o similar.

### Almacenamiento (`Get-StorageInfo`)
La sección más compleja. Cruza tres fuentes por número de disco: `Win32_DiskDrive` (WMI clásico), `Get-PhysicalDisk`/`Get-StorageReliabilityCounter` (Storage Management, moderno, requiere admin para SMART detallado) y `Get-Disk`. Clasifica cada disco como NVMe SSD / SSD / HDD combinando `BusType`, `MediaType` y `SpindleSpeed` (0 RPM = SSD), con un último recurso de detectar "SSD"/"NVMe"/"M.2" en el nombre del modelo. Identifica cuál es el disco de arranque cruzando la letra de `$env:SystemDrive` con `Get-Partition`. Lee salud SMART combinando `Win32_DiskDrive.Status` con `MSStorageDriver_FailurePredictStatus` (namespace `root/wmi`). El desgaste del SSD, horas de encendido y temperatura vienen de `Get-StorageReliabilityCounter`, que casi siempre requiere administrador. Si no está disponible, degrada explícitamente a `"Unknown (requires Administrator)"`. `Get-TrimState` corre `fsutil behavior query DisableDeleteNotify` y parsea la salida de texto para saber si TRIM está activo.

### GPU (`Get-GpuInfo`)
- `Get-GpuVram`: `Win32_VideoController.AdapterRAM` es un entero de 32 bits, así que se satura en 4 GB para tarjetas modernas. Por eso primero intenta leer el valor real de 64 bits (`HardwareInformation.qwMemorySize`) directo del registro del driver, buscando la clave cuya `DriverDesc` coincida con el nombre de la GPU; si no lo encuentra, cae al valor de WMI y avisa si probablemente está capado.
- `Test-GpuIntegrated`: clasifica integrada/dedicada con reglas por fabricante (NVIDIA siempre dedicada; Intel dedicada solo si el nombre dice "Arc"; AMD integrada si el nombre calza con los patrones típicos de gráficos Vega/Radeon Graphics integrados; Qualcomm/Adreno integrada).

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

## Health Check y Buyer Analysis

Estas dos funciones **no vuelven a consultar Windows**: solo leen `$Script:Raw`, el diccionario de hechos que cada colector fue llenando. Por eso corren después de que las 13 secciones ya se recolectaron.

- **`Get-HealthChecks`**: genera advertencias (`OK`/`INFO`/`WARN`/`CRIT`) comparando los valores en `$Script:Raw` contra umbrales fijos: BIOS con más de 3-5 años, un solo módulo de RAM (canal único), velocidad de RAM por debajo de lo típico para su generación, menos de 8 GB de RAM, ausencia de SSD, disco de arranque en HDD, problemas SMART, temperaturas de CPU/disco altas, virtualización desactivada, drivers de GPU con más de 900 días, desgaste de batería (≥20% warning, ≥40% crítico), Windows no activado, Legacy BIOS, Secure Boot desactivado, no cumple Windows 11, y dispositivos PCI con problemas de driver.
- **`Get-BuyerAnalysis`**: arma una lista de observaciones neutras y objetivas (sin "bueno"/"malo") pensadas para apoyar una decisión de compra: slots de RAM libres, si el disco ya es NVMe, tipo de disco de arranque, modo de firmware, presencia de TPM 2.0, antigüedad de BIOS, veredicto de compatibilidad con Windows 11, retención de batería, núcleos de CPU.

La separación entre estas dos funciones es intencional: el *health check* juzga ("esto es un problema"), el *buyer analysis* solo describe hechos ("esto es así, decide tú").

## Resumen y exportación

- **`Out-HealthSection`** / **`Out-AnalysisSection`**: renderizan las listas de arriba con color según severidad.
- **`Out-SummarySection`**: arma un resumen de una pantalla (fabricante+modelo, SO, CPU, RAM, disco de arranque, GPU) y cuenta cuántos issues de cada severidad hubo, además del tiempo total que tardó la inspección (`Stopwatch`).
- **`Export-Reports`**: si se pasó `-Json` y/o `-Txt`, escribe los archivos en `$OutputPath` (o la carpeta del script si no se especificó). El JSON incluye metadata (versión, timestamp, si corrió como admin) más el reporte completo, el health check y el buyer analysis, serializado con `ConvertTo-Json -Depth 12` (la profundidad alta es necesaria porque hay secciones con varios niveles de anidamiento, como RAM → Modules → cada módulo). El TXT es simplemente el contenido de `$Script:TxtBuffer` volcado a disco: exactamente lo mismo que se vio en consola, sin colores.

## Función Main

**`Invoke-PCInspector`** es el punto de entrada real. Hace, en orden:

1. Imprime el banner y avisa si no está corriendo como administrador.
2. Define `$plan`: un array de 13 objetos `@{ Key; Title; Fn }`, uno por sección, **en el orden en que deben ejecutarse y mostrarse** (System primero porque llena datos de `$Script:Raw` que otras secciones, como el veredicto de Windows 11, necesitan; Storage antes que Sensors porque la temperatura de disco se usa en Sensors).
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
