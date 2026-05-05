## DofusProcessHub (C++ / Qt 6 · Windows)

Proyecto autocontenido: `CMakeLists.txt`, `src/`, `third_party/minhook/`. La compilación local va a **`build/`** (ignorada por Git).

Aplicación pensada para **detectar procesos cuyo nombre contiene «Dofus»**, **selección automática**
si solo hay uno, tabla filtrada si hay varios, **parche IPv4 en RAM** del proceso seleccionado (servidor real → `127.0.0.1`)
y un **proxy TCP local** en **127.0.0.1:5555** que reenvía al upstream real. **No usa archivo hosts ni netsh.**

No sustituye aún todas las capacidades del `process_sniffer_gui.py` Python (BPF/Scapy, parche ☆iri, protobuf, sesión JSONL).
Para eso puedes seguir usando el Python en paralelo. Esta herramienta prioriza **UI más cuidada** y **automática con Dofus**.

### Requisitos

- **Windows 10/11**
- [CMake](https://cmake.org/download/) 3.20+
- **Qt 6** (Widgets + Network), por ejemplo el instalador en [qt.io](https://www.qt.io/download-qt-installer).
- Visual Studio **2019 / 2022** con compilador C++, o el kit que use tu instalador de Qt (`msvc2019_64` / `mingw`), etc.

Configura **`CMAKE_PREFIX_PATH`** al directorio kit de Qt, por ejemplo:

`C:/Qt/6.8.0/msvc2022_64`

Para **tu PC con Qt en `C:\Qt` (MinGW)**: ya se puede compilar **sin instalar Visual Studio** usando el CMake y MinGW que vienen con Qt.

1. Abre la carpeta del repo (`dc`) en el Explorador.
2. Doble clic en **`COMPILAR_CON_MI_QT.bat`** (recompila si cambias el código y copia DLL con `windeployqt`).
3. Doble clic en **`EJECUTAR_app.bat`** para abrir la app, o ve a `build\dofus_process_sniffer.exe`.

Si actualizas Qt a otra carpeta o versión (p. ej. `6.12.0`), abre `COMPILAR_CON_MI_QT.bat` con el bloc de notas y cambia las variables `QT_KIT`, `CMAKE_EXE`, etc. al inicio.

---

### Compilar manualmente sin el .bat

Desde la raíz del repo:

```powershell
cmake -B build -S . -DCMAKE_PREFIX_PATH="C:/Qt/6.8.0/msvc2022_64"
cmake --build build --config Release
```

El ejecutable quedará en `build/Release/dofus_process_sniffer.exe` (con MSVC multicongif) o en `build/` según tu generador.

### Uso rápido

1. Ejecutar **como administrador** (hace falta `OpenProcess` + escritura de memoria en Dofus).
2. **Actualizar lista** y **seleccionar** la fila de `Dofus.exe` (o el proceso del cliente).
3. Ajustar si hace falta la **IPv4 upstream** (p. ej. `18.202.11.172`) y puerto **5555**.
4. **Iniciar proxy**: parche IPv4 en RAM → **aborta sockets TCP IPv4 del juego al puerto upstream** (`SetTcpEntry`) → listener `127.0.0.1:5555` → el cliente reconecta contra la IP ya parcheada.
5. **Detener proxy** restaura los bytes originales en memoria (si el proceso sigue vivo) y cierra sockets.

### Notas

- El proxy admite **una sesión TCP** cliente a la vez.
- El **PID seleccionado** define en qué proceso se aplica el parche de memoria antes de abrir el listener.