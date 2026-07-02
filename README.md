# AES féléves projekt / AES semester project

Készítő / Author: **Baba Levente**

Ez a repository egy több részből álló AES-alapú projektet tartalmaz:
- natív CPU-s AES könyvtárat,
- OpenCL-alapú gyorsított AES megoldást,
- egy WinForms felhasználói felületet fájlműveletekhez és benchmarkhoz,
- valamint a mérési eredményekből készített dokumentációt.

This repository contains a multi-part AES project with:
- a native CPU AES library,
- an OpenCL-accelerated AES implementation,
- a WinForms user interface for file operations and benchmarking,
- and a documentation project built from benchmark results.

Nyelvek / Languages:
- [Magyar](#magyar)
- [English](#english)

---

## Magyar

### Áttekintés

A projekt fő célja az AES különböző megvalósításainak összehasonlítása és bemutatása:
- natív CPU-s megoldás,
- OpenCL-alapú gyorsított megoldás,
- kezelhető grafikus felület,
- benchmark és CSV export/import,
- mérési eredményekből készült dokumentáció.

A repository fő részei:
- [`aeslib`](./aeslib) – natív CPU-s AES könyvtár
- [`crypto_aes_opencl`](./crypto_aes_opencl) – OpenCL-es AES könyvtár
- [`kernel_loader`](./kernel_loader) – OpenCL kernel betöltő segédkönyvtár
- [`AES.WinForms`](./AES.WinForms) – Windows-os grafikus felület
- [`Docs`](./Docs) – a dokumentáció forrása és a mérési statisztikák

### Mappa- és projektstruktúra

#### [`aeslib`](./aeslib)
A CPU-s kriptográfiai komponens.

Fontosabb részek:
- [`include/aes.h`](./aeslib/include/aes.h) – AES alap API
- [`include/aes_ctr.h`](./aeslib/include/aes_ctr.h) – AES-CTR
- [`include/aes_gcm.h`](./aeslib/include/aes_gcm.h) – AES-GCM
- [`include/cbc.h`](./aeslib/include/cbc.h) – AES-CBC
- [`include/crypto_ffi.h`](./aeslib/include/crypto_ffi.h) – egyszerűbb FFI / DLL API
- [`src`](./aeslib/src) – implementációk
- [`tests/test_aes.c`](./aeslib/tests/test_aes.c) – tesztprogram
- [`tests/bench_aes.c`](./aeslib/tests/bench_aes.c) – benchmark
- [`tests/profile_aes.c`](./aeslib/tests/profile_aes.c) – profilozó buildhez készült futtatható teszt
- [`README_PROFILING.txt`](./aeslib/README_PROFILING.txt) – profilozási tudnivalók

Támogatott algoritmusok:
- AES-CBC
- AES-CTR
- AES-GCM

#### [`kernel_loader`](./kernel_loader)
Segédkönyvtár OpenCL kernel forrásfájlok beolvasásához és betöltéséhez.

Fontosabb részek:
- [`include/kernel_loader.h`](./kernel_loader/include/kernel_loader.h)
- [`src/kernel_loader.c`](./kernel_loader/src/kernel_loader.c)

#### [`crypto_aes_opencl`](./crypto_aes_opencl)
Az OpenCL-es gyorsított megoldás.

Fontosabb részek:
- [`include/crypto_ffi_opencl.h`](./crypto_aes_opencl/include/crypto_ffi_opencl.h) – DLL / FFI API
- [`include/opencl_aes_ctr.h`](./crypto_aes_opencl/include/opencl_aes_ctr.h)
- [`include/opencl_aes_gcm.h`](./crypto_aes_opencl/include/opencl_aes_gcm.h)
- [`kernels/aes_ctr_xor.cl`](./crypto_aes_opencl/kernels/aes_ctr_xor.cl)
- [`kernels/gcm_ghash_chunk.cl`](./crypto_aes_opencl/kernels/gcm_ghash_chunk.cl)
- [`src`](./crypto_aes_opencl/src) – implementációk
- [`tests/test_opencl_aes.c`](./crypto_aes_opencl/tests/test_opencl_aes.c)
- [`tests/bench_opencl_aes.c`](./crypto_aes_opencl/tests/bench_opencl_aes.c)
- [`tests/profile_opencl_aes.c`](./crypto_aes_opencl/tests/profile_opencl_aes.c)
- [`README_PROFILING.txt`](./crypto_aes_opencl/README_PROFILING.txt) – OpenCL profilozási jegyzetek

Támogatott OpenCL algoritmusok:
- AES-CTR
- AES-GCM

Megjegyzés:
- az OpenCL rész a [`aeslib`](./aeslib) és a [`kernel_loader`](./kernel_loader) projektekre épül;
- a build során a szükséges DLL-ek és a `kernels` mappa a kimeneti könyvtárba másolódnak.

#### [`AES.WinForms`](./AES.WinForms)
Windows-os felhasználói felület a projekt bemutatására.

Fontosabb részek:
- [`AES.WinForms/AES.WinForms.csproj`](./AES.WinForms/AES.WinForms/AES.WinForms.csproj)
- [`AES.WinForms/Form1.cs`](./AES.WinForms/AES.WinForms/Form1.cs)
- [`AES.WinForms/Native`](./AES.WinForms/AES.WinForms/Native) – natív DLL hívások
- [`AES.WinForms/Services`](./AES.WinForms/AES.WinForms/Services) – benchmark, CSV, jelszó-származtatás, fájlműveletek
- [`AES.WinForms/Models`](./AES.WinForms/AES.WinForms/Models) – modellek és enumok
- [`AES.WinForms.slnx`](./AES.WinForms/AES.WinForms.slnx) – solution

A felület fő funkciói:
- egyetlen fájl titkosítása és visszafejtése,
- CPU és OpenCL motorok használata,
- benchmark futtatása több motorral,
- CSV export/import,
- OpenCL és rendszerdiagnosztika.

Megjegyzés:
- a natív CPU útvonal CBC, CTR és GCM algoritmusokat támogat;
- az OpenCL útvonal CTR és GCM algoritmusokat támogat;
- a benchmark felületen a menedzselt .NET AES referenciaútvonalként is szerepel bizonyos esetekben.

#### [`Docs`](./Docs)
A projekt dokumentációja és a benchmark statisztikák.

Fontosabb részek:
- [`Docs.tex`](./Docs/Docs.tex) – fő LaTeX dokumentum
- [`sections`](./Docs/sections) – fejezetek
- [`Stats`](./Docs/Stats) – mérési CSV-k
- [`scripts/generate_stats.py`](./Docs/scripts/generate_stats.py) – statisztikagenerálás
- [`Makefile`](./Docs/Makefile) – dokumentum build

### Követelmények

#### Általános
- `make`
- C fordító (`gcc`, `clang`, MinGW-w64 vagy kompatibilis toolchain)

#### OpenCL-hez
- OpenCL runtime / ICD loader telepítve
- OpenCL fejlécek és linkelhető könyvtár (`OpenCL`)

#### WinForms felülethez
- Windows
- .NET SDK, amely támogatja a projektben beállított `net10.0-windows` célkeretrendszert
- elérhető `make` parancs a PATH-ban

#### Dokumentációhoz
- Python
- LuaLaTeX

### Build útmutató

### 1. `aeslib` build

Alap build:

```bash
cd aeslib
make all
```

Kimenetek tipikusan:
- `build/bin/test_aes`
- `build/bin/bench_aes`
- megosztott könyvtár (`.dll` vagy `.so`)
- statikus könyvtár (`.a`)

További hasznos célok:

```bash
make lib
make shared
make test
make bench
make clean
```

Profilozós build:

```bash
make clean
make PROF=1 all
```

Gyorsabb optimalizált build:

```bash
make clean
make FAST=1 all
```

Windows x64 MinGW-w64 példa:

```bash
make clean
make all BUILD_SUBDIR=x64 CC=x86_64-w64-mingw32-gcc AR=x86_64-w64-mingw32-ar
```

Windows x86 MinGW-w64 példa:

```bash
make clean
make all BUILD_SUBDIR=x86 CC=i686-w64-mingw32-gcc AR=i686-w64-mingw32-ar
```

### 2. `kernel_loader` build

```bash
cd kernel_loader
make all
```

Windows x64 példa:

```bash
make clean
make all BUILD_SUBDIR=x64 CC=x86_64-w64-mingw32-gcc AR=x86_64-w64-mingw32-ar
```

### 3. `crypto_aes_opencl` build

Az OpenCL projekt a szükséges függőségeket is buildeli.

```bash
cd crypto_aes_opencl
make all
```

Hasznos célok:

```bash
make lib
make shared
make test
make bench
make clean
```

Profilozós build:

```bash
make clean
make PROF=1 all
```

Windows x64 példa:

```bash
make clean
make all BUILD_SUBDIR=x64 CC=x86_64-w64-mingw32-gcc AR=x86_64-w64-mingw32-ar
```

Windows x86 példa:

```bash
make clean
make all BUILD_SUBDIR=x86 CC=i686-w64-mingw32-gcc AR=i686-w64-mingw32-ar
```

Szükség esetén megadható OpenCL linkelés külön is:

```bash
make all OPENCL_LIBS="-lOpenCL"
```

Hasznos OpenCL környezeti változók:
- `CRYPTO_OCL_PLATFORM_INDEX`
- `CRYPTO_OCL_DEVICE_INDEX`
- `CRYPTO_OCL_LOCAL_SIZE`
- `CRYPTO_OCL_GHASH_CHUNK_BLOCKS`
- `CRYPTO_OCL_KERNEL_DIR`

Fontos:
- a `kernels` mappának a futtatható állomány mellett elérhetőnek kell lennie;
- x86 build esetén 32 bites OpenCL runtime szükséges;
- x64 build esetén 64 bites OpenCL runtime szükséges.

### 4. `AES.WinForms` build

A WinForms projekt Windows alatt build közben meghívja a natív OpenCL projekt buildjét is, majd a szükséges DLL-eket és kernel fájlokat a kimeneti mappába másolja.

Solution build x64-re:

```bash
dotnet build AES.WinForms/AES.WinForms.slnx -c Release -p:Platform=x64
```

Solution build x86-ra:

```bash
dotnet build AES.WinForms/AES.WinForms.slnx -c Release -p:Platform=x86
```

Ha a rendszereden a `make` parancs neve például `mingw32-make`, akkor ezt külön megadhatod:

```bash
dotnet build AES.WinForms/AES.WinForms.slnx -c Release -p:Platform=x64 -p:NativeMakeCommand=mingw32-make
```

Megjegyzés:
- a projektfájl automatikusan a `crypto_aes_opencl` könyvtárban indítja a natív buildet;
- a futtatáshoz a kimásolt natív DLL-eknek és a `kernels` almappának a WinForms kimeneti könyvtárban kell maradniuk.

### 5. Dokumentáció build

```bash
cd Docs
make
```

A generált PDF tipikus helye:
- `Docs/build/Docs.pdf`

A build a következőket végzi:
- futtatja a [`scripts/generate_stats.py`](./Docs/scripts/generate_stats.py) szkriptet,
- majd LuaLaTeX segítségével elkészíti a PDF-et.

### Futtatás és használat

#### Natív tesztek és benchmarkok

CPU-s könyvtár:

```bash
./aeslib/build/bin/test_aes
./aeslib/build/bin/bench_aes
```

OpenCL-es könyvtár:

```bash
./crypto_aes_opencl/build/bin/test_opencl_aes
./crypto_aes_opencl/build/bin/bench_opencl_aes
```

Windows alatt a futtatható fájlok `.exe` kiterjesztésűek.

#### WinForms felület

A felületben elérhető főbb munkafolyamatok:
- fájl titkosítása,
- fájl visszafejtése,
- benchmark futtatása,
- benchmark CSV exportálása,
- benchmark CSV visszatöltése,
- OpenCL diagnosztika.

A felület által létrehozott titkosított fájlcsomag fejlécben tárolja többek között:
- az algoritmust,
- a padding módot,
- a kulcsméretet,
- a PBKDF2 iterációszámot,
- a sót,
- az IV-et,
- GCM esetén a taget.

### Open source és licenc

Ez a projekt szabadon felhasználható open source projektként.

A repository a mellékelt [`LICENSE`](./LICENSE) fájl szerint használható, terjeszthető és módosítható.
A jelenlegi licenc: **MIT License**.

### Fontos megjegyzés

Ez a projekt elsősorban oktatási, demonstrációs és benchmark célokat szolgál.
Kriptográfiai vagy biztonsági szempontból érzékeny, éles környezetben történő használat előtt külön audit és alapos ellenőrzés javasolt.

---

## English

### Overview

The goal of this repository is to present and compare multiple AES-based implementations:
- a native CPU implementation,
- an OpenCL-accelerated implementation,
- a Windows desktop UI,
- benchmark and CSV export/import support,
- and documentation generated from measurement results.

Main repository parts:
- [`aeslib`](./aeslib) – native CPU AES library
- [`crypto_aes_opencl`](./crypto_aes_opencl) – OpenCL AES library
- [`kernel_loader`](./kernel_loader) – OpenCL kernel loading helper library
- [`AES.WinForms`](./AES.WinForms) – Windows desktop UI
- [`Docs`](./Docs) – documentation sources and benchmark data

### Project structure

#### [`aeslib`](./aeslib)
The CPU-side cryptography component.

Key parts:
- [`include/aes.h`](./aeslib/include/aes.h) – core AES API
- [`include/aes_ctr.h`](./aeslib/include/aes_ctr.h) – AES-CTR
- [`include/aes_gcm.h`](./aeslib/include/aes_gcm.h) – AES-GCM
- [`include/cbc.h`](./aeslib/include/cbc.h) – AES-CBC
- [`include/crypto_ffi.h`](./aeslib/include/crypto_ffi.h) – simplified FFI / DLL API
- [`src`](./aeslib/src) – implementations
- [`tests/test_aes.c`](./aeslib/tests/test_aes.c) – test program
- [`tests/bench_aes.c`](./aeslib/tests/bench_aes.c) – benchmark program
- [`tests/profile_aes.c`](./aeslib/tests/profile_aes.c) – profiling-oriented executable
- [`README_PROFILING.txt`](./aeslib/README_PROFILING.txt) – profiling notes

Supported algorithms:
- AES-CBC
- AES-CTR
- AES-GCM

#### [`kernel_loader`](./kernel_loader)
A helper library for reading and loading OpenCL kernel source files.

Key parts:
- [`include/kernel_loader.h`](./kernel_loader/include/kernel_loader.h)
- [`src/kernel_loader.c`](./kernel_loader/src/kernel_loader.c)

#### [`crypto_aes_opencl`](./crypto_aes_opencl)
The OpenCL-accelerated implementation.

Key parts:
- [`include/crypto_ffi_opencl.h`](./crypto_aes_opencl/include/crypto_ffi_opencl.h) – DLL / FFI API
- [`include/opencl_aes_ctr.h`](./crypto_aes_opencl/include/opencl_aes_ctr.h)
- [`include/opencl_aes_gcm.h`](./crypto_aes_opencl/include/opencl_aes_gcm.h)
- [`kernels/aes_ctr_xor.cl`](./crypto_aes_opencl/kernels/aes_ctr_xor.cl)
- [`kernels/gcm_ghash_chunk.cl`](./crypto_aes_opencl/kernels/gcm_ghash_chunk.cl)
- [`src`](./crypto_aes_opencl/src) – implementations
- [`tests/test_opencl_aes.c`](./crypto_aes_opencl/tests/test_opencl_aes.c)
- [`tests/bench_opencl_aes.c`](./crypto_aes_opencl/tests/bench_opencl_aes.c)
- [`tests/profile_opencl_aes.c`](./crypto_aes_opencl/tests/profile_opencl_aes.c)
- [`README_PROFILING.txt`](./crypto_aes_opencl/README_PROFILING.txt) – OpenCL profiling notes

Supported OpenCL algorithms:
- AES-CTR
- AES-GCM

Notes:
- the OpenCL project depends on [`aeslib`](./aeslib) and [`kernel_loader`](./kernel_loader);
- the build copies required DLLs/shared libraries and the `kernels` folder into the output directory.

#### [`AES.WinForms`](./AES.WinForms)
A Windows desktop UI used to demonstrate the project.

Key parts:
- [`AES.WinForms/AES.WinForms.csproj`](./AES.WinForms/AES.WinForms/AES.WinForms.csproj)
- [`AES.WinForms/Form1.cs`](./AES.WinForms/AES.WinForms/Form1.cs)
- [`AES.WinForms/Native`](./AES.WinForms/AES.WinForms/Native) – native DLL bindings
- [`AES.WinForms/Services`](./AES.WinForms/AES.WinForms/Services) – benchmark, CSV, password derivation, file operations
- [`AES.WinForms/Models`](./AES.WinForms/AES.WinForms/Models) – models and enums
- [`AES.WinForms.slnx`](./AES.WinForms/AES.WinForms.slnx) – solution file

Main UI features:
- single-file encryption and decryption,
- CPU and OpenCL engines,
- benchmark execution across multiple engines,
- CSV export/import,
- OpenCL and environment diagnostics.

Notes:
- the native CPU path supports CBC, CTR and GCM;
- the OpenCL path supports CTR and GCM;
- the benchmark UI also uses managed .NET AES as a reference path in supported scenarios.

#### [`Docs`](./Docs)
Documentation sources and benchmark statistics.

Key parts:
- [`Docs.tex`](./Docs/Docs.tex) – main LaTeX document
- [`sections`](./Docs/sections) – chapter files
- [`Stats`](./Docs/Stats) – benchmark CSV samples
- [`scripts/generate_stats.py`](./Docs/scripts/generate_stats.py) – statistics generator
- [`Makefile`](./Docs/Makefile) – documentation build

### Requirements

#### General
- `make`
- a C compiler (`gcc`, `clang`, MinGW-w64, or a compatible toolchain)

#### For OpenCL
- installed OpenCL runtime / ICD loader
- OpenCL headers and linkable library (`OpenCL`)

#### For the WinForms UI
- Windows
- a .NET SDK that supports the `net10.0-windows` target framework used by the project
- a working `make` command available in `PATH`

#### For the documentation
- Python
- LuaLaTeX

### Build guide

### 1. Build `aeslib`

Basic build:

```bash
cd aeslib
make all
```

Typical outputs:
- `build/bin/test_aes`
- `build/bin/bench_aes`
- a shared library (`.dll` or `.so`)
- a static library (`.a`)

Useful targets:

```bash
make lib
make shared
make test
make bench
make clean
```

Profiling build:

```bash
make clean
make PROF=1 all
```

Faster optimized build:

```bash
make clean
make FAST=1 all
```

Windows x64 MinGW-w64 example:

```bash
make clean
make all BUILD_SUBDIR=x64 CC=x86_64-w64-mingw32-gcc AR=x86_64-w64-mingw32-ar
```

Windows x86 MinGW-w64 example:

```bash
make clean
make all BUILD_SUBDIR=x86 CC=i686-w64-mingw32-gcc AR=i686-w64-mingw32-ar
```

### 2. Build `kernel_loader`

```bash
cd kernel_loader
make all
```

Windows x64 example:

```bash
make clean
make all BUILD_SUBDIR=x64 CC=x86_64-w64-mingw32-gcc AR=x86_64-w64-mingw32-ar
```

### 3. Build `crypto_aes_opencl`

The OpenCL project builds its required dependencies as well.

```bash
cd crypto_aes_opencl
make all
```

Useful targets:

```bash
make lib
make shared
make test
make bench
make clean
```

Profiling build:

```bash
make clean
make PROF=1 all
```

Windows x64 example:

```bash
make clean
make all BUILD_SUBDIR=x64 CC=x86_64-w64-mingw32-gcc AR=x86_64-w64-mingw32-ar
```

Windows x86 example:

```bash
make clean
make all BUILD_SUBDIR=x86 CC=i686-w64-mingw32-gcc AR=i686-w64-mingw32-ar
```

If needed, OpenCL linkage can be provided explicitly:

```bash
make all OPENCL_LIBS="-lOpenCL"
```

Useful OpenCL environment variables:
- `CRYPTO_OCL_PLATFORM_INDEX`
- `CRYPTO_OCL_DEVICE_INDEX`
- `CRYPTO_OCL_LOCAL_SIZE`
- `CRYPTO_OCL_GHASH_CHUNK_BLOCKS`
- `CRYPTO_OCL_KERNEL_DIR`

Important:
- the `kernels` folder must be available next to the executable;
- x86 builds require a 32-bit OpenCL runtime;
- x64 builds require a 64-bit OpenCL runtime.

### 4. Build `AES.WinForms`

On Windows, the WinForms project triggers the native OpenCL build during compilation, then copies the required native DLLs and kernel files into the UI output directory.

Build the solution for x64:

```bash
dotnet build AES.WinForms/AES.WinForms.slnx -c Release -p:Platform=x64
```

Build the solution for x86:

```bash
dotnet build AES.WinForms/AES.WinForms.slnx -c Release -p:Platform=x86
```

If your system exposes `make` as `mingw32-make`, you can pass it explicitly:

```bash
dotnet build AES.WinForms/AES.WinForms.slnx -c Release -p:Platform=x64 -p:NativeMakeCommand=mingw32-make
```

Notes:
- the project file automatically starts the native build inside `crypto_aes_opencl`;
- native DLLs and the `kernels` subfolder must remain in the WinForms output directory.

### 5. Build the documentation

```bash
cd Docs
make
```

Typical generated PDF path:
- `Docs/build/Docs.pdf`

The build process:
- runs [`scripts/generate_stats.py`](./Docs/scripts/generate_stats.py),
- then generates the PDF with LuaLaTeX.

### Running and usage

#### Native tests and benchmarks

CPU library:

```bash
./aeslib/build/bin/test_aes
./aeslib/build/bin/bench_aes
```

OpenCL library:

```bash
./crypto_aes_opencl/build/bin/test_opencl_aes
./crypto_aes_opencl/build/bin/bench_opencl_aes
```

On Windows, the executables use the `.exe` extension.

#### WinForms UI

Main supported workflows in the UI:
- file encryption,
- file decryption,
- benchmark execution,
- benchmark CSV export,
- benchmark CSV import,
- OpenCL diagnostics.

The encrypted file package created by the UI stores header metadata such as:
- algorithm,
- padding mode,
- key size,
- PBKDF2 iteration count,
- salt,
- IV,
- and, for GCM, the authentication tag.

### Open source and license

This project is available as an open source project.

It may be used, modified and redistributed under the terms of the included [`LICENSE`](./LICENSE) file.
The current license is the **MIT License**.

### Important note

This project is primarily intended for educational, demonstration and benchmarking purposes.
Before using it in a security-sensitive production environment, an independent audit and thorough review are strongly recommended.
