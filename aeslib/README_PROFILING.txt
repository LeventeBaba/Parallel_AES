Profiling / Benchmarking

Build (Windows MinGW):
  mingw32-make clean
  mingw32-make all

Outputs:
  build\bin\bench_aes.exe
  build\bin\test_aes.exe
  build\bin\crypto_aes.dll
  build\lib\libcrypto_aes.dll.a
  build\lib\libcrypto_aes.a

Run benchmark:
  build\bin\bench_aes.exe

Run profiler build:
  mingw32-make clean
  mingw32-make PROF=1 all
  build\bin\profile_aes.exe

Profiler output highlights:
  - AES-CTR stage breakdown
  - AES-GCM top-level stages and internal hotspots
  - AES-CBC encrypt and decrypt bottlenecks
  - Optimization hints based on measured hotspots

No-instrumentation build (default):
  PROF=0

Instrumentation build:
  PROF=1
  This adds detailed counters and builds profile_aes.exe.

Optional fast build flags:
  mingw32-make clean
  mingw32-make FAST=1 all

You can combine flags:
  mingw32-make FAST=1 PROF=1 all

Optional gprof build:
  mingw32-make clean
  mingw32-make GPROF=1 all
  build\bin\bench_aes.exe
  gprof build\bin\bench_aes.exe gmon.out > gprof.txt
