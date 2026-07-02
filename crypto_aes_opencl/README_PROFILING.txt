OpenCL Profiling / Benchmarking

Build (Windows MinGW):
  mingw32-make clean
  mingw32-make all

Default outputs:
  build\bin\bench_opencl_aes.exe
  build\bin\test_opencl_aes.exe
  build\bin\crypto_aes_opencl.dll
  build\lib\libcrypto_aes_opencl.dll.a
  build\lib\libcrypto_aes_opencl.a

Profiler build:
  mingw32-make clean
  mingw32-make PROF=1 all
  build\bin\profile_opencl_aes.exe

Profiler output highlights:
  - Cold-start initialization breakdown
  - Warm AES-CTR transfer, kernel and host overhead breakdown
  - Warm AES-GCM encrypt and decrypt stage breakdown
  - CPU-side helper hotspots inside the hybrid GPU path
  - Optimization hints for transfer-bound or kernel-bound runs

Useful environment variables:
  CRYPTO_OCL_PLATFORM_INDEX
  CRYPTO_OCL_DEVICE_INDEX
  CRYPTO_OCL_LOCAL_SIZE
  CRYPTO_OCL_GHASH_CHUNK_BLOCKS
  CRYPTO_OCL_KERNEL_DIR
