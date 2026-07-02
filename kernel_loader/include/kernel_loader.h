#ifndef KERNEL_LOADER_H
#define KERNEL_LOADER_H

#include <CL/cl.h>

#ifdef _WIN32
  #ifdef KERNEL_LOADER_BUILD_DLL
    #define KERNEL_LOADER_API __declspec(dllexport)
  #else
    #define KERNEL_LOADER_API __declspec(dllimport)
  #endif
#else
  #define KERNEL_LOADER_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

enum
{
    KL_OK = 0,
    KL_ERR_INVALID_ARGS = -1,
    KL_ERR_FILE_OPEN = -2,
    KL_ERR_FILE_READ = -3,
    KL_ERR_OOM = -4,
    KL_ERR_CL_CREATE_PROGRAM = -5,
    KL_ERR_CL_BUILD_PROGRAM = -6,
    KL_ERR_CL_CREATE_KERNEL = -7
};

KERNEL_LOADER_API const char* kl_error_to_string(int code);

KERNEL_LOADER_API void kl_free(void* p);

KERNEL_LOADER_API char* kl_read_text_file(
    const char* path,
    int* out_error);

KERNEL_LOADER_API cl_program kl_build_program_from_file(
    cl_context context,
    cl_device_id device,
    const char* path,
    const char* build_options,
    char** out_build_log,
    int* out_error,
    cl_int* out_cl_error);

KERNEL_LOADER_API cl_kernel kl_create_kernel_from_file(
    cl_context context,
    cl_device_id device,
    const char* path,
    const char* kernel_name,
    const char* build_options,
    cl_program* out_program,
    char** out_build_log,
    int* out_error,
    cl_int* out_cl_error);

#ifdef __cplusplus
}
#endif

#endif