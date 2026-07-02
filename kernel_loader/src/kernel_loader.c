#include "kernel_loader.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char* kl_strdup(const char* s)
{
    if (!s) return NULL;
    size_t n = strlen(s);
    char* p = (char*)malloc(n + 1);
    if (!p) return NULL;
    memcpy(p, s, n + 1);
    return p;
}

const char* kl_error_to_string(int code)
{
    switch (code)
    {
        case KL_OK: return "KL_OK";
        case KL_ERR_INVALID_ARGS: return "KL_ERR_INVALID_ARGS";
        case KL_ERR_FILE_OPEN: return "KL_ERR_FILE_OPEN";
        case KL_ERR_FILE_READ: return "KL_ERR_FILE_READ";
        case KL_ERR_OOM: return "KL_ERR_OOM";
        case KL_ERR_CL_CREATE_PROGRAM: return "KL_ERR_CL_CREATE_PROGRAM";
        case KL_ERR_CL_BUILD_PROGRAM: return "KL_ERR_CL_BUILD_PROGRAM";
        case KL_ERR_CL_CREATE_KERNEL: return "KL_ERR_CL_CREATE_KERNEL";
        default: return "KL_ERR_UNKNOWN";
    }
}

void kl_free(void* p)
{
    free(p);
}

char* kl_read_text_file(const char* path, int* out_error)
{
    if (out_error) *out_error = KL_OK;
    if (!path)
    {
        if (out_error) *out_error = KL_ERR_INVALID_ARGS;
        return NULL;
    }

    FILE* f = fopen(path, "rb");
    if (!f)
    {
        if (out_error) *out_error = KL_ERR_FILE_OPEN;
        return NULL;
    }

    if (fseek(f, 0, SEEK_END) != 0)
    {
        fclose(f);
        if (out_error) *out_error = KL_ERR_FILE_READ;
        return NULL;
    }

    long len = ftell(f);
    if (len < 0)
    {
        fclose(f);
        if (out_error) *out_error = KL_ERR_FILE_READ;
        return NULL;
    }

    if (fseek(f, 0, SEEK_SET) != 0)
    {
        fclose(f);
        if (out_error) *out_error = KL_ERR_FILE_READ;
        return NULL;
    }

    char* buf = (char*)malloc((size_t)len + 1);
    if (!buf)
    {
        fclose(f);
        if (out_error) *out_error = KL_ERR_OOM;
        return NULL;
    }

    size_t got = fread(buf, 1, (size_t)len, f);
    fclose(f);

    if (got != (size_t)len)
    {
        free(buf);
        if (out_error) *out_error = KL_ERR_FILE_READ;
        return NULL;
    }

    buf[len] = '\0';
    return buf;
}

static char* kl_get_build_log(cl_program program, cl_device_id device)
{
    size_t sz = 0;
    cl_int e = clGetProgramBuildInfo(program, device, CL_PROGRAM_BUILD_LOG, 0, NULL, &sz);
    if (e != CL_SUCCESS || sz == 0) return kl_strdup("");
    char* log = (char*)malloc(sz + 1);
    if (!log) return NULL;
    e = clGetProgramBuildInfo(program, device, CL_PROGRAM_BUILD_LOG, sz, log, NULL);
    if (e != CL_SUCCESS)
    {
        free(log);
        return NULL;
    }
    log[sz] = '\0';
    return log;
}

cl_program kl_build_program_from_file(
    cl_context context,
    cl_device_id device,
    const char* path,
    const char* build_options,
    char** out_build_log,
    int* out_error,
    cl_int* out_cl_error)
{
    if (out_error) *out_error = KL_OK;
    if (out_cl_error) *out_cl_error = CL_SUCCESS;
    if (out_build_log) *out_build_log = NULL;

    if (!context || !device || !path)
    {
        if (out_error) *out_error = KL_ERR_INVALID_ARGS;
        return NULL;
    }

    int rerr = KL_OK;
    char* src = kl_read_text_file(path, &rerr);
    if (!src)
    {
        if (out_error) *out_error = rerr;
        return NULL;
    }

    const char* sources[] = { src };
    cl_int cle = CL_SUCCESS;
    cl_program program = clCreateProgramWithSource(context, 1, sources, NULL, &cle);
    free(src);

    if (cle != CL_SUCCESS || !program)
    {
        if (out_error) *out_error = KL_ERR_CL_CREATE_PROGRAM;
        if (out_cl_error) *out_cl_error = cle;
        if (program) clReleaseProgram(program);
        return NULL;
    }

    const char* opts = build_options ? build_options : "";
    cle = clBuildProgram(program, 1, &device, opts, NULL, NULL);

    if (cle != CL_SUCCESS)
    {
        char* log = kl_get_build_log(program, device);
        if (out_build_log) *out_build_log = log;
        else free(log);

        if (out_error) *out_error = KL_ERR_CL_BUILD_PROGRAM;
        if (out_cl_error) *out_cl_error = cle;

        clReleaseProgram(program);
        return NULL;
    }

    if (out_build_log)
    {
        char* log = kl_get_build_log(program, device);
        *out_build_log = log ? log : kl_strdup("");
    }

    return program;
}

cl_kernel kl_create_kernel_from_file(
    cl_context context,
    cl_device_id device,
    const char* path,
    const char* kernel_name,
    const char* build_options,
    cl_program* out_program,
    char** out_build_log,
    int* out_error,
    cl_int* out_cl_error)
{
    if (out_error) *out_error = KL_OK;
    if (out_cl_error) *out_cl_error = CL_SUCCESS;
    if (out_build_log) *out_build_log = NULL;
    if (out_program) *out_program = NULL;

    if (!context || !device || !path || !kernel_name)
    {
        if (out_error) *out_error = KL_ERR_INVALID_ARGS;
        return NULL;
    }

    cl_program program = kl_build_program_from_file(
        context, device, path, build_options, out_build_log, out_error, out_cl_error);

    if (!program) return NULL;

    cl_int cle = CL_SUCCESS;
    cl_kernel kernel = clCreateKernel(program, kernel_name, &cle);
    if (cle != CL_SUCCESS || !kernel)
    {
        if (out_error) *out_error = KL_ERR_CL_CREATE_KERNEL;
        if (out_cl_error) *out_cl_error = cle;
        clReleaseProgram(program);
        return NULL;
    }

    if (out_program) *out_program = program;
    else clReleaseProgram(program);

    return kernel;
}