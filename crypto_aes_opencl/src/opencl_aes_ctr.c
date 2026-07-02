#include <CL/cl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "aes.h"
#include "crypto_status.h"
#include "crypto_timer.h"
#include "crypto_gf128.h"
#include "kernel_loader.h"
#include "opencl_aes_ctr.h"
#include "opencl_aes_gcm.h"
#include "crypto_ocl_profile.h"

#ifndef CRYPTO_OCL_MAX_ERROR
#define CRYPTO_OCL_MAX_ERROR 2048
#endif

typedef struct crypto_ocl_ctx_t {
    int inited;
    cl_platform_id platform;
    cl_device_id device;
    cl_context context;
    cl_command_queue queue;
    cl_program program;
    cl_kernel kernel;
    cl_kernel kernel_gcm_ctr;
    cl_mem round_keys_buf;
    cl_mem in_buf;
    cl_mem out_buf;
    size_t io_capacity;
    size_t max_wg;

    cl_program ghash_program;
    cl_kernel ghash_kernel;
    cl_kernel ghash_reduce_kernel;
    cl_mem ghash_blocks_buf;
    cl_mem ghash_chunks_buf;
    cl_mem ghash_final_buf;
    size_t ghash_blocks_capacity;
    size_t ghash_chunks_capacity;

    int round_keys_cached;
    size_t cached_round_keys_len;
    uint8_t cached_round_keys[240];

    char last_error[CRYPTO_OCL_MAX_ERROR];
} crypto_ocl_ctx_t;

static crypto_ocl_ctx_t g_ctx;
static char g_platform_name[256];
static char g_platform_version[256];
static char g_device_name[256];
static char g_device_version[256];
static char g_device_opencl_c_version[256];

static crypto_status_t ocl_init_if_needed(void);
static crypto_status_t ocl_ensure_io_buffers(size_t len);
static crypto_status_t ocl_upload_round_keys_if_needed(const uint8_t* round_keys, size_t round_keys_len);
static size_t choose_local_size(size_t max_wg);
static crypto_status_t ocl_write_buffer(cl_mem buffer, size_t offset, const void* src, size_t len);
static crypto_status_t ocl_read_buffer(cl_mem buffer, size_t offset, void* dst, size_t len);
static crypto_status_t ocl_copy_buffer(cl_mem src_buf, size_t src_offset, cl_mem dst_buf, size_t dst_offset, size_t len);
static crypto_status_t ocl_launch_ctr_kernel(cl_kernel kernel_obj,
                                            size_t round_keys_len,
                                            uint64_t iv_hi,
                                            uint64_t iv_lo,
                                            size_t len,
                                            uint64_t block_offset,
                                            uint64_t* out_kernel_ns,
                                            int profile_ctr);

static void secure_zero(void* p, size_t n)
{
    volatile uint8_t* v = (volatile uint8_t*)p;
    while (n--) {
        *v++ = 0;
    }
}

static void ocl_set_error(const char* msg)
{
    if (!msg) {
        g_ctx.last_error[0] = 0;
        return;
    }
    strncpy(g_ctx.last_error, msg, sizeof(g_ctx.last_error) - 1);
    g_ctx.last_error[sizeof(g_ctx.last_error) - 1] = 0;
}

const char* crypto_ocl_last_error_message(void)
{
    if (!g_ctx.last_error[0]) {
        return "";
    }
    return g_ctx.last_error;
}

static uint64_t be64_load(const uint8_t b[8])
{
    return ((uint64_t)b[0] << 56) |
           ((uint64_t)b[1] << 48) |
           ((uint64_t)b[2] << 40) |
           ((uint64_t)b[3] << 32) |
           ((uint64_t)b[4] << 24) |
           ((uint64_t)b[5] << 16) |
           ((uint64_t)b[6] << 8) |
           ((uint64_t)b[7]);
}

static void pack_round_keys_words(cl_uint out_words[60], const uint8_t* in_bytes, size_t in_len)
{
    size_t words = in_len / 4;
    for (int i = 0; i < 60; i++) {
        out_words[i] = 0;
    }
    for (size_t i = 0; i < words && i < 60; i++) {
        size_t j = i * 4;
        out_words[i] = ((cl_uint)in_bytes[j + 0] << 24) |
                       ((cl_uint)in_bytes[j + 1] << 16) |
                       ((cl_uint)in_bytes[j + 2] << 8) |
                       ((cl_uint)in_bytes[j + 3]);
    }
}


static void format_cl_error(char* dst, size_t cap, const char* where, cl_int e)
{
    if (!dst || cap == 0) {
        return;
    }
    if (!where) {
        where = "";
    }
#if defined(_WIN32) || defined(_WIN64)
    _snprintf(dst, cap, "%s (OpenCL error %d)", where, (int)e);
#else
    snprintf(dst, cap, "%s (OpenCL error %d)", where, (int)e);
#endif
    dst[cap - 1] = 0;
}

static crypto_status_t ocl_choose_platform_device(cl_platform_id* out_platform, cl_device_id* out_device);

static void query_platform_info_string(cl_platform_id platform, cl_platform_info param, char* dst, size_t cap)
{
    size_t need = 0;
    cl_int e;

    if (!dst || cap == 0) {
        return;
    }

    dst[0] = '\0';
    if (!platform) {
        return;
    }

    e = clGetPlatformInfo(platform, param, 0, NULL, &need);
    if (e != CL_SUCCESS || need == 0) {
        return;
    }

    if (need > cap) {
        need = cap;
    }

    e = clGetPlatformInfo(platform, param, need, dst, NULL);
    if (e != CL_SUCCESS) {
        dst[0] = '\0';
        return;
    }

    dst[cap - 1] = '\0';
}

static void query_device_info_string(cl_device_id device, cl_device_info param, char* dst, size_t cap)
{
    size_t need = 0;
    cl_int e;

    if (!dst || cap == 0) {
        return;
    }

    dst[0] = '\0';
    if (!device) {
        return;
    }

    e = clGetDeviceInfo(device, param, 0, NULL, &need);
    if (e != CL_SUCCESS || need == 0) {
        return;
    }

    if (need > cap) {
        need = cap;
    }

    e = clGetDeviceInfo(device, param, need, dst, NULL);
    if (e != CL_SUCCESS) {
        dst[0] = '\0';
        return;
    }

    dst[cap - 1] = '\0';
}

static void refresh_opencl_info_cache(void)
{
    cl_platform_id platform = NULL;
    cl_device_id device = NULL;

    g_platform_name[0] = '\0';
    g_platform_version[0] = '\0';
    g_device_name[0] = '\0';
    g_device_version[0] = '\0';
    g_device_opencl_c_version[0] = '\0';

    if (g_ctx.platform && g_ctx.device) {
        platform = g_ctx.platform;
        device = g_ctx.device;
    } else if (ocl_choose_platform_device(&platform, &device) != CRYPTO_OK) {
        return;
    }

    query_platform_info_string(platform, CL_PLATFORM_NAME, g_platform_name, sizeof(g_platform_name));
    query_platform_info_string(platform, CL_PLATFORM_VERSION, g_platform_version, sizeof(g_platform_version));
    query_device_info_string(device, CL_DEVICE_NAME, g_device_name, sizeof(g_device_name));
    query_device_info_string(device, CL_DEVICE_VERSION, g_device_version, sizeof(g_device_version));
    query_device_info_string(device, CL_DEVICE_OPENCL_C_VERSION, g_device_opencl_c_version, sizeof(g_device_opencl_c_version));
}

const char* crypto_ocl_platform_name(void)
{
    refresh_opencl_info_cache();
    return g_platform_name;
}

const char* crypto_ocl_platform_version(void)
{
    refresh_opencl_info_cache();
    return g_platform_version;
}

const char* crypto_ocl_device_name(void)
{
    refresh_opencl_info_cache();
    return g_device_name;
}

const char* crypto_ocl_device_version(void)
{
    refresh_opencl_info_cache();
    return g_device_version;
}

const char* crypto_ocl_device_opencl_c_version(void)
{
    refresh_opencl_info_cache();
    return g_device_opencl_c_version;
}

static crypto_status_t ocl_choose_platform_device(cl_platform_id* out_platform, cl_device_id* out_device)
{
    cl_uint platform_count = 0;
    cl_platform_id platforms[16];
    cl_device_id devices[32];
    cl_int e;
    const char* env_platform;
    const char* env_device;
    int platform_index = 0;
    int device_index = 0;

    if (!out_platform || !out_device) {
        return CRYPTO_INVALID_ARG;
    }

    e = clGetPlatformIDs(16, platforms, &platform_count);
    if (e != CL_SUCCESS || platform_count == 0) {
        format_cl_error(g_ctx.last_error, sizeof(g_ctx.last_error), "clGetPlatformIDs failed", e);
        return CRYPTO_UNSUPPORTED;
    }

    env_platform = getenv("CRYPTO_OCL_PLATFORM_INDEX");
    if (env_platform && env_platform[0]) {
        platform_index = atoi(env_platform);
    }
    if (platform_index < 0 || (cl_uint)platform_index >= platform_count) {
        platform_index = 0;
    }

    *out_platform = platforms[platform_index];

    env_device = getenv("CRYPTO_OCL_DEVICE_INDEX");
    if (env_device && env_device[0]) {
        device_index = atoi(env_device);
    }
    if (device_index < 0) {
        device_index = 0;
    }

    {
        cl_uint device_count = 0;
        e = clGetDeviceIDs(*out_platform, CL_DEVICE_TYPE_GPU, 32, devices, &device_count);
        if (e != CL_SUCCESS || device_count == 0) {
            e = clGetDeviceIDs(*out_platform, CL_DEVICE_TYPE_ALL, 32, devices, &device_count);
        }
        if (e != CL_SUCCESS || device_count == 0) {
            format_cl_error(g_ctx.last_error, sizeof(g_ctx.last_error), "clGetDeviceIDs failed", e);
            return CRYPTO_UNSUPPORTED;
        }
        if ((cl_uint)device_index >= device_count) {
            device_index = 0;
        }
        *out_device = devices[device_index];
    }

    return CRYPTO_OK;
}

static crypto_status_t crypto_ocl_aes_gcm_ctr_xor_round_keys_internal(const uint8_t* round_keys,
                                                                     size_t round_keys_len,
                                                                     const uint8_t j0[16],
                                                                     const uint8_t* input,
                                                                     uint8_t* output,
                                                                     size_t len,
                                                                     uint64_t block_offset,
                                                                     int upload_input,
                                                                     int download_output,
                                                                     uint64_t* out_kernel_ns)
{
    crypto_status_t st;
    uint64_t iv_hi;
    uint64_t iv_lo;
    uint64_t t_stage;

    if (out_kernel_ns) {
        *out_kernel_ns = 0;
    }

    if (!round_keys || !j0) {
        ocl_set_error("Invalid argument");
        return CRYPTO_INVALID_ARG;
    }
    if (upload_input && !input) {
        ocl_set_error("Invalid argument");
        return CRYPTO_INVALID_ARG;
    }
    if (download_output && !output) {
        ocl_set_error("Invalid argument");
        return CRYPTO_INVALID_ARG;
    }

    if (len == 0) {
        return CRYPTO_OK;
    }

    st = ocl_init_if_needed();
    if (st != CRYPTO_OK) {
        return st;
    }

    st = ocl_ensure_io_buffers(len);
    if (st != CRYPTO_OK) {
        return st;
    }

    st = ocl_upload_round_keys_if_needed(round_keys, round_keys_len);
    if (st != CRYPTO_OK) {
        return st;
    }

    iv_hi = be64_load(j0);
    iv_lo = be64_load(j0 + 8);

    if (upload_input) {
        t_stage = crypto_time_now_ns();
        st = ocl_write_buffer(g_ctx.in_buf, 0, input, len);
#ifdef CRYPTO_OCL_PROFILE
        crypto_ocl_profile_add_ctr_host_to_device(crypto_time_now_ns() - t_stage);
#endif
        if (st != CRYPTO_OK) {
            return st;
        }
    }

    st = ocl_launch_ctr_kernel(g_ctx.kernel_gcm_ctr,
                               round_keys_len,
                               iv_hi,
                               iv_lo,
                               len,
                               block_offset,
                               out_kernel_ns,
                               1);
    if (st != CRYPTO_OK) {
        return st;
    }

    if (download_output) {
        t_stage = crypto_time_now_ns();
        st = ocl_read_buffer(g_ctx.out_buf, 0, output, len);
#ifdef CRYPTO_OCL_PROFILE
        crypto_ocl_profile_add_ctr_device_to_host(crypto_time_now_ns() - t_stage);
#endif
        if (st != CRYPTO_OK) {
            return st;
        }
    }

    return CRYPTO_OK;
}

crypto_status_t crypto_ocl_aes_gcm_ctr_xor_round_keys(const uint8_t* round_keys,
                                                           size_t round_keys_len,
                                                           const uint8_t j0[16],
                                                           const uint8_t* input,
                                                           uint8_t* output,
                                                           size_t len,
                                                           uint64_t block_offset,
                                                           uint64_t* out_kernel_ns)
{
    return crypto_ocl_aes_gcm_ctr_xor_round_keys_internal(round_keys, round_keys_len, j0, input, output, len, block_offset, 1, 1, out_kernel_ns);
}

static void join_path(char* out_path, size_t cap, const char* dir, const char* file)
{
    size_t dl;
    size_t fl;
    if (!out_path || cap == 0) {
        return;
    }
    out_path[0] = 0;
    if (!dir || !dir[0]) {
        strncpy(out_path, file ? file : "", cap - 1);
        out_path[cap - 1] = 0;
        return;
    }
    dl = strlen(dir);
    fl = file ? strlen(file) : 0;
    if (dl + 1 + fl + 1 > cap) {
        return;
    }
    memcpy(out_path, dir, dl);
    if (dir[dl - 1] != '/' && dir[dl - 1] != '\\') {
        out_path[dl] = '/';
        dl++;
    }
    if (file && fl) {
        memcpy(out_path + dl, file, fl);
        dl += fl;
    }
    out_path[dl] = 0;
}

static crypto_status_t ocl_init_if_needed(void)
{
    cl_int e;
    crypto_status_t st;
    char kernel_path[1024];
    const char* env_kernel_dir;
    char* build_log = NULL;
    int kl_err = 0;
    cl_int cl_err = CL_SUCCESS;
    uint64_t t_total = crypto_time_now_ns();
    uint64_t t_stage = 0;
    uint64_t choose_device_ns = 0;
    uint64_t context_ns = 0;
    uint64_t queue_ns = 0;
    uint64_t round_keys_buffer_ns = 0;
    uint64_t ctr_program_ns = 0;
    uint64_t gcm_program_ns = 0;

    if (g_ctx.inited) {
        return CRYPTO_OK;
    }

    memset(&g_ctx, 0, sizeof(g_ctx));

    t_stage = crypto_time_now_ns();
    st = ocl_choose_platform_device(&g_ctx.platform, &g_ctx.device);
    choose_device_ns = crypto_time_now_ns() - t_stage;
    if (st != CRYPTO_OK) {
        return st;
    }

    t_stage = crypto_time_now_ns();
    g_ctx.context = clCreateContext(NULL, 1, &g_ctx.device, NULL, NULL, &e);
    context_ns = crypto_time_now_ns() - t_stage;
    if (!g_ctx.context || e != CL_SUCCESS) {
        format_cl_error(g_ctx.last_error, sizeof(g_ctx.last_error), "clCreateContext failed", e);
        return CRYPTO_INTERNAL_ERROR;
    }

    t_stage = crypto_time_now_ns();
#ifdef CRYPTO_OCL_PROFILE
    g_ctx.queue = clCreateCommandQueue(g_ctx.context, g_ctx.device, CL_QUEUE_PROFILING_ENABLE, &e);
#else
    g_ctx.queue = clCreateCommandQueue(g_ctx.context, g_ctx.device, 0, &e);
#endif
    queue_ns = crypto_time_now_ns() - t_stage;
    if (!g_ctx.queue || e != CL_SUCCESS) {
        format_cl_error(g_ctx.last_error, sizeof(g_ctx.last_error), "clCreateCommandQueue failed", e);
        clReleaseContext(g_ctx.context);
        g_ctx.context = NULL;
        return CRYPTO_INTERNAL_ERROR;
    }

    {
        size_t wg = 0;
        e = clGetDeviceInfo(g_ctx.device, CL_DEVICE_MAX_WORK_GROUP_SIZE, sizeof(size_t), &wg, NULL);
        if (e == CL_SUCCESS && wg > 0) {
            g_ctx.max_wg = wg;
        } else {
            g_ctx.max_wg = 256;
        }
    }

    t_stage = crypto_time_now_ns();
    g_ctx.round_keys_buf = clCreateBuffer(g_ctx.context, CL_MEM_READ_ONLY, 240, NULL, &e);
    round_keys_buffer_ns = crypto_time_now_ns() - t_stage;
    if (!g_ctx.round_keys_buf || e != CL_SUCCESS) {
        format_cl_error(g_ctx.last_error, sizeof(g_ctx.last_error), "clCreateBuffer(round_keys) failed", e);
        clReleaseCommandQueue(g_ctx.queue);
        clReleaseContext(g_ctx.context);
        g_ctx.queue = NULL;
        g_ctx.context = NULL;
        return CRYPTO_INTERNAL_ERROR;
    }

    env_kernel_dir = getenv("CRYPTO_OCL_KERNEL_DIR");
    if (env_kernel_dir && env_kernel_dir[0]) {
        join_path(kernel_path, sizeof(kernel_path), env_kernel_dir, "aes_ctr_xor.cl");
    } else {
        join_path(kernel_path, sizeof(kernel_path), "kernels", "aes_ctr_xor.cl");
    }

    t_stage = crypto_time_now_ns();
    g_ctx.kernel = kl_create_kernel_from_file(g_ctx.context,
                                             g_ctx.device,
                                             kernel_path,
                                             "aes_ctr_xor",
                                             NULL,
                                             &g_ctx.program,
                                             &build_log,
                                             &kl_err,
                                             &cl_err);
    ctr_program_ns = crypto_time_now_ns() - t_stage;

    if (!g_ctx.kernel || kl_err != KL_OK || cl_err != CL_SUCCESS) {
        if (build_log && build_log[0]) {
            ocl_set_error(build_log);
        } else if (kl_err != KL_OK) {
            ocl_set_error(kl_error_to_string(kl_err));
        } else {
            format_cl_error(g_ctx.last_error, sizeof(g_ctx.last_error), "OpenCL build/create kernel failed", cl_err);
        }
        if (build_log) {
            kl_free(build_log);
        }
        if (g_ctx.program) {
            clReleaseProgram(g_ctx.program);
            g_ctx.program = NULL;
        }
        clReleaseMemObject(g_ctx.round_keys_buf);
        clReleaseCommandQueue(g_ctx.queue);
        clReleaseContext(g_ctx.context);
        g_ctx.round_keys_buf = NULL;
        g_ctx.queue = NULL;
        g_ctx.context = NULL;
        return CRYPTO_INTERNAL_ERROR;
    }

    if (build_log) {
        kl_free(build_log);
    }

    {
        cl_int e2 = CL_SUCCESS;
        g_ctx.kernel_gcm_ctr = clCreateKernel(g_ctx.program, "aes_gcm_ctr_xor", &e2);
        if (!g_ctx.kernel_gcm_ctr || e2 != CL_SUCCESS) {
            format_cl_error(g_ctx.last_error, sizeof(g_ctx.last_error), "clCreateKernel(aes_gcm_ctr_xor) failed", e2);
            if (g_ctx.kernel_gcm_ctr) {
                clReleaseKernel(g_ctx.kernel_gcm_ctr);
                g_ctx.kernel_gcm_ctr = NULL;
            }
            clReleaseKernel(g_ctx.kernel);
            g_ctx.kernel = NULL;
            clReleaseProgram(g_ctx.program);
            g_ctx.program = NULL;
            clReleaseMemObject(g_ctx.round_keys_buf);
            g_ctx.round_keys_buf = NULL;
            clReleaseCommandQueue(g_ctx.queue);
            clReleaseContext(g_ctx.context);
            g_ctx.queue = NULL;
            g_ctx.context = NULL;
            return CRYPTO_INTERNAL_ERROR;
        }
    }

    {
        char ghash_path[1024];
        const char* env_kernel_dir2 = getenv("CRYPTO_OCL_KERNEL_DIR");
        char* build_log2 = NULL;
        int kl_err2 = 0;
        cl_int cl_err2 = CL_SUCCESS;

        if (env_kernel_dir2 && env_kernel_dir2[0]) {
            join_path(ghash_path, sizeof(ghash_path), env_kernel_dir2, "gcm_ghash_chunk.cl");
        } else {
            join_path(ghash_path, sizeof(ghash_path), "kernels", "gcm_ghash_chunk.cl");
        }

        t_stage = crypto_time_now_ns();
        g_ctx.ghash_kernel = kl_create_kernel_from_file(g_ctx.context,
                                                        g_ctx.device,
                                                        ghash_path,
                                                        "gcm_ghash_chunk",
                                                        NULL,
                                                        &g_ctx.ghash_program,
                                                        &build_log2,
                                                        &kl_err2,
                                                        &cl_err2);
        gcm_program_ns = crypto_time_now_ns() - t_stage;

        if (!g_ctx.ghash_kernel || kl_err2 != KL_OK || cl_err2 != CL_SUCCESS) {
            if (build_log2 && build_log2[0]) {
                ocl_set_error(build_log2);
            } else if (kl_err2 != KL_OK) {
                ocl_set_error(kl_error_to_string(kl_err2));
            } else {
                format_cl_error(g_ctx.last_error, sizeof(g_ctx.last_error), "OpenCL build/create ghash kernel failed", cl_err2);
            }
            if (build_log2) {
                kl_free(build_log2);
            }

            if (g_ctx.ghash_program) {
                clReleaseProgram(g_ctx.ghash_program);
                g_ctx.ghash_program = NULL;
            }
            if (g_ctx.ghash_kernel) {
                clReleaseKernel(g_ctx.ghash_kernel);
                g_ctx.ghash_kernel = NULL;
            }

            clReleaseKernel(g_ctx.kernel_gcm_ctr);
            g_ctx.kernel_gcm_ctr = NULL;

            clReleaseKernel(g_ctx.kernel);
            g_ctx.kernel = NULL;
            clReleaseProgram(g_ctx.program);
            g_ctx.program = NULL;
            clReleaseMemObject(g_ctx.round_keys_buf);
            g_ctx.round_keys_buf = NULL;
            clReleaseCommandQueue(g_ctx.queue);
            clReleaseContext(g_ctx.context);
            g_ctx.queue = NULL;
            g_ctx.context = NULL;
            return CRYPTO_INTERNAL_ERROR;
        }

        if (build_log2) {
            kl_free(build_log2);
        }

        {
            cl_int e3 = CL_SUCCESS;
            g_ctx.ghash_reduce_kernel = clCreateKernel(g_ctx.ghash_program, "gcm_ghash_reduce", &e3);
            if (!g_ctx.ghash_reduce_kernel || e3 != CL_SUCCESS) {
                format_cl_error(g_ctx.last_error, sizeof(g_ctx.last_error), "clCreateKernel(gcm_ghash_reduce) failed", e3);
                if (g_ctx.ghash_reduce_kernel) {
                    clReleaseKernel(g_ctx.ghash_reduce_kernel);
                    g_ctx.ghash_reduce_kernel = NULL;
                }
                if (g_ctx.ghash_kernel) {
                    clReleaseKernel(g_ctx.ghash_kernel);
                    g_ctx.ghash_kernel = NULL;
                }
                if (g_ctx.ghash_program) {
                    clReleaseProgram(g_ctx.ghash_program);
                    g_ctx.ghash_program = NULL;
                }
                clReleaseKernel(g_ctx.kernel_gcm_ctr);
                g_ctx.kernel_gcm_ctr = NULL;
                clReleaseKernel(g_ctx.kernel);
                g_ctx.kernel = NULL;
                clReleaseProgram(g_ctx.program);
                g_ctx.program = NULL;
                clReleaseMemObject(g_ctx.round_keys_buf);
                g_ctx.round_keys_buf = NULL;
                clReleaseCommandQueue(g_ctx.queue);
                clReleaseContext(g_ctx.context);
                g_ctx.queue = NULL;
                g_ctx.context = NULL;
                return CRYPTO_INTERNAL_ERROR;
            }
        }
    }

    g_ctx.inited = 1;
#ifdef CRYPTO_OCL_PROFILE
    crypto_ocl_profile_add_init(crypto_time_now_ns() - t_total,
                                choose_device_ns,
                                context_ns,
                                queue_ns,
                                round_keys_buffer_ns,
                                ctr_program_ns,
                                gcm_program_ns);
#endif
    return CRYPTO_OK;
}

static void ocl_release_buffers(void)
{
    if (g_ctx.in_buf) {
        clReleaseMemObject(g_ctx.in_buf);
        g_ctx.in_buf = NULL;
    }
    if (g_ctx.out_buf) {
        clReleaseMemObject(g_ctx.out_buf);
        g_ctx.out_buf = NULL;
    }
    g_ctx.io_capacity = 0;
}

void crypto_ocl_shutdown(void)
{
    if (!g_ctx.inited) {
        return;
    }

    ocl_release_buffers();

    if (g_ctx.round_keys_buf) {
        clReleaseMemObject(g_ctx.round_keys_buf);
        g_ctx.round_keys_buf = NULL;
    }

    if (g_ctx.ghash_blocks_buf) {
        clReleaseMemObject(g_ctx.ghash_blocks_buf);
        g_ctx.ghash_blocks_buf = NULL;
    }
    if (g_ctx.ghash_chunks_buf) {
        clReleaseMemObject(g_ctx.ghash_chunks_buf);
        g_ctx.ghash_chunks_buf = NULL;
    }
    if (g_ctx.ghash_final_buf) {
        clReleaseMemObject(g_ctx.ghash_final_buf);
        g_ctx.ghash_final_buf = NULL;
    }
    g_ctx.ghash_blocks_capacity = 0;
    g_ctx.ghash_chunks_capacity = 0;

    if (g_ctx.ghash_reduce_kernel) {
        clReleaseKernel(g_ctx.ghash_reduce_kernel);
        g_ctx.ghash_reduce_kernel = NULL;
    }
    if (g_ctx.ghash_kernel) {
        clReleaseKernel(g_ctx.ghash_kernel);
        g_ctx.ghash_kernel = NULL;
    }
    if (g_ctx.ghash_program) {
        clReleaseProgram(g_ctx.ghash_program);
        g_ctx.ghash_program = NULL;
    }

    if (g_ctx.kernel_gcm_ctr) {
        clReleaseKernel(g_ctx.kernel_gcm_ctr);
        g_ctx.kernel_gcm_ctr = NULL;
    }

    if (g_ctx.kernel) {
        clReleaseKernel(g_ctx.kernel);
        g_ctx.kernel = NULL;
    }

    if (g_ctx.program) {
        clReleaseProgram(g_ctx.program);
        g_ctx.program = NULL;
    }

    if (g_ctx.queue) {
        clReleaseCommandQueue(g_ctx.queue);
        g_ctx.queue = NULL;
    }

    if (g_ctx.context) {
        clReleaseContext(g_ctx.context);
        g_ctx.context = NULL;
    }

    secure_zero(g_ctx.cached_round_keys, sizeof(g_ctx.cached_round_keys));
    memset(&g_ctx, 0, sizeof(g_ctx));
}

static crypto_status_t ocl_ensure_io_buffers(size_t len)
{
    cl_int e;
    uint64_t t0 = crypto_time_now_ns();
    int reallocated = 0;
    if (len == 0) {
        return CRYPTO_INVALID_ARG;
    }

    if (g_ctx.io_capacity >= len && g_ctx.in_buf && g_ctx.out_buf) {
#ifdef CRYPTO_OCL_PROFILE
        crypto_ocl_profile_add_ensure_io(crypto_time_now_ns() - t0, 0, len);
#endif
        return CRYPTO_OK;
    }

    reallocated = 1;
    ocl_release_buffers();

    g_ctx.in_buf = clCreateBuffer(g_ctx.context, CL_MEM_READ_ONLY, len, NULL, &e);
    if (!g_ctx.in_buf || e != CL_SUCCESS) {
        format_cl_error(g_ctx.last_error, sizeof(g_ctx.last_error), "clCreateBuffer(input) failed", e);
        ocl_release_buffers();
        return CRYPTO_INTERNAL_ERROR;
    }

    g_ctx.out_buf = clCreateBuffer(g_ctx.context, CL_MEM_WRITE_ONLY, len, NULL, &e);
    if (!g_ctx.out_buf || e != CL_SUCCESS) {
        format_cl_error(g_ctx.last_error, sizeof(g_ctx.last_error), "clCreateBuffer(output) failed", e);
        ocl_release_buffers();
        return CRYPTO_INTERNAL_ERROR;
    }

    g_ctx.io_capacity = len;
#ifdef CRYPTO_OCL_PROFILE
    crypto_ocl_profile_add_ensure_io(crypto_time_now_ns() - t0, reallocated, len);
#endif
    return CRYPTO_OK;
}

static void ocl_release_ghash_buffers(void)
{
    if (g_ctx.ghash_blocks_buf) {
        clReleaseMemObject(g_ctx.ghash_blocks_buf);
        g_ctx.ghash_blocks_buf = NULL;
    }
    if (g_ctx.ghash_chunks_buf) {
        clReleaseMemObject(g_ctx.ghash_chunks_buf);
        g_ctx.ghash_chunks_buf = NULL;
    }
    if (g_ctx.ghash_final_buf) {
        clReleaseMemObject(g_ctx.ghash_final_buf);
        g_ctx.ghash_final_buf = NULL;
    }
    g_ctx.ghash_blocks_capacity = 0;
    g_ctx.ghash_chunks_capacity = 0;
}

static crypto_status_t ocl_ensure_ghash_buffers(size_t blocks_bytes, size_t chunk_count)
{
    cl_int e;
    uint64_t t0 = crypto_time_now_ns();
    int reallocated = 0;

    if (blocks_bytes == 0 || chunk_count == 0) {
        return CRYPTO_INVALID_ARG;
    }

    if (g_ctx.ghash_blocks_capacity >= blocks_bytes &&
        g_ctx.ghash_chunks_capacity >= chunk_count &&
        g_ctx.ghash_blocks_buf &&
        g_ctx.ghash_chunks_buf &&
        g_ctx.ghash_final_buf) {
#ifdef CRYPTO_OCL_PROFILE
        crypto_ocl_profile_add_ensure_ghash(crypto_time_now_ns() - t0, 0, blocks_bytes, chunk_count);
#endif
        return CRYPTO_OK;
    }

    reallocated = 1;
    ocl_release_ghash_buffers();

    g_ctx.ghash_blocks_buf = clCreateBuffer(g_ctx.context, CL_MEM_READ_ONLY, blocks_bytes, NULL, &e);
    if (!g_ctx.ghash_blocks_buf || e != CL_SUCCESS) {
        format_cl_error(g_ctx.last_error, sizeof(g_ctx.last_error), "clCreateBuffer(ghash_blocks) failed", e);
        ocl_release_ghash_buffers();
        return CRYPTO_INTERNAL_ERROR;
    }

    g_ctx.ghash_chunks_buf = clCreateBuffer(g_ctx.context, CL_MEM_READ_WRITE, chunk_count * 2u * sizeof(uint64_t), NULL, &e);
    if (!g_ctx.ghash_chunks_buf || e != CL_SUCCESS) {
        format_cl_error(g_ctx.last_error, sizeof(g_ctx.last_error), "clCreateBuffer(ghash_chunks) failed", e);
        ocl_release_ghash_buffers();
        return CRYPTO_INTERNAL_ERROR;
    }

    g_ctx.ghash_final_buf = clCreateBuffer(g_ctx.context, CL_MEM_WRITE_ONLY, 2u * sizeof(uint64_t), NULL, &e);
    if (!g_ctx.ghash_final_buf || e != CL_SUCCESS) {
        format_cl_error(g_ctx.last_error, sizeof(g_ctx.last_error), "clCreateBuffer(ghash_final) failed", e);
        ocl_release_ghash_buffers();
        return CRYPTO_INTERNAL_ERROR;
    }

    g_ctx.ghash_blocks_capacity = blocks_bytes;
    g_ctx.ghash_chunks_capacity = chunk_count;
#ifdef CRYPTO_OCL_PROFILE
    crypto_ocl_profile_add_ensure_ghash(crypto_time_now_ns() - t0, reallocated, blocks_bytes, chunk_count);
#endif
    return CRYPTO_OK;
}

static size_t choose_local_size(size_t max_wg)
{
    const char* env = getenv("CRYPTO_OCL_LOCAL_SIZE");
    if (env && env[0]) {
        long v = strtol(env, NULL, 10);
        if (v > 0 && (size_t)v <= max_wg) {
            return (size_t)v;
        }
    }

    if (max_wg >= 256) {
        return 256;
    }
    if (max_wg >= 128) {
        return 128;
    }
    if (max_wg >= 64) {
        return 64;
    }
    if (max_wg >= 32) {
        return 32;
    }
    return 1;
}

static crypto_status_t ocl_write_buffer(cl_mem buffer, size_t offset, const void* src, size_t len)
{
    cl_int e;

    if (len == 0) {
        return CRYPTO_OK;
    }
    if (!buffer || !src) {
        ocl_set_error("Invalid argument");
        return CRYPTO_INVALID_ARG;
    }

    e = clEnqueueWriteBuffer(g_ctx.queue, buffer, CL_TRUE, offset, len, src, 0, NULL, NULL);
    if (e != CL_SUCCESS) {
        format_cl_error(g_ctx.last_error, sizeof(g_ctx.last_error), "clEnqueueWriteBuffer failed", e);
        return CRYPTO_INTERNAL_ERROR;
    }
    return CRYPTO_OK;
}

static crypto_status_t ocl_read_buffer(cl_mem buffer, size_t offset, void* dst, size_t len)
{
    cl_int e;

    if (len == 0) {
        return CRYPTO_OK;
    }
    if (!buffer || !dst) {
        ocl_set_error("Invalid argument");
        return CRYPTO_INVALID_ARG;
    }

    e = clEnqueueReadBuffer(g_ctx.queue, buffer, CL_TRUE, offset, len, dst, 0, NULL, NULL);
    if (e != CL_SUCCESS) {
        format_cl_error(g_ctx.last_error, sizeof(g_ctx.last_error), "clEnqueueReadBuffer failed", e);
        return CRYPTO_INTERNAL_ERROR;
    }
    return CRYPTO_OK;
}

static crypto_status_t ocl_copy_buffer(cl_mem src_buf, size_t src_offset, cl_mem dst_buf, size_t dst_offset, size_t len)
{
    cl_int e;

    if (len == 0) {
        return CRYPTO_OK;
    }
    if (!src_buf || !dst_buf) {
        ocl_set_error("Invalid argument");
        return CRYPTO_INVALID_ARG;
    }

    e = clEnqueueCopyBuffer(g_ctx.queue, src_buf, dst_buf, src_offset, dst_offset, len, 0, NULL, NULL);
    if (e != CL_SUCCESS) {
        format_cl_error(g_ctx.last_error, sizeof(g_ctx.last_error), "clEnqueueCopyBuffer failed", e);
        return CRYPTO_INTERNAL_ERROR;
    }
    return CRYPTO_OK;
}

static crypto_status_t ocl_launch_ctr_kernel(cl_kernel kernel_obj,
                                            size_t round_keys_len,
                                            uint64_t iv_hi,
                                            uint64_t iv_lo,
                                            size_t len,
                                            uint64_t block_offset,
                                            uint64_t* out_kernel_ns,
                                            int profile_ctr)
{
    cl_int e;
    cl_ulong total_len = (cl_ulong)len;
    cl_ulong cl_iv_hi = (cl_ulong)iv_hi;
    cl_ulong cl_iv_lo = (cl_ulong)iv_lo;
    cl_ulong cl_block_off = (cl_ulong)block_offset;
    cl_uint cl_rounds = (cl_uint)((round_keys_len / 16u) - 1u);
    size_t global;
    size_t local;
    cl_event evt = NULL;
    uint64_t t_stage;
    uint64_t device_kernel_ns = 0;

    if (out_kernel_ns) {
        *out_kernel_ns = 0;
    }
    if (!kernel_obj) {
        ocl_set_error("CTR kernel is not initialized");
        return CRYPTO_INTERNAL_ERROR;
    }

    t_stage = crypto_time_now_ns();
    e = clSetKernelArg(kernel_obj, 0, sizeof(cl_mem), &g_ctx.in_buf);
    if (e == CL_SUCCESS) {
        e = clSetKernelArg(kernel_obj, 1, sizeof(cl_mem), &g_ctx.out_buf);
    }
    if (e == CL_SUCCESS) {
        e = clSetKernelArg(kernel_obj, 2, sizeof(cl_ulong), &total_len);
    }
    if (e == CL_SUCCESS) {
        e = clSetKernelArg(kernel_obj, 3, sizeof(cl_mem), &g_ctx.round_keys_buf);
    }
    if (e == CL_SUCCESS) {
        e = clSetKernelArg(kernel_obj, 4, sizeof(cl_uint), &cl_rounds);
    }
    if (e == CL_SUCCESS) {
        e = clSetKernelArg(kernel_obj, 5, sizeof(cl_ulong), &cl_iv_hi);
    }
    if (e == CL_SUCCESS) {
        e = clSetKernelArg(kernel_obj, 6, sizeof(cl_ulong), &cl_iv_lo);
    }
    if (e == CL_SUCCESS) {
        e = clSetKernelArg(kernel_obj, 7, sizeof(cl_ulong), &cl_block_off);
    }
#ifdef CRYPTO_OCL_PROFILE
    if (profile_ctr) {
        crypto_ocl_profile_add_ctr_set_args(crypto_time_now_ns() - t_stage);
    }
#endif
    if (e != CL_SUCCESS) {
        format_cl_error(g_ctx.last_error, sizeof(g_ctx.last_error), "clSetKernelArg failed", e);
        return CRYPTO_INTERNAL_ERROR;
    }

    {
        size_t blocks = (len + 15) / 16;
        global = (blocks + 3) / 4;
    }
    local = choose_local_size(g_ctx.max_wg);
    if (local > global && global > 0) {
        local = global;
    }
    if (local == 0) {
        local = 1;
    }
    if (global % local != 0) {
        global = ((global + local - 1) / local) * local;
    }

    t_stage = crypto_time_now_ns();
#ifdef CRYPTO_OCL_PROFILE
    e = clEnqueueNDRangeKernel(g_ctx.queue, kernel_obj, 1, NULL, &global, &local, 0, NULL, &evt);
    if (profile_ctr) {
        crypto_ocl_profile_add_ctr_kernel_enqueue(crypto_time_now_ns() - t_stage, 0);
    }
#else
    e = clEnqueueNDRangeKernel(g_ctx.queue, kernel_obj, 1, NULL, &global, &local, 0, NULL, NULL);
#endif
    if (e != CL_SUCCESS) {
        format_cl_error(g_ctx.last_error, sizeof(g_ctx.last_error), "clEnqueueNDRangeKernel failed", e);
        if (evt) {
            clReleaseEvent(evt);
        }
        return CRYPTO_INTERNAL_ERROR;
    }

#ifdef CRYPTO_OCL_PROFILE
    if (evt) {
        cl_ulong te0 = 0;
        cl_ulong te1 = 0;
        if (clGetEventProfilingInfo(evt, CL_PROFILING_COMMAND_START, sizeof(cl_ulong), &te0, NULL) == CL_SUCCESS &&
            clGetEventProfilingInfo(evt, CL_PROFILING_COMMAND_END, sizeof(cl_ulong), &te1, NULL) == CL_SUCCESS &&
            te1 >= te0) {
            device_kernel_ns = (uint64_t)(te1 - te0);
        }
        if (profile_ctr) {
            crypto_ocl_profile_add_ctr_kernel_enqueue(0, device_kernel_ns);
        }
        clReleaseEvent(evt);
        evt = NULL;
    }
#endif

    if (out_kernel_ns) {
        *out_kernel_ns = device_kernel_ns;
    }
    return CRYPTO_OK;
}

static crypto_status_t ocl_upload_round_keys_if_needed(const uint8_t* round_keys, size_t round_keys_len)
{
    cl_int e;
    cl_uint rk_words[60];
    uint64_t t0 = crypto_time_now_ns();

    if (!round_keys) {
        ocl_set_error("Invalid argument");
        return CRYPTO_INVALID_ARG;
    }

    if (round_keys_len != 176 && round_keys_len != 208 && round_keys_len != 240) {
        ocl_set_error("Unsupported key size");
        return CRYPTO_UNSUPPORTED;
    }

    if (g_ctx.round_keys_cached && g_ctx.cached_round_keys_len == round_keys_len &&
        memcmp(g_ctx.cached_round_keys, round_keys, round_keys_len) == 0) {
#ifdef CRYPTO_OCL_PROFILE
        crypto_ocl_profile_add_round_key_upload(crypto_time_now_ns() - t0, 1);
#endif
        return CRYPTO_OK;
    }

    pack_round_keys_words(rk_words, round_keys, round_keys_len);

    e = clEnqueueWriteBuffer(g_ctx.queue, g_ctx.round_keys_buf, CL_TRUE, 0, sizeof(rk_words), rk_words, 0, NULL, NULL);
    if (e != CL_SUCCESS) {
        format_cl_error(g_ctx.last_error, sizeof(g_ctx.last_error), "clEnqueueWriteBuffer(round_keys) failed", e);
        secure_zero(rk_words, sizeof(rk_words));
        return CRYPTO_INTERNAL_ERROR;
    }

    memcpy(g_ctx.cached_round_keys, round_keys, round_keys_len);
    if (round_keys_len < sizeof(g_ctx.cached_round_keys)) {
        memset(g_ctx.cached_round_keys + round_keys_len, 0, sizeof(g_ctx.cached_round_keys) - round_keys_len);
    }
    g_ctx.cached_round_keys_len = round_keys_len;
    g_ctx.round_keys_cached = 1;

    secure_zero(rk_words, sizeof(rk_words));
#ifdef CRYPTO_OCL_PROFILE
    crypto_ocl_profile_add_round_key_upload(crypto_time_now_ns() - t0, 0);
#endif
    return CRYPTO_OK;
}

crypto_status_t crypto_ocl_aes_ctr_xor_round_keys(const uint8_t* round_keys,
                                                 size_t round_keys_len,
                                                 const uint8_t iv16[16],
                                                 const uint8_t* input,
                                                 uint8_t* output,
                                                 size_t len,
                                                 uint64_t block_offset,
                                                 uint64_t* out_kernel_ns)
{
    crypto_status_t st;
    cl_int e;
    uint64_t iv_hi;
    uint64_t iv_lo;
    cl_ulong total_len;
    cl_ulong cl_iv_hi;
    cl_ulong cl_iv_lo;
    cl_ulong cl_block_off;
    size_t global;
    size_t local;
    cl_event evt = NULL;
    uint64_t t_total = crypto_time_now_ns();
    uint64_t t_stage = 0;
    uint64_t device_kernel_ns = 0;

    if (out_kernel_ns) {
        *out_kernel_ns = 0;
    }

    if (!round_keys || !iv16 || !input || !output) {
        ocl_set_error("Invalid argument");
        return CRYPTO_INVALID_ARG;
    }

    if (len == 0) {
        return CRYPTO_OK;
    }

    st = ocl_init_if_needed();
    if (st != CRYPTO_OK) {
        return st;
    }

    st = ocl_ensure_io_buffers(len);
    if (st != CRYPTO_OK) {
        return st;
    }

    st = ocl_upload_round_keys_if_needed(round_keys, round_keys_len);
    if (st != CRYPTO_OK) {
        return st;
    }

    iv_hi = be64_load(iv16);
    iv_lo = be64_load(iv16 + 8);

    t_stage = crypto_time_now_ns();
    e = clEnqueueWriteBuffer(g_ctx.queue, g_ctx.in_buf, CL_TRUE, 0, len, input, 0, NULL, NULL);
#ifdef CRYPTO_OCL_PROFILE
    crypto_ocl_profile_add_ctr_host_to_device(crypto_time_now_ns() - t_stage);
#endif
    if (e != CL_SUCCESS) {
        format_cl_error(g_ctx.last_error, sizeof(g_ctx.last_error), "clEnqueueWriteBuffer(input) failed", e);
        return CRYPTO_INTERNAL_ERROR;
    }

    total_len = (cl_ulong)len;
    cl_iv_hi = (cl_ulong)iv_hi;
    cl_iv_lo = (cl_ulong)iv_lo;
    cl_block_off = (cl_ulong)block_offset;

    cl_uint cl_rounds = (cl_uint)((round_keys_len / 16u) - 1u);

    t_stage = crypto_time_now_ns();
    e = clSetKernelArg(g_ctx.kernel, 0, sizeof(cl_mem), &g_ctx.in_buf);
    if (e == CL_SUCCESS) {
        e = clSetKernelArg(g_ctx.kernel, 1, sizeof(cl_mem), &g_ctx.out_buf);
    }
    if (e == CL_SUCCESS) {
        e = clSetKernelArg(g_ctx.kernel, 2, sizeof(cl_ulong), &total_len);
    }
    if (e == CL_SUCCESS) {
        e = clSetKernelArg(g_ctx.kernel, 3, sizeof(cl_mem), &g_ctx.round_keys_buf);
    }
    if (e == CL_SUCCESS) {
        e = clSetKernelArg(g_ctx.kernel, 4, sizeof(cl_uint), &cl_rounds);
    }
    if (e == CL_SUCCESS) {
        e = clSetKernelArg(g_ctx.kernel, 5, sizeof(cl_ulong), &cl_iv_hi);
    }
    if (e == CL_SUCCESS) {
        e = clSetKernelArg(g_ctx.kernel, 6, sizeof(cl_ulong), &cl_iv_lo);
    }
    if (e == CL_SUCCESS) {
        e = clSetKernelArg(g_ctx.kernel, 7, sizeof(cl_ulong), &cl_block_off);
    }
#ifdef CRYPTO_OCL_PROFILE
    crypto_ocl_profile_add_ctr_set_args(crypto_time_now_ns() - t_stage);
#endif
    if (e != CL_SUCCESS) {
        format_cl_error(g_ctx.last_error, sizeof(g_ctx.last_error), "clSetKernelArg failed", e);
        return CRYPTO_INTERNAL_ERROR;
    }

    {
        size_t blocks = (len + 15) / 16;
        global = (blocks + 3) / 4;
    }
    local = choose_local_size(g_ctx.max_wg);
    if (local > global && global > 0) {
        local = global;
    }
    if (local == 0) {
        local = 1;
    }
    if (global % local != 0) {
        global = ((global + local - 1) / local) * local;
    }

    t_stage = crypto_time_now_ns();
#ifdef CRYPTO_OCL_PROFILE
    e = clEnqueueNDRangeKernel(g_ctx.queue, g_ctx.kernel, 1, NULL, &global, &local, 0, NULL, &evt);
#else
    e = clEnqueueNDRangeKernel(g_ctx.queue, g_ctx.kernel, 1, NULL, &global, &local, 0, NULL, NULL);
#endif
#ifdef CRYPTO_OCL_PROFILE
    crypto_ocl_profile_add_ctr_kernel_enqueue(crypto_time_now_ns() - t_stage, 0);
#endif
    if (e != CL_SUCCESS) {
        format_cl_error(g_ctx.last_error, sizeof(g_ctx.last_error), "clEnqueueNDRangeKernel failed", e);
        if (evt) {
            clReleaseEvent(evt);
        }
        return CRYPTO_INTERNAL_ERROR;
    }

    t_stage = crypto_time_now_ns();
    e = clEnqueueReadBuffer(g_ctx.queue, g_ctx.out_buf, CL_TRUE, 0, len, output, 0, NULL, NULL);
#ifdef CRYPTO_OCL_PROFILE
    crypto_ocl_profile_add_ctr_device_to_host(crypto_time_now_ns() - t_stage);
#endif
    if (e != CL_SUCCESS) {
        format_cl_error(g_ctx.last_error, sizeof(g_ctx.last_error), "clEnqueueReadBuffer(output) failed", e);
        return CRYPTO_INTERNAL_ERROR;
    }

#ifdef CRYPTO_OCL_PROFILE
    if (evt) {
        cl_ulong te0 = 0;
        cl_ulong te1 = 0;
        if (clGetEventProfilingInfo(evt, CL_PROFILING_COMMAND_START, sizeof(cl_ulong), &te0, NULL) == CL_SUCCESS &&
            clGetEventProfilingInfo(evt, CL_PROFILING_COMMAND_END, sizeof(cl_ulong), &te1, NULL) == CL_SUCCESS &&
            te1 >= te0) {
            device_kernel_ns = (uint64_t)(te1 - te0);
        }
        crypto_ocl_profile_add_ctr_kernel_enqueue(0, device_kernel_ns);
    }
#endif
    if (out_kernel_ns) {
        *out_kernel_ns = device_kernel_ns;
    }
    if (evt) {
        clReleaseEvent(evt);
        evt = NULL;
    }
#ifdef CRYPTO_OCL_PROFILE
    crypto_ocl_profile_add_ctr_total(crypto_time_now_ns() - t_total, len);
#endif
    return CRYPTO_OK;
}

crypto_status_t crypto_ocl_aes_ctr_xor(const uint8_t* key,
                                      size_t key_len_bytes,
                                      const uint8_t iv16[16],
                                         const uint8_t* input,
                                         uint8_t* output,
                                         size_t len,
                                         uint64_t block_offset,
                                         uint64_t* out_kernel_ns)
{
    crypto_aes_t aes;
    crypto_status_t st;
    uint64_t t_key_schedule = 0;

    if (!key || !iv16 || !input || !output) {
        ocl_set_error("Invalid argument");
        return CRYPTO_INVALID_ARG;
    }

    if (len == 0) {
        return CRYPTO_OK;
    }

    t_key_schedule = crypto_time_now_ns();
    st = crypto_aes_init(&aes, key, key_len_bytes);
#ifdef CRYPTO_OCL_PROFILE
    crypto_ocl_profile_add_ctr_key_schedule(crypto_time_now_ns() - t_key_schedule);
#endif
    if (st != CRYPTO_OK) {
        ocl_set_error("AES key expansion failed");
        return st;
    }

    st = crypto_ocl_aes_ctr_xor_round_keys(aes.round_keys, crypto_aes_round_keys_bytes(&aes), iv16, input, output, len, block_offset, out_kernel_ns);

    crypto_aes_clear(&aes);
    return st;
}

static void be64_store(uint64_t v, uint8_t out[8])
{
    out[0] = (uint8_t)(v >> 56);
    out[1] = (uint8_t)(v >> 48);
    out[2] = (uint8_t)(v >> 40);
    out[3] = (uint8_t)(v >> 32);
    out[4] = (uint8_t)(v >> 24);
    out[5] = (uint8_t)(v >> 16);
    out[6] = (uint8_t)(v >> 8);
    out[7] = (uint8_t)(v);
}

static int ct_mem_equal_16(const uint8_t a[16], const uint8_t b[16])
{
    uint8_t r = 0;
    for (int i = 0; i < 16; i++) {
        r |= (uint8_t)(a[i] ^ b[i]);
    }
    return r == 0;
}

static void ghash_update_block_cpu(const uint8_t h[16], uint8_t y[16], const uint8_t x[16])
{
    uint8_t t[16];
    crypto_gf128_xor(t, y, x);
    crypto_gf128_mul(t, h, y);
    secure_zero(t, sizeof(t));
}

static void ghash_update_bytes_cpu(const uint8_t h[16], uint8_t y[16], const uint8_t* data, size_t data_len)
{
    size_t full = (data_len / 16) * 16;
    size_t rem = data_len - full;

    for (size_t off = 0; off < full; off += 16) {
        ghash_update_block_cpu(h, y, data + off);
    }

    if (rem) {
        uint8_t last[16];
        memset(last, 0, sizeof(last));
        memcpy(last, data + full, rem);
        ghash_update_block_cpu(h, y, last);
        secure_zero(last, sizeof(last));
    }
}

static void ghash_lengths_cpu(const uint8_t h[16], uint8_t y[16], uint64_t aad_len, uint64_t ct_len)
{
    uint8_t blk[16];
    be64_store(aad_len * 8u, blk);
    be64_store(ct_len * 8u, blk + 8);
    ghash_update_block_cpu(h, y, blk);
    secure_zero(blk, sizeof(blk));
}

static void gcm_compute_j0_cpu(const uint8_t h[16], const uint8_t* iv, size_t iv_len, uint8_t j0[16])
{
    if (iv_len == 12) {
        memcpy(j0, iv, 12);
        j0[12] = 0;
        j0[13] = 0;
        j0[14] = 0;
        j0[15] = 1;
        return;
    }

    memset(j0, 0, 16);
    ghash_update_bytes_cpu(h, j0, iv, iv_len);
    ghash_lengths_cpu(h, j0, 0, (uint64_t)iv_len);
}

static size_t gcm_choose_chunk_blocks(size_t num_blocks)
{
    const char* env = getenv("CRYPTO_OCL_GHASH_CHUNK_BLOCKS");
    size_t v;

    if (env && env[0]) {
        unsigned long long tmp = strtoull(env, NULL, 10);
        if (tmp > 0) {
            v = (size_t)tmp;
        } else {
            v = 1024;
        }
    } else if (num_blocks >= 262144u) {
        v = 2048;
    } else if (num_blocks >= 16384u) {
        v = 1024;
    } else if (num_blocks >= 2048u) {
        v = 512;
    } else {
        v = 256;
    }

    if (v < 64) {
        v = 64;
    }
    if (v > 16384) {
        v = 16384;
    }
    return v;
}

static crypto_status_t gcm_ghash_opencl(const uint8_t h[16],
                                       const uint8_t* aad,
                                       size_t aad_len,
                                       const uint8_t* ct_host,
                                       size_t ct_len,
                                       cl_mem ct_device_buf,
                                       uint8_t y_out[16],
                                       uint64_t* out_kernel_ns)
{
    crypto_status_t st;
    size_t aad_blocks = (aad_len + 15) / 16;
    size_t ct_blocks = (ct_len + 15) / 16;
    size_t num_blocks = aad_blocks + ct_blocks + 1;
    size_t blocks_bytes = num_blocks * 16;

    size_t chunk_blocks = gcm_choose_chunk_blocks(num_blocks);
    size_t chunk_count = (num_blocks + chunk_blocks - 1) / chunk_blocks;
    size_t last_len = num_blocks - (chunk_count - 1) * chunk_blocks;

    cl_int e;
    size_t global;
    size_t local;
    cl_event evt_chunk = NULL;
    cl_event evt_reduce = NULL;

    uint64_t cl_num_blocks;
    uint64_t cl_chunk_count;
    uint32_t cl_chunk_blocks;
    uint64_t h_hi;
    uint64_t h_lo;
    uint64_t final_hash[2];
    uint8_t len_blk[16];
    uint8_t pow_full[16];
    uint8_t pow_last[16];
    uint64_t pow_full_hi;
    uint64_t pow_full_lo;
    uint64_t pow_last_hi;
    uint64_t pow_last_lo;
    uint64_t t_total = crypto_time_now_ns();
    uint64_t t_stage = 0;
    uint64_t device_chunk_ns = 0;
    uint64_t device_reduce_ns = 0;

    if (out_kernel_ns) {
        *out_kernel_ns = 0;
    }
    if (!h || !y_out) {
        ocl_set_error("Invalid argument");
        return CRYPTO_INVALID_ARG;
    }
    if (ct_len && !ct_host && !ct_device_buf) {
        ocl_set_error("Invalid argument");
        return CRYPTO_INVALID_ARG;
    }
    if (aad_len && !aad) {
        ocl_set_error("Invalid argument");
        return CRYPTO_INVALID_ARG;
    }

    if (last_len == 0) {
        last_len = chunk_blocks;
    }

    st = ocl_init_if_needed();
    if (st != CRYPTO_OK) {
        return st;
    }

    st = ocl_ensure_ghash_buffers(blocks_bytes, chunk_count);
    if (st != CRYPTO_OK) {
        return st;
    }

    if (aad_len) {
        size_t aad_full = (aad_len / 16) * 16;
        size_t aad_rem = aad_len - aad_full;

        if (aad_full) {
            t_stage = crypto_time_now_ns();
            st = ocl_write_buffer(g_ctx.ghash_blocks_buf, 0, aad, aad_full);
#ifdef CRYPTO_OCL_PROFILE
            crypto_ocl_profile_add_ghash_host_to_device(crypto_time_now_ns() - t_stage);
#endif
            if (st != CRYPTO_OK) {
                return st;
            }
        }
        if (aad_rem) {
            uint8_t tail[16];
            memset(tail, 0, sizeof(tail));
            memcpy(tail, aad + aad_full, aad_rem);
            t_stage = crypto_time_now_ns();
            st = ocl_write_buffer(g_ctx.ghash_blocks_buf, aad_full, tail, 16);
#ifdef CRYPTO_OCL_PROFILE
            crypto_ocl_profile_add_ghash_host_to_device(crypto_time_now_ns() - t_stage);
#endif
            secure_zero(tail, sizeof(tail));
            if (st != CRYPTO_OK) {
                return st;
            }
        }
    }

    if (ct_len) {
        size_t ct_offset = aad_blocks * 16;
        size_t ct_full = (ct_len / 16) * 16;
        size_t ct_rem = ct_len - ct_full;

        if (ct_full) {
            t_stage = crypto_time_now_ns();
            if (ct_device_buf) {
                st = ocl_copy_buffer(ct_device_buf, 0, g_ctx.ghash_blocks_buf, ct_offset, ct_full);
#ifdef CRYPTO_OCL_PROFILE
                crypto_ocl_profile_add_ghash_device_copy(crypto_time_now_ns() - t_stage);
#endif
            } else {
                st = ocl_write_buffer(g_ctx.ghash_blocks_buf, ct_offset, ct_host, ct_full);
#ifdef CRYPTO_OCL_PROFILE
                crypto_ocl_profile_add_ghash_host_to_device(crypto_time_now_ns() - t_stage);
#endif
            }
            if (st != CRYPTO_OK) {
                return st;
            }
        }

        if (ct_rem) {
            uint8_t tail[16];
            memset(tail, 0, sizeof(tail));
            if (ct_host) {
                memcpy(tail, ct_host + ct_full, ct_rem);
            } else {
                st = ocl_read_buffer(ct_device_buf, ct_full, tail, ct_rem);
                if (st != CRYPTO_OK) {
                    secure_zero(tail, sizeof(tail));
                    return st;
                }
            }

            t_stage = crypto_time_now_ns();
            st = ocl_write_buffer(g_ctx.ghash_blocks_buf, ct_offset + ct_full, tail, 16);
#ifdef CRYPTO_OCL_PROFILE
            crypto_ocl_profile_add_ghash_host_to_device(crypto_time_now_ns() - t_stage);
#endif
            secure_zero(tail, sizeof(tail));
            if (st != CRYPTO_OK) {
                return st;
            }
        }
    }

    be64_store((uint64_t)aad_len * 8u, len_blk);
    be64_store((uint64_t)ct_len * 8u, len_blk + 8);
    t_stage = crypto_time_now_ns();
    st = ocl_write_buffer(g_ctx.ghash_blocks_buf, (num_blocks - 1) * 16, len_blk, 16);
#ifdef CRYPTO_OCL_PROFILE
    crypto_ocl_profile_add_ghash_host_to_device(crypto_time_now_ns() - t_stage);
#endif
    secure_zero(len_blk, sizeof(len_blk));
    if (st != CRYPTO_OK) {
        return st;
    }

    crypto_gf128_pow(h, (uint64_t)chunk_blocks, pow_full);
    crypto_gf128_pow(h, (uint64_t)last_len, pow_last);
    pow_full_hi = be64_load(pow_full);
    pow_full_lo = be64_load(pow_full + 8);
    pow_last_hi = be64_load(pow_last);
    pow_last_lo = be64_load(pow_last + 8);
    secure_zero(pow_full, sizeof(pow_full));
    secure_zero(pow_last, sizeof(pow_last));

    h_hi = (uint64_t)be64_load(h);
    h_lo = (uint64_t)be64_load(h + 8);
    cl_num_blocks = (uint64_t)num_blocks;
    cl_chunk_count = (uint64_t)chunk_count;
    cl_chunk_blocks = (uint32_t)chunk_blocks;

    t_stage = crypto_time_now_ns();
    e = clSetKernelArg(g_ctx.ghash_kernel, 0, sizeof(cl_mem), &g_ctx.ghash_blocks_buf);
    if (e == CL_SUCCESS) {
        e = clSetKernelArg(g_ctx.ghash_kernel, 1, sizeof(cl_mem), &g_ctx.ghash_chunks_buf);
    }
    if (e == CL_SUCCESS) {
        e = clSetKernelArg(g_ctx.ghash_kernel, 2, sizeof(uint64_t), &cl_num_blocks);
    }
    if (e == CL_SUCCESS) {
        e = clSetKernelArg(g_ctx.ghash_kernel, 3, sizeof(uint32_t), &cl_chunk_blocks);
    }
    if (e == CL_SUCCESS) {
        e = clSetKernelArg(g_ctx.ghash_kernel, 4, sizeof(uint64_t), &h_hi);
    }
    if (e == CL_SUCCESS) {
        e = clSetKernelArg(g_ctx.ghash_kernel, 5, sizeof(uint64_t), &h_lo);
    }
#ifdef CRYPTO_OCL_PROFILE
    crypto_ocl_profile_add_ghash_set_args(crypto_time_now_ns() - t_stage);
#endif
    if (e != CL_SUCCESS) {
        format_cl_error(g_ctx.last_error, sizeof(g_ctx.last_error), "clSetKernelArg(ghash) failed", e);
        return CRYPTO_INTERNAL_ERROR;
    }

    global = chunk_count;
    local = choose_local_size(g_ctx.max_wg);
    if (local > global && global > 0) {
        local = global;
    }
    if (local == 0) {
        local = 1;
    }
    if (global % local != 0) {
        global = ((global + local - 1) / local) * local;
    }

    t_stage = crypto_time_now_ns();
#ifdef CRYPTO_OCL_PROFILE
    e = clEnqueueNDRangeKernel(g_ctx.queue, g_ctx.ghash_kernel, 1, NULL, &global, &local, 0, NULL, &evt_chunk);
    crypto_ocl_profile_add_ghash_kernel_enqueue(crypto_time_now_ns() - t_stage, 0);
#else
    e = clEnqueueNDRangeKernel(g_ctx.queue, g_ctx.ghash_kernel, 1, NULL, &global, &local, 0, NULL, NULL);
#endif
    if (e != CL_SUCCESS) {
        format_cl_error(g_ctx.last_error, sizeof(g_ctx.last_error), "clEnqueueNDRangeKernel(ghash) failed", e);
        if (evt_chunk) {
            clReleaseEvent(evt_chunk);
        }
        return CRYPTO_INTERNAL_ERROR;
    }

    t_stage = crypto_time_now_ns();
    e = clSetKernelArg(g_ctx.ghash_reduce_kernel, 0, sizeof(cl_mem), &g_ctx.ghash_chunks_buf);
    if (e == CL_SUCCESS) {
        e = clSetKernelArg(g_ctx.ghash_reduce_kernel, 1, sizeof(cl_mem), &g_ctx.ghash_final_buf);
    }
    if (e == CL_SUCCESS) {
        e = clSetKernelArg(g_ctx.ghash_reduce_kernel, 2, sizeof(uint64_t), &cl_chunk_count);
    }
    if (e == CL_SUCCESS) {
        e = clSetKernelArg(g_ctx.ghash_reduce_kernel, 3, sizeof(uint64_t), &pow_full_hi);
    }
    if (e == CL_SUCCESS) {
        e = clSetKernelArg(g_ctx.ghash_reduce_kernel, 4, sizeof(uint64_t), &pow_full_lo);
    }
    if (e == CL_SUCCESS) {
        e = clSetKernelArg(g_ctx.ghash_reduce_kernel, 5, sizeof(uint64_t), &pow_last_hi);
    }
    if (e == CL_SUCCESS) {
        e = clSetKernelArg(g_ctx.ghash_reduce_kernel, 6, sizeof(uint64_t), &pow_last_lo);
    }
#ifdef CRYPTO_OCL_PROFILE
    crypto_ocl_profile_add_ghash_reduce_set_args(crypto_time_now_ns() - t_stage);
#endif
    if (e != CL_SUCCESS) {
        format_cl_error(g_ctx.last_error, sizeof(g_ctx.last_error), "clSetKernelArg(ghash_reduce) failed", e);
        if (evt_chunk) {
            clReleaseEvent(evt_chunk);
        }
        return CRYPTO_INTERNAL_ERROR;
    }

    global = 1;
    local = 1;
    t_stage = crypto_time_now_ns();
#ifdef CRYPTO_OCL_PROFILE
    e = clEnqueueNDRangeKernel(g_ctx.queue, g_ctx.ghash_reduce_kernel, 1, NULL, &global, &local, 0, NULL, &evt_reduce);
    crypto_ocl_profile_add_ghash_reduce_kernel_enqueue(crypto_time_now_ns() - t_stage, 0);
#else
    e = clEnqueueNDRangeKernel(g_ctx.queue, g_ctx.ghash_reduce_kernel, 1, NULL, &global, &local, 0, NULL, NULL);
#endif
    if (e != CL_SUCCESS) {
        format_cl_error(g_ctx.last_error, sizeof(g_ctx.last_error), "clEnqueueNDRangeKernel(ghash_reduce) failed", e);
        if (evt_chunk) {
            clReleaseEvent(evt_chunk);
        }
        if (evt_reduce) {
            clReleaseEvent(evt_reduce);
        }
        return CRYPTO_INTERNAL_ERROR;
    }

    t_stage = crypto_time_now_ns();
    st = ocl_read_buffer(g_ctx.ghash_final_buf, 0, final_hash, sizeof(final_hash));
#ifdef CRYPTO_OCL_PROFILE
    crypto_ocl_profile_add_ghash_reduce_device_to_host(crypto_time_now_ns() - t_stage);
#endif
    if (st != CRYPTO_OK) {
        if (evt_chunk) {
            clReleaseEvent(evt_chunk);
        }
        if (evt_reduce) {
            clReleaseEvent(evt_reduce);
        }
        return st;
    }

#ifdef CRYPTO_OCL_PROFILE
    if (evt_chunk) {
        cl_ulong te0 = 0;
        cl_ulong te1 = 0;
        if (clGetEventProfilingInfo(evt_chunk, CL_PROFILING_COMMAND_START, sizeof(cl_ulong), &te0, NULL) == CL_SUCCESS &&
            clGetEventProfilingInfo(evt_chunk, CL_PROFILING_COMMAND_END, sizeof(cl_ulong), &te1, NULL) == CL_SUCCESS &&
            te1 >= te0) {
            device_chunk_ns = (uint64_t)(te1 - te0);
        }
        crypto_ocl_profile_add_ghash_kernel_enqueue(0, device_chunk_ns);
        clReleaseEvent(evt_chunk);
        evt_chunk = NULL;
    }
    if (evt_reduce) {
        cl_ulong te0 = 0;
        cl_ulong te1 = 0;
        if (clGetEventProfilingInfo(evt_reduce, CL_PROFILING_COMMAND_START, sizeof(cl_ulong), &te0, NULL) == CL_SUCCESS &&
            clGetEventProfilingInfo(evt_reduce, CL_PROFILING_COMMAND_END, sizeof(cl_ulong), &te1, NULL) == CL_SUCCESS &&
            te1 >= te0) {
            device_reduce_ns = (uint64_t)(te1 - te0);
        }
        crypto_ocl_profile_add_ghash_reduce_kernel_enqueue(0, device_reduce_ns);
        clReleaseEvent(evt_reduce);
        evt_reduce = NULL;
    }
#endif

    if (out_kernel_ns) {
        *out_kernel_ns = device_chunk_ns + device_reduce_ns;
    }

    be64_store(final_hash[0], y_out);
    be64_store(final_hash[1], y_out + 8);
    secure_zero(final_hash, sizeof(final_hash));
#ifdef CRYPTO_OCL_PROFILE
    crypto_ocl_profile_add_ghash_total(crypto_time_now_ns() - t_total, blocks_bytes);
#endif
    return CRYPTO_OK;
}

crypto_status_t crypto_ocl_aes_gcm_encrypt(const uint8_t* key,
                                          size_t key_len_bytes,
                                          const uint8_t* iv,
                                          size_t iv_len,
                                          const uint8_t* aad,
                                          size_t aad_len,
                                          const uint8_t* plaintext,
                                          size_t plaintext_len,
                                          uint8_t* ciphertext_out,
                                          uint8_t tag16_out[16],
                                          uint64_t* out_kernel_ns)
{
    crypto_aes_t aes;
    crypto_status_t st;
    uint8_t h[16];
    uint8_t j0[16];
    uint8_t y[16];
    uint8_t s[16];
    uint64_t k1 = 0;
    uint64_t k2 = 0;
    uint64_t t_total = crypto_time_now_ns();
    uint64_t t_stage = 0;

    if (out_kernel_ns) {
        *out_kernel_ns = 0;
    }

    if (!key || !iv || !ciphertext_out || !tag16_out) {
        ocl_set_error("Invalid argument");
        return CRYPTO_INVALID_ARG;
    }
    if (plaintext_len && !plaintext) {
        ocl_set_error("Invalid argument");
        return CRYPTO_INVALID_ARG;
    }
    if (aad_len && !aad) {
        ocl_set_error("Invalid argument");
        return CRYPTO_INVALID_ARG;
    }

    t_stage = crypto_time_now_ns();
    st = crypto_aes_init(&aes, key, key_len_bytes);
    if (st != CRYPTO_OK) {
        ocl_set_error("AES key expansion failed");
        return st;
    }

    memset(h, 0, sizeof(h));
    crypto_aes_encrypt_block(&aes, h, h);
    gcm_compute_j0_cpu(h, iv, iv_len, j0);
#ifdef CRYPTO_OCL_PROFILE
    crypto_ocl_profile_add_gcm_cpu_prep(crypto_time_now_ns() - t_stage);
#endif

    if (plaintext_len) {
        t_stage = crypto_time_now_ns();
        st = crypto_ocl_aes_gcm_ctr_xor_round_keys_internal(aes.round_keys, crypto_aes_round_keys_bytes(&aes), j0, plaintext, ciphertext_out, plaintext_len, 1, 1, 1, &k1);
#ifdef CRYPTO_OCL_PROFILE
        crypto_ocl_profile_add_gcm_ctr_stage(crypto_time_now_ns() - t_stage);
#endif
        if (st != CRYPTO_OK) {
            crypto_aes_clear(&aes);
            secure_zero(h, sizeof(h));
            secure_zero(j0, sizeof(j0));
            return st;
        }
    }

    t_stage = crypto_time_now_ns();
    st = gcm_ghash_opencl(h, aad, aad_len, plaintext_len ? ciphertext_out : NULL, plaintext_len, plaintext_len ? g_ctx.out_buf : NULL, y, &k2);
#ifdef CRYPTO_OCL_PROFILE
    crypto_ocl_profile_add_gcm_ghash_stage(crypto_time_now_ns() - t_stage);
#endif
    if (st != CRYPTO_OK) {
        crypto_aes_clear(&aes);
        secure_zero(h, sizeof(h));
        secure_zero(j0, sizeof(j0));
        secure_zero(y, sizeof(y));
        return st;
    }

    t_stage = crypto_time_now_ns();
    crypto_aes_encrypt_block(&aes, j0, s);
    crypto_gf128_xor(tag16_out, y, s);
#ifdef CRYPTO_OCL_PROFILE
    crypto_ocl_profile_add_gcm_tag_finalize(crypto_time_now_ns() - t_stage);
#endif

    if (out_kernel_ns) {
        *out_kernel_ns = k1 + k2;
    }

    crypto_aes_clear(&aes);
    secure_zero(h, sizeof(h));
    secure_zero(j0, sizeof(j0));
    secure_zero(y, sizeof(y));
    secure_zero(s, sizeof(s));
#ifdef CRYPTO_OCL_PROFILE
    crypto_ocl_profile_add_gcm_encrypt_total(crypto_time_now_ns() - t_total, plaintext_len);
#endif
    return CRYPTO_OK;
}

crypto_status_t crypto_ocl_aes_gcm_decrypt(const uint8_t* key,
                                          size_t key_len_bytes,
                                          const uint8_t* iv,
                                          size_t iv_len,
                                          const uint8_t* aad,
                                          size_t aad_len,
                                          const uint8_t* ciphertext,
                                          size_t ciphertext_len,
                                          const uint8_t tag16[16],
                                          uint8_t* plaintext_out,
                                          uint64_t* out_kernel_ns)
{
    crypto_aes_t aes;
    crypto_status_t st;
    uint8_t h[16];
    uint8_t j0[16];
    uint8_t y[16];
    uint8_t s[16];
    uint8_t expected[16];
    uint64_t k1 = 0;
    uint64_t k2 = 0;
    uint64_t t_total = crypto_time_now_ns();
    uint64_t t_stage = 0;

    if (out_kernel_ns) {
        *out_kernel_ns = 0;
    }

    if (!key || !iv || !ciphertext || !tag16 || !plaintext_out) {
        ocl_set_error("Invalid argument");
        return CRYPTO_INVALID_ARG;
    }
    if (aad_len && !aad) {
        ocl_set_error("Invalid argument");
        return CRYPTO_INVALID_ARG;
    }

    t_stage = crypto_time_now_ns();
    st = crypto_aes_init(&aes, key, key_len_bytes);
    if (st != CRYPTO_OK) {
        ocl_set_error("AES key expansion failed");
        return st;
    }

    memset(h, 0, sizeof(h));
    crypto_aes_encrypt_block(&aes, h, h);
    gcm_compute_j0_cpu(h, iv, iv_len, j0);
#ifdef CRYPTO_OCL_PROFILE
    crypto_ocl_profile_add_gcm_cpu_prep(crypto_time_now_ns() - t_stage);
#endif

    t_stage = crypto_time_now_ns();
    if (ciphertext_len) {
        t_stage = crypto_time_now_ns();
        st = ocl_init_if_needed();
        if (st == CRYPTO_OK) {
            st = ocl_ensure_io_buffers(ciphertext_len);
        }
        if (st == CRYPTO_OK) {
            st = ocl_write_buffer(g_ctx.in_buf, 0, ciphertext, ciphertext_len);
        }
#ifdef CRYPTO_OCL_PROFILE
        crypto_ocl_profile_add_ghash_host_to_device(crypto_time_now_ns() - t_stage);
#endif
        if (st != CRYPTO_OK) {
            crypto_aes_clear(&aes);
            secure_zero(h, sizeof(h));
            secure_zero(j0, sizeof(j0));
            return st;
        }
    }

    st = gcm_ghash_opencl(h, aad, aad_len, ciphertext_len ? ciphertext : NULL, ciphertext_len, ciphertext_len ? g_ctx.in_buf : NULL, y, &k2);
#ifdef CRYPTO_OCL_PROFILE
    crypto_ocl_profile_add_gcm_ghash_stage(crypto_time_now_ns() - t_stage);
#endif
    if (st != CRYPTO_OK) {
        crypto_aes_clear(&aes);
        secure_zero(h, sizeof(h));
        secure_zero(j0, sizeof(j0));
        return st;
    }

    t_stage = crypto_time_now_ns();
    crypto_aes_encrypt_block(&aes, j0, s);
    crypto_gf128_xor(expected, y, s);
#ifdef CRYPTO_OCL_PROFILE
    crypto_ocl_profile_add_gcm_tag_finalize(crypto_time_now_ns() - t_stage);
#endif

    t_stage = crypto_time_now_ns();
    if (!ct_mem_equal_16(expected, tag16)) {
#ifdef CRYPTO_OCL_PROFILE
        crypto_ocl_profile_add_gcm_auth_check(crypto_time_now_ns() - t_stage);
#endif
        crypto_aes_clear(&aes);
        secure_zero(h, sizeof(h));
        secure_zero(j0, sizeof(j0));
        secure_zero(y, sizeof(y));
        secure_zero(s, sizeof(s));
        secure_zero(expected, sizeof(expected));
        return CRYPTO_AUTH_FAILED;
    }
#ifdef CRYPTO_OCL_PROFILE
    crypto_ocl_profile_add_gcm_auth_check(crypto_time_now_ns() - t_stage);
#endif

    if (ciphertext_len) {
        t_stage = crypto_time_now_ns();
        st = crypto_ocl_aes_gcm_ctr_xor_round_keys_internal(aes.round_keys, crypto_aes_round_keys_bytes(&aes), j0, NULL, plaintext_out, ciphertext_len, 1, 0, 1, &k1);
#ifdef CRYPTO_OCL_PROFILE
        crypto_ocl_profile_add_gcm_ctr_stage(crypto_time_now_ns() - t_stage);
#endif
        if (st != CRYPTO_OK) {
            crypto_aes_clear(&aes);
            secure_zero(h, sizeof(h));
            secure_zero(j0, sizeof(j0));
            secure_zero(y, sizeof(y));
            secure_zero(s, sizeof(s));
            secure_zero(expected, sizeof(expected));
            return st;
        }
    }

    if (out_kernel_ns) {
        *out_kernel_ns = k1 + k2;
    }

    crypto_aes_clear(&aes);
    secure_zero(h, sizeof(h));
    secure_zero(j0, sizeof(j0));
    secure_zero(y, sizeof(y));
    secure_zero(s, sizeof(s));
    secure_zero(expected, sizeof(expected));
#ifdef CRYPTO_OCL_PROFILE
    crypto_ocl_profile_add_gcm_decrypt_total(crypto_time_now_ns() - t_total, ciphertext_len);
#endif
    return CRYPTO_OK;
}
