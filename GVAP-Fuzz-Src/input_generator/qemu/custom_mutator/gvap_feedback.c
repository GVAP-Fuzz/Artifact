/* GVAP-FuzzCC feedback (ablation: traditional code coverage).
 * Does not paint GVAP bits; AFL edge coverage is left as the fuzzer recorded it.
 * Queue order stays AFL's. Packet mutation matches the GVAP-coverage mutator. */
#define _DEFAULT_SOURCE
#include "afl-fuzz.h"

#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define GVAP_AFL_MAGIC 0x47564150u
#define GVAP_AFL_MAX_PAIRS 4096u

typedef struct {
    uint32_t magic, count;
    uint64_t hashes[GVAP_AFL_MAX_PAIRS];
    uint32_t dists[GVAP_AFL_MAX_PAIRS];
} gvap_afl_shm_t;

typedef struct {
    afl_state_t *afl;
    gvap_afl_shm_t *shm;
    char shm_name[64];
    unsigned seed;
    uint8_t *fuzz_buf;
    size_t fuzz_cap;
} gvap_fb_t;

#include "gvap_packet_fuzz.inc"

void *afl_custom_init(afl_state_t *afl, unsigned int seed)
{
    gvap_fb_t *data = calloc(1, sizeof(*data));
    int fd;
    if (!data)
        return NULL;
    data->afl = afl;
    data->seed = seed ? seed : 1;
    snprintf(data->shm_name, sizeof data->shm_name, "/gvap_afl_only_%d", (int)getpid());
    shm_unlink(data->shm_name);
    fd = shm_open(data->shm_name, O_CREAT | O_RDWR, 0600);
    if (fd < 0 || ftruncate(fd, sizeof(gvap_afl_shm_t)) != 0) {
        free(data);
        return NULL;
    }
    data->shm = mmap(NULL, sizeof(gvap_afl_shm_t), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    if (data->shm == MAP_FAILED) {
        free(data);
        return NULL;
    }
    data->shm->magic = GVAP_AFL_MAGIC;
    setenv("GVAP_AFL_SHM", data->shm_name, 1);
    return data;
}

size_t afl_custom_fuzz(void *data_raw, uint8_t *buf, size_t buf_size, uint8_t **out_buf,
                       uint8_t *add_buf, size_t add_buf_size, size_t max_size)
{
    gvap_fb_t *data = data_raw;
    (void)add_buf;
    (void)add_buf_size;
    if (!data || !out_buf || !max_size)
        return 0;
    if (data->fuzz_cap < max_size) {
        uint8_t *grown = realloc(data->fuzz_buf, max_size);
        if (!grown)
            return 0;
        data->fuzz_buf = grown;
        data->fuzz_cap = max_size;
    }
    *out_buf = data->fuzz_buf;
    return gvap_packet_fuzz(data->fuzz_buf, max_size, buf ? buf : (uint8_t *)"", buf && buf_size ? buf_size : 0,
                            data->seed++);
}

/* Code-coverage scheduling: do not reorder the queue by GVAP distance. */
uint8_t afl_custom_queue_get(void *data_raw, const uint8_t *filename)
{
    (void)data_raw;
    (void)filename;
    return 1;
}

void afl_custom_post_run(void *raw)
{
    (void)raw;
}

void afl_custom_deinit(void *raw)
{
    gvap_fb_t *data = raw;
    if (!data)
        return;
    free(data->fuzz_buf);
    if (data->shm && data->shm != MAP_FAILED)
        munmap(data->shm, sizeof(*data->shm));
    shm_unlink(data->shm_name);
    free(data);
}
