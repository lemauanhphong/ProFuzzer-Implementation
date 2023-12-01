#include "afl-fuzz.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define DATA_SIZE (100)

static const char *commands[] = {

    "GET",
    "PUT",
    "DEL",

};

typedef struct fraction
{
    u8 x, y;
} fraction_t;

typedef struct probe
{
    FILE *debug;
    u8 *mutated_out;
    int c;

    afl_state_t *afl;

    // any additional data here!
    int step, idx;
    fraction_t **FS, **FD;
    u8 *base_coverage;
    char old_val;
} probe_t;

/**
 * Initialize this custom mutator
 *
 * @param[in] afl a pointer to the internal state object. Can be ignored for
 * now.
 * @param[in] seed A seed for this mutator - the same seed should always mutate
 * in the same way.
 * @return Pointer to the data object this custom mutator instance should use.
 *         There may be multiple instances of this mutator in one afl-fuzz run!
 *         Return NULL on error.
 */
probe_t *afl_custom_init(afl_state_t *afl, unsigned int seed)
{
    srand(seed); // needed also by surgical_havoc_mutate()

    probe_t *data = calloc(1, sizeof(probe_t));
    if (!data)
    {

        perror("afl_custom_init alloc");
        return NULL;
    }

    data->debug = fopen("debug", "w");
    data->c = 0;
    if ((data->mutated_out = (u8 *)malloc(MAX_FILE)) == NULL)
    {

        perror("afl_custom_init malloc");
        return NULL;
    }

    if ((data->base_coverage = (u8 *)malloc(MAX_FILE)) == NULL)
    {

        perror("afl_custom_init malloc");
        return NULL;
    }

    data->idx = 0;
    data->old_val = -1;
    data->step = -1;
    data->afl = afl;
    
    return data;
}

/**
 * Perform custom mutations on a given input
 *
 * (Optional for now. Required in the future)
 *
 * @param[in] data pointer returned in afl_custom_init for this fuzz case
 * @param[in] buf Pointer to input data to be mutated
 * @param[in] buf_size Size of input data
 * @param[out] out_buf the buffer we will work on. we can reuse *buf. NULL on
 * error.
 * @param[in] add_buf Buffer containing the additional test case
 * @param[in] add_buf_size Size of the additional test case
 * @param[in] max_size Maximum size of the mutated output. The mutation must not
 *     produce data larger than max_size.
 * @return Size of the mutated output.
 */
size_t afl_custom_fuzz(probe_t *data, uint8_t *buf, size_t buf_size,
                       u8 **out_buf, uint8_t *add_buf,
                       size_t add_buf_size, // add_buf can be NULL
                       size_t max_size)
{
    for (int i = 0; i < 10; ++i)
    {
        fprintf(data->debug, "%d ", *(data->afl->fsrv.trace_bits+i));
    }
    

    


    // if (data->step == 256)
    // {
    //     buf[data->idx] = data->old_val;
    //     ++data->idx;

    //     if (data->idx == buf_size)
    //     {
    //         // TODO: print as template
    //         // exit
    //     }

    //     data->step = 0;
    // }
    
    // if (data->step >= 0)
    // {
    //     if (data->step == 0) data->old_val = buf[data->idx];
    //     if (data->idx == 0)
    //         memcpy(data->base_coverage, data->afl->shm.map, data->afl->shm.map_size);

    //     // TODO: calculate FS, FD
    //     // FS
    //     int coverage_intersection = 0;
    //     int coverage_union = 0;
    //     for (int i = 0; i < data->afl->shm.map_size; ++i)
    //     {
            
    //     }

    //     buf[data->idx] = data->step;
    // }

    // ++data->step;
    // *out_buf = buf;
    if (data->c == 10) exit(1);
    memcpy(data->mutated_out, buf, buf_size);
    *(data->mutated_out + 1) = data->c++ + 48;
    fprintf(data->debug, "%s\n", data->mutated_out);
    fprintf(data->debug, "\n----------\n");
    *out_buf = data->mutated_out;
    return buf_size;
}

/**
 * Deinitialize everything
 *
 * @param data The data ptr from afl_custom_init
 */
void afl_custom_deinit(probe_t *data)
{

    // free(data->post_process_buf);
    // free(data->mutated_out);
    // free(data->trim_buf);
    // free(data);
}
