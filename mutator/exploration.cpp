/*
  New Custom Mutator for AFL++
  Written by Khaled Yakdan <yakdan@code-intelligence.de>
             Andrea Fioraldi <andreafioraldi@gmail.com>
             Shengtuo Hu <h1994st@gmail.com>
             Dominik Maier <mail@dmnk.co>
*/

// You need to use -I/path/to/AFLplusplus/include -I.
#include "AFLplusplus/afl-fuzz.h"
#include "probe/probe.h"

#include <bits/stdc++.h>
#include <experimental/filesystem>

using namespace std;
namespace fs = experimental::filesystem;

const string MUTATION_NAME = "exploration";
const enum FIELD {
    ASSERTION,
    RAWDATA,
    ENUMERATION,
    LOOPCOUNT,
    OFFSET,
    SIZE,
    OTHER
};

typedef struct my_mutator
{
    afl_state_t *afl;
    vector<pair<pair<int, int>, int>> fields;
    bool init_probe;
    u8 *mutated_out;
} my_mutator_t;

int rd(int l, int r)
{
    return rand() % (r - l + 1) + l;
}

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
extern "C" my_mutator_t *afl_custom_init(afl_state_t *afl, unsigned int seed)
{

    srand(seed); // needed also by surgical_havoc_mutate()

    my_mutator_t *data = (my_mutator_t *)calloc(1, sizeof(my_mutator_t));
    if (!data)
    {

        perror("afl_custom_init alloc");
        return NULL;
    }

    data->init_probe = 0;

    if ((data->mutated_out = (u8 *)malloc(MAX_FILE)) == NULL)
    {

        perror("afl_custom_init malloc");
        return NULL;
    }

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
extern "C" size_t afl_custom_fuzz(my_mutator_t *data, uint8_t *buf, size_t buf_size,
                                  u8 **out_buf, uint8_t *add_buf,
                                  size_t add_buf_size, // add_buf can be NULL
                                  size_t max_size)
{
    if (!data->init_probe)
    {
        data->init_probe = 1;
        ofstream ofs(MUTATION_NAME + "_seed");
        ofs.write((char *)buf, buf_size);
        ofs.close();
        auto fields = probe(MUTATION_NAME + "_seed", MUTATION_NAME + "_template", getenv("TARGET"), 0);
        int l = 0;
        for (auto &field : fields)
            data->fields.push_back({{l, l + field.first - 1}, field.second}), l += field.first;
        for (auto &field : data->fields)
            cout << field.first.first << ' ' << field.first.second << ' ' << field.second << '\n';
        fs::remove(MUTATION_NAME + "_seed");
    }

    int mutated_i;
    while (1)
    {
        mutated_i = rd(0, data->fields.size() - 1);
        if (data->fields[mutated_i].second != RAWDATA)
            break;
    }

    int type = data->fields[mutated_i].second;

    if (type == ASSERTION)
    {
        
    }

    return buf_size;
}

/**
 * Deinitialize everything
 *
 * @param data The data ptr from afl_custom_init
 */
extern "C" void afl_custom_deinit(my_mutator_t *data)
{
    free(data->mutated_out);
    free(data);
}
