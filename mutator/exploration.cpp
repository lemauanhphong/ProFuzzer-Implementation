/*
  New Custom Mutator for AFL++
  Written by Khaled Yakdan <yakdan@code-intelligence.de>
             Andrea Fioraldi <andreafioraldi@gmail.com>
             Shengtuo Hu <h1994st@gmail.com>
             Dominik Maier <mail@dmnk.co>
*/

#include <bits/stdc++.h>
#include <experimental/filesystem>

using namespace std;
namespace fs = experimental::filesystem;

// You need to use -I/path/to/AFLplusplus/include -I.
#include "afl-fuzz.h"
#include "probe.h"
#include "fields.h"

const string MUTATION_NAME = "exploration";
const int DATA_SIZE = 100;
const float HIGH_PROB = 0.9;
const int FRUITLESS = 11;
enum FIELD
{
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
    vector<Field> fields;
    bool init_probe;
    u8 *mutated_out;
    u8 fruitless;
    // vector <string> str_constants = {};
    // vector <int> int_constants = {1, 45, 123};
    map<int, vector<string>> ex_constants;
    int mutated_i;
} my_mutator_t;

// =============================
// This is functions from afl++
#if __GNUC__ < 6
#ifndef likely
#define likely(_x) (_x)
#endif
#ifndef unlikely
#define unlikely(_x) (_x)
#endif
#else
#ifndef likely
#define likely(_x) __builtin_expect(!!(_x), 1)
#endif
#ifndef unlikely
#define unlikely(_x) __builtin_expect(!!(_x), 0)
#endif
#endif

/* Updates the virgin bits, then reflects whether a new count or a new tuple is
 * seen in ret. */
inline void discover_word(u8 *ret, u64 *current, u64 *virgin)
{

    /* Optimize for (*current & *virgin) == 0 - i.e., no bits in current bitmap
       that have not been already cleared from the virgin map - since this will
       almost always be the case. */

    if (*current & *virgin)
    {

        if (likely(*ret < 2))
        {

            u8 *cur = (u8 *)current;
            u8 *vir = (u8 *)virgin;

            /* Looks like we have not found any new bytes yet; see if any non-zero
               bytes in current[] are pristine in virgin[]. */

            if ((cur[0] && vir[0] == 0xff) || (cur[1] && vir[1] == 0xff) || (cur[2] && vir[2] == 0xff) ||
                (cur[3] && vir[3] == 0xff) || (cur[4] && vir[4] == 0xff) || (cur[5] && vir[5] == 0xff) ||
                (cur[6] && vir[6] == 0xff) || (cur[7] && vir[7] == 0xff))
                *ret = 2;
            else
                *ret = 1;
        }

        *virgin &= ~*current;
    }
}

/* Check if the current execution path brings anything new to the table.
   Update virgin bits to reflect the finds. Returns 1 if the only change is
   the hit-count for a particular tuple; 2 if there are new tuples seen.
   Updates the map, so subsequent calls will always return 0.

   This function is called after every exec() on a fairly large buffer, so
   it needs to be fast. We do this in 32-bit and 64-bit flavors. */

inline u8 has_new_bits(afl_state_t *afl, u8 *virgin_map)
{

#ifdef WORD_SIZE_64

    u64 *current = (u64 *)afl->fsrv.trace_bits;
    u64 *virgin = (u64 *)virgin_map;

    u32 i = ((afl->fsrv.real_map_size + 7) >> 3);

#else

    u32 *current = (u32 *)afl->fsrv.trace_bits;
    u32 *virgin = (u32 *)virgin_map;

    u32 i = ((afl->fsrv.real_map_size + 3) >> 2);

#endif /* ^WORD_SIZE_64 */

    u8 ret = 0;
    while (i--)
    {

        if (unlikely(*current))
            discover_word(&ret, current, virgin);

        current++;
        virgin++;
    }

    if (unlikely(ret) && likely(virgin_map == afl->virgin_bits))
        afl->bitmap_changed = 1;

    return ret;
}
// =============================

int rd(int l, int r)
{
    return rand() % (r - l + 1) + l;
}

float rd()
{
    return (float)rand() / RAND_MAX;
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

    data->mutated_i = 0;
    data->fruitless = FRUITLESS;
    data->init_probe = 0;
    cout << "123\n";
    data->ex_constants[2] = {string("\x01"), string("\x2d"), string("\x7b")};
    cout << "123\n";
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
    size_t mutated_size = DATA_SIZE <= max_size ? DATA_SIZE : max_size;
    memcpy(data->mutated_out, buf, buf_size);

    if (!data->init_probe)
    {
        data->init_probe = 1;
        ofstream ofs(MUTATION_NAME + "_seed");
        ofs.write((char *)buf, buf_size);
        ofs.close();
        auto fields = probe(MUTATION_NAME + "_seed", MUTATION_NAME + "_template", getenv("TARGET"), 0);
        int l = 0;
        for (auto &field : fields)
        {
            if (field.second == 0)
                data->fields.push_back(Assertion(l, l + field.first - 1, &(data->ex_constants)));
            else if (field.second == 1)
                data->fields.push_back(Rawdata(l, l + field.first - 1));
            else if (field.second == 2)
                data->fields.push_back(Assertion(l, l + field.first - 1, &(data->ex_constants)));
            else if (field.second == 3)
                data->fields.push_back(Loopcount(l, l + field.first - 1, 0, (1 << 16) - 1));
            else if (field.second == 4)
                data->fields.push_back(Offset(l, l + field.first - 1, -1));
            else if (field.second == 5)
                data->fields.push_back(Size(l, l + field.first - 1, -1));
            else
                data->fields.push_back(Field(l, l + field.first - 1, 6));

            l += field.first;
        }

        fs::remove(MUTATION_NAME + "_seed");
    }

    if (!has_new_bits(data->afl, data->afl->virgin_bits))
        --data->fruitless;
    else
        data->fruitless = FRUITLESS;

    int mutated_i;
    int type = data->fields[mutated_i].getType();
    int len = data->fields[mutated_i].getR() - data->fields[mutated_i].getL() + 1;
    if (!data->fruitless)
    {
        for (int i = 0; i < data->fields.size(); ++i)
        {
            mutated_i = (mutated_i + 1) % data->fields.size();
            if (data->fields[mutated_i].getType() != RAWDATA)
                break;
        }

        data->mutated_i = mutated_i;
        data->fruitless = FRUITLESS;

        if (type == ASSERTION) // this is just another bad replacement, ProFuzzer does not do that :)
        {
            if (rd() > HIGH_PROB && data->ex_constants[len].size() > 0)
            {
                memcpy(data->mutated_out + data->fields[mutated_i].getL(), data->ex_constants[len][rd(0, data->ex_constants[len].size() - 1)].c_str(), len);
            }
        }
        else if (type == ENUMERATION) // this is just another bad replacement, ProFuzzer does not do that :)
        {
            if (rd() < HIGH_PROB && data->ex_constants[len].size() > 0)
            {
                memcpy(data->mutated_out + data->fields[mutated_i].getL(), data->ex_constants[len][rd(0, data->ex_constants[len].size() - 1)].c_str(), len);
            }
            else
            {
                memcpy(data->mutated_out + data->fields[mutated_i].getL(), data->ex_constants[len][rd(0, data->ex_constants[len].size() - 1)].c_str(), len);
            }
        }
        else if (type == LOOPCOUNT)
        {
            // do something
        }
        else if (type == OFFSET)
        {
            // do something
        }
        else if (type == SIZE)
        {
            // do something
        }
        else
        {
            // fallback to default AFL random per-byte mutation
        }
    }
    else
    {
        // exploitation mutation
    }

    *out_buf = data->mutated_out;
    return mutated_size;
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
