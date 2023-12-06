#pragma comment(linker, "/STACK:268435456");

#include <bits/stdc++.h>
#include <experimental/filesystem>

using namespace std;
namespace fs = experimental::filesystem;

struct fraction
{
    unsigned long long x, y;

    fraction operator+(const fraction &other) const
    {
        if (this->y == 0 || other.y == 0)
            return {1, 0}; // inf
        unsigned long long lcm = this->y / __gcd(this->y, other.y) * other.y;
        return {1ULL * lcm / other.y * this->x + 1ULL * lcm / this->y * other.x, 1ULL * lcm};
    }

    bool operator<(const fraction &other) const
    {
        if (this->y == 0)
            return 0;
        if (other.y == 0)
            return 1;
        return 1ULL * this->x * other.y < 1ULL * this->y * other.x;
    }

    bool operator==(const fraction &other) const
    {
        if (this->y == 0 && other.y == 0)
            return 1;
        return 1ULL * this->x * other.y == 1ULL * this->y * other.x;
    }

    bool operator<=(const fraction &other) const
    {
        return *this < other || *this == other;
    }

    double to_double() const
    {
        return 1.0 * this->x / this->y;
    }
};

const int LEN_MAP = 1 << 16;
const int MAX_FILE = 1 << 20; // AFL++ constant
const fraction BETA = {1, 5}; // small data variation

int max_cov_used = -1; // <= MAX_FILE

void init()
{
    fs::create_directory("tmp_in");
    fs::create_directory("tmp_out");
}

void parse_map_file(string filepath, uint8_t *cov)
{
    FILE *f = fopen(filepath.c_str(), "r");
    int a, b;
    while (fscanf(f, "%u:%u", &a, &b) != -1)
        cov[a] = b, max_cov_used = max(max_cov_used, a);
    fclose(f);
}

void exe_engine(string command)
{
    string ignore_output = "";
    if (getenv("IGNORE_EXE_STDOUT"))
        ignore_output = " > /dev/null";
    system((command + ignore_output).c_str());
}

void type_field_identification(vector<pair<int, int>> &fields, fraction FS[][256], fraction FD[][256], fraction *alpha_x2, size_t &len)
{
    int l = 0, r = 0;
    for (auto &field : fields)
    {
        r = l + field.first - 1;
        int type = -1;
        bool assertion = 1, rawdata = 1, enumration = 0, loopcount = 0, offset = 0, size = 0;

        // Assertion Field
        for (int i = l; i <= r && assertion; ++i)
        {
            int cnt_e1 = 0;
            int cnt_la = 0;
            for (int j = 0; j < 256; ++j)
            {
                cnt_e1 += FS[i][j].y && FS[i][j].x == FS[i][j].y;                // FS[i][j].x / FS[i][j].y == 1
                cnt_la += fraction({FS[i][j].x << 1, FS[i][j].y}) < alpha_x2[i]; // 2 * (FS[i][j].x / FX[i][j].y) < 2alpha
            }

            if (cnt_e1 != 1 || cnt_la != 255)
                assertion = 0;
        }

        if (assertion)
        {
            type = 0;
            goto JMP;
        }

        // Raw Data Field
        for (int i = l; i <= r && rawdata; ++i)
            for (int j = 0; j < 256 && rawdata; ++j)
                if (!(FS[i][j].y && FS[i][j].x == FS[i][j].y))
                    rawdata = 0;

        if (rawdata)
        {
            type = 1;
            goto JMP;
        }

        // Enumeration Field
        for (int i = l; i <= r && !enumration; ++i)
        {
            int cnt_g = 0;
            for (int j = 0; j < 256; ++j)
                cnt_g += alpha_x2[i] < fraction({FS[i][j].x << 1, FS[i][j].y});
            if (cnt_g > 1)
                enumration = 1;
        }

        if (enumration)
        {
            type = 2;
            goto JMP;
        }

        // Loop Count Field
        for (int i = l; i <= r && !loopcount; ++i)
        {
            fraction mean_FD = {0, 1};
            double mean_FS = 0; // sai so
            for (int j = 0; j < 256; ++j)
            {
                mean_FD = mean_FD + FD[i][j];
                mean_FS += FS[i][j].to_double();
            }
            mean_FD.y *= 256; // div 256
            mean_FS /= 256;
            if (mean_FD.x < mean_FD.y) // average(FD[i][j]) <= 1
                continue;

            double variance_FS = 0;
            for (int j = 0; j < 256 && variance_FS < BETA.to_double() * 256; ++j)
                variance_FS += (mean_FS - FS[i][j].to_double()) * (mean_FS - FS[i][j].to_double());

            if (variance_FS < BETA.to_double() * 256)
                loopcount = 1;
        }

        if (loopcount)
        {
            type = 3;
            goto JMP;
        }

        // Offset Field
        for (int i = l; i <= r && !offset; ++i)
            if (alpha_x2[i] < fraction({FS[i][0].x << 1, FS[i][0].y}))
            {
                int t_min = -1;
                for (int j = 1; j < 256 && t_min == -1; ++j)
                    if (!(FS[i][j] == FS[i][0]))
                        t_min = j;

                if (t_min != -1) // if t exist, just use t == 255 -> don't care about w
                    offset = 1;
            }

        if (offset)
        {
            type = 4;
            goto JMP;
        }

        // Size Field
        for (int i = l; i <= r && !size; ++i)
        {
            int t_min = -1;
            for (int j = 1; j < 256 && t_min == -1; ++j)
                if (!(FS[i][j] == FS[i][0]))
                    t_min = j;

            if (t_min != -1) // if t exist, just use t == 255 -> don't care about w
                size = 1;
        }

        if (size)
        {
            type = 5;
            goto JMP;
        }

    JMP:
        l = r + 1;
        field.second = type;
    }
}

void write_template(const vector<pair<int, int>> &fields, fs::path &template_path)
{
    fs::path out_file = template_path;
    if (fs::is_directory(template_path))
    {
        out_file = template_path / "template";
    }

    ofstream f(out_file);
    for (const auto &field : fields)
        f << field.first << ' ' << field.second << '\n';
}

void process(fs::path &seed_path, fs::path &template_path, fs::path &target_path)
{
    uint8_t *base_cov = new uint8_t[LEN_MAP];
    uint8_t *cmp_cov = new uint8_t[LEN_MAP];
    char *seed = new char[MAX_FILE];

    memset(base_cov, 0, sizeof(uint8_t) * LEN_MAP);

    string seedname = seed_path.stem().string();
    string seedfile = "tmp_in/" + seedname;
    fs::copy(seed_path, "tmp_in", fs::copy_options::update_existing);
    exe_engine("afl-showmap -r -i tmp_in -o tmp_out " + target_path.string());

    ifstream f(seedfile);
    f.read(seed, MAX_FILE);
    parse_map_file("tmp_out/" + seedname, base_cov);
    fs::remove(seedfile);

    size_t len = f.gcount();
    auto FS = new fraction[len][256], FD = new fraction[len][256];
    fraction *alpha_x2 = new fraction[len];
    vector<pair<int, int>> fields;
    fraction last_mi = {UINT_MAX, UINT_MAX};
    for (int i = 0; i < len; ++i)
    {
        // Feature extraction
        char old_chr = seed[i];
        for (int j = 0; j < 256; ++j)
        {
            string filename = "tmp_in/" + to_string(j);
            seed[i] = j;
            ofstream f(filename);
            f.write(seed, len);
        }
        
        exe_engine("afl-showmap -r -i tmp_in -o tmp_out " + target_path.string());        

        if (i == 4)
        {
            int c = 4;
        }

        fraction ma = {ULLONG_MAX, ULLONG_MAX}, mi = {ULLONG_MAX, ULLONG_MAX};
        for (int j = 0; j < 256; ++j)
        {
            memset(cmp_cov, 0, sizeof(uint8_t) * LEN_MAP);
            string filename = "tmp_out/" + to_string(j);
            seed[i] = j;
            parse_map_file(filename, cmp_cov);

            unsigned int cov_intersection = 0, cov_union = 0;
            unsigned int diff_freq = 0, diff_cov = 0;
            for (int k = 0; k <= max_cov_used; ++k)
            {
                cov_intersection += cmp_cov[k] != 0 && base_cov[k] != 0;
                cov_union += cmp_cov[k] != 0 || base_cov[k] != 0;
                diff_freq += cmp_cov[k] != base_cov[k] && cmp_cov[k] != 0 && base_cov[k] != 0;
                diff_cov += cmp_cov[k] != base_cov[k] && (cmp_cov[k] == 0 || base_cov[k] == 0);
            }

            FS[i][j] = {cov_intersection, cov_union};
            FD[i][j] = {diff_freq, diff_cov};

            if (ma.x == ULLONG_MAX)
                ma = FS[i][j];
            else if (ma < FS[i][j])
                ma = FS[i][j];
            if (mi.x == ULLONG_MAX)
                mi = FS[i][j];
            else if (FS[i][j] < mi)
                mi = FS[i][j];
        }

        alpha_x2[i] = ma + mi;

        cout << mi.x << ' ' << mi.y << endl;
        // cout << ma.x << ' ' << ma.y << endl;

        if (fields.size() && last_mi == mi)
            fields.back().first += 1;
        else
            fields.push_back({1, -1});

        last_mi = mi;
        seed[i] = old_chr;
    }

    type_field_identification(fields, FS, FD, alpha_x2, len);
    write_template(fields, template_path);
}

void cleanup()
{
    fs::remove_all("tmp_in");
    fs::remove_all("tmp_out");
}

int main(int argc, char *argv[])
{
    fs::path seeds_path = argv[1];
    fs::path template_path = argv[2];
    fs::path target_path = argv[3];

    if (!fs::exists(seeds_path) || !fs::exists(template_path) || !fs::exists(target_path))
    {
        perror("");
        exit(-1);
    }

    init();
    process(seeds_path, template_path, target_path);
    cleanup();
    return 0;
}