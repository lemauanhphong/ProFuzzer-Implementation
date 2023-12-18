#include <bits/stdc++.h>
#include <experimental/filesystem>

using namespace std;
namespace fs = experimental::filesystem;

vector<std::pair<int, int>> probe(const fs::path &seed_path, const fs::path &template_path, const fs::path &target_path, bool write = 1);