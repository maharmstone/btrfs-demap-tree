#include <iostream>
#include <filesystem>
#include <fstream>

import cxxbtrfs;
import formatted_error;

using namespace std;

struct device {
    device(const filesystem::path& fn) : f(fn) { }

    ifstream f;
    btrfs::super_block sb;
};

static void read_superblock(device& d) {
    d.f.seekg(btrfs::superblock_addrs[0]);
    d.f.read((char*)&d.sb, sizeof(d.sb));

    if (d.sb.magic != btrfs::MAGIC)
        throw runtime_error("not btrfs");

    if (!check_superblock_csum(d.sb))
        throw runtime_error("superblock csum mismatch");
}

static void demap(const filesystem::path& fn) {
    device d(fn);

    if (d.f.fail())
        throw formatted_error("Failed to open {}", fn.string()); // FIXME - include why

    read_superblock(d);

    if (!(d.sb.incompat_flags & btrfs::FEATURE_INCOMPAT_REMAP_TREE))
        throw runtime_error("remap-tree incompat flag not set");

    if (d.sb.num_devices != 1)
        throw runtime_error("multi-device support not yet implemented"); // FIXME

    // FIXME - loop through BGT
    // FIXME - process BGs with REMAPPED flag set
}

int main() {
    // FIXME - solicit filename

    try {
        demap("../test.img");
    } catch (const exception& e) {
        cerr << "Exception: " << e.what() << endl;
        return 1;
    }

    return 0;
}
