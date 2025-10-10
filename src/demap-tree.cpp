#include <iostream>
#include <filesystem>
#include <fstream>
#include <getopt.h>
#include "config.h"

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

int main(int argc, char** argv) {
    bool print_version = false, print_usage = false;

    try {
        while (true) {
            enum {
                GETOPT_VAL_HELP,
                GETOPT_VAL_VERSION,
            };

            static const option long_opts[] = {
                { "help", no_argument, nullptr, GETOPT_VAL_HELP },
                { "version", no_argument, nullptr, GETOPT_VAL_VERSION },
                { nullptr, 0, nullptr, 0 }
            };

            auto c = getopt_long(argc, argv, "", long_opts, nullptr);
            if (c < 0)
                break;

            switch (c) {
                case GETOPT_VAL_VERSION:
                    print_version = true;
                    break;
                case GETOPT_VAL_HELP:
                case '?':
                    print_usage = true;
                    break;
            }
        }

        if (print_version) {
            cout << "demap-tree " << PROJECT_VER << endl;
            return 0;
        }

        if (print_usage || optind == argc) {
            cerr << R"(Usage: demap-tree <device>

Remove the remap-tree incompat feature from a btrfs filesystem.

Options:
    --version           print version string
    --help              print this screen
)";
            return 1;
        }

        demap(argv[optind]);
    } catch (const exception& e) {
        cerr << "Exception: " << e.what() << endl;
        return 1;
    }

    return 0;
}
