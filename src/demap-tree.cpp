#include <iostream>
#include <filesystem>
#include <fstream>
#include <map>
#include <functional>
#include <print>
#include <getopt.h>
#include "config.h"

import cxxbtrfs;
import formatted_error;

using namespace std;

#define MAX_STRIPES 16

struct device {
    device(const filesystem::path& fn) : f(fn) { }

    ifstream f;
    btrfs::super_block sb;
};

struct chunk : btrfs::chunk {
    btrfs::stripe next_stripes[MAX_STRIPES - 1];
};

struct fs {
    fs(const filesystem::path& fn) : dev(fn) { }

    device dev;
    map<uint64_t, chunk> sys_chunks, chunks;
    map<uint64_t, string> tree_cache;
};

static uint64_t find_tree_addr(fs& f, uint64_t tree);

static void read_superblock(device& d) {
    d.f.seekg(btrfs::superblock_addrs[0]);
    d.f.read((char*)&d.sb, sizeof(d.sb));

    if (d.sb.magic != btrfs::MAGIC)
        throw runtime_error("not btrfs");

    if (!check_superblock_csum(d.sb))
        throw runtime_error("superblock csum mismatch");
}

static void load_sys_chunks(fs& f) {
    auto& sb = f.dev.sb;

    auto sys_array = span(sb.sys_chunk_array.data(), sb.sys_chunk_array_size);

    while (!sys_array.empty()) {
        if (sys_array.size() < sizeof(btrfs::key))
            throw runtime_error("sys array truncated");

        auto& k = *(btrfs::key*)sys_array.data();

        if (k.type != btrfs::key_type::CHUNK_ITEM)
            throw formatted_error("unexpected key type {} in sys array", k.type);

        sys_array = sys_array.subspan(sizeof(btrfs::key));

        if (sys_array.size() < offsetof(btrfs::chunk, stripe))
            throw runtime_error("sys array truncated");

        auto& c = *(chunk*)sys_array.data();

        if (sys_array.size() < offsetof(btrfs::chunk, stripe) + (c.num_stripes * sizeof(btrfs::stripe)))
            throw runtime_error("sys array truncated");

        if (c.num_stripes > MAX_STRIPES) {
            throw formatted_error("chunk num_stripes is {}, maximum supported is {}",
                                  c.num_stripes, MAX_STRIPES);
        }

        sys_array = sys_array.subspan(offsetof(btrfs::chunk, stripe) + (c.num_stripes * sizeof(btrfs::stripe)));

        f.sys_chunks.insert(make_pair((uint64_t)k.offset, c));
    }
}

static const pair<uint64_t, const chunk&> find_chunk(const map<uint64_t, chunk>& chunks,
                                                     uint64_t address) {
    auto it = chunks.upper_bound(address);

    if (it == chunks.begin())
        throw formatted_error("could not find address {:x} in chunks", address);

    const auto& p = *prev(it);

    if (p.first + p.second.length <= address)
        throw formatted_error("could not find address {:x} in chunks", address);

    return p;
}

static string read_data(fs& f, uint64_t addr, uint64_t size) {
    auto& chunks = f.chunks.empty() ? f.sys_chunks : f.chunks;
    auto& [chunk_start, c] = find_chunk(chunks, addr);

    // FIXME - remaps

    string ret;

    ret.resize(size);

    // FIXME - handle degraded reads?
    // FIXME - handle csum failures (get other stripe)

    switch (btrfs::get_chunk_raid_type(c)) {
        // FIXME - RAID5, RAID6, RAID10, RAID0

        case btrfs::raid_type::SINGLE:
        case btrfs::raid_type::DUP:
        case btrfs::raid_type::RAID1:
        case btrfs::raid_type::RAID1C3:
        case btrfs::raid_type::RAID1C4: {
            if (f.dev.sb.dev_item.devid != c.stripe[0].devid)
                throw formatted_error("device {} not found", c.stripe[0].devid);

            f.dev.f.seekg(c.stripe[0].offset + addr - chunk_start);
            f.dev.f.read(ret.data(), size);

            break;
        }

        default:
            throw formatted_error("unhandled RAID type {}\n",
                                  btrfs::get_chunk_raid_type(c));
    }

    return ret;
}

static void walk_tree2(fs& f, uint64_t addr,
                       const function<bool(const btrfs::key&, span<const uint8_t>)>& func,
                       optional<btrfs::key> from) {
    const auto& sb = f.dev.sb;

    if (!f.tree_cache.contains(addr)) {
        auto tree = read_data(f, addr, sb.nodesize);

        const auto& h = *(btrfs::header*)tree.data();

        // FIXME - also die on generation or level mismatch
        // FIXME - check csums
        // FIXME - use other chunk stripe if verification fails

        if (h.bytenr != addr)
            throw formatted_error("Address mismatch: expected {:x}, got {:x}", addr, h.bytenr);

        f.tree_cache.emplace(make_pair(addr, tree));
    }

    auto& tree = f.tree_cache.find(addr)->second;
    const auto& h = *(btrfs::header*)tree.data();

    if (h.level == 0) {
        auto items = span((btrfs::item*)((uint8_t*)&h + sizeof(btrfs::header)), h.nritems);

        for (const auto& it : items) {
            if (from.has_value() && it.key < *from)
                continue;

            auto item = span((uint8_t*)tree.data() + sizeof(btrfs::header) + it.offset, it.size);

            if (!func(it.key, item))
                break;
        }
    } else {
        auto items = span((btrfs::key_ptr*)((uint8_t*)&h + sizeof(btrfs::header)), h.nritems);

        for (size_t i = 0; i < items.size(); i++) {
            const auto& it = items[i];

            if (from.has_value() && i < items.size() - 1 && *from < items[i + 1].key)
                continue;

            walk_tree2(f, it.blockptr, func, from);
        }
    }
}

static pair<btrfs::key, span<const uint8_t>> find_item2(fs& f, uint64_t addr,
                                                        const btrfs::key& key) {
    const auto& sb = f.dev.sb;

    if (!f.tree_cache.contains(addr)) {
        auto tree = read_data(f, addr, sb.nodesize);

        const auto& h = *(btrfs::header*)tree.data();

        // FIXME - also die on generation or level mismatch
        // FIXME - check csums
        // FIXME - use other chunk stripe if verification fails

        if (h.bytenr != addr)
            throw formatted_error("Address mismatch: expected {:x}, got {:x}", addr, h.bytenr);

        f.tree_cache.emplace(make_pair(addr, tree));
    }

    auto& tree = f.tree_cache.find(addr)->second;
    const auto& h = *(btrfs::header*)tree.data();

    if (h.level == 0) {
        auto items = span((btrfs::item*)((uint8_t*)&h + sizeof(btrfs::header)), h.nritems);

        for (const auto& it : items) {
            if (it.key < key)
                continue;

            auto item = span((uint8_t*)tree.data() + sizeof(btrfs::header) + it.offset, it.size);

            return make_pair(it.key, item);
        }

        return make_pair((btrfs::key){ 0xffffffffffffffff, (enum btrfs::key_type)0xff, 0xffffffffffffffff }, span<uint8_t>());
    } else {
        auto items = span((btrfs::key_ptr*)((uint8_t*)&h + sizeof(btrfs::header)), h.nritems);

        for (size_t i = 0; i < h.nritems - 1; i++) {
            if (key >= items[i].key && key < items[i + 1].key)
                return find_item2(f, items[i].blockptr, key);
        }

        return find_item2(f, items[h.nritems - 1].blockptr, key);
    }
}

static pair<btrfs::key, span<const uint8_t>> find_item(fs& f, uint64_t tree, const btrfs::key& key) {
    auto addr = find_tree_addr(f, tree);

    return find_item2(f, addr, key);
}

static uint64_t find_tree_addr(fs& f, uint64_t tree) {
    auto& sb = f.dev.sb;

    if (tree == btrfs::CHUNK_TREE_OBJECTID)
        return sb.chunk_root;
    else if (tree == btrfs::ROOT_TREE_OBJECTID)
        return sb.root;

    auto [key, data] = find_item(f, btrfs::ROOT_TREE_OBJECTID, { tree, btrfs::key_type::ROOT_ITEM, 0 });

    if (key.objectid != tree || key.type != btrfs::key_type::ROOT_ITEM)
        throw formatted_error("find_tree_addr: tree {:x} not found in root\n", tree);

    if (data.size() < sizeof(btrfs::root_item)) {
        throw formatted_error("find_tree_addr: ROOT_ITEM for tree {:x} was {} bytes, expected {}\n",
                              tree, data.size(), sizeof(btrfs::root_item));
    }

    const auto& ri = *(btrfs::root_item*)data.data();

    return ri.bytenr;
}

static void walk_tree(fs& f, uint64_t tree, optional<btrfs::key> from,
                      const function<bool(const btrfs::key&, span<const uint8_t>)>& func) {
    auto addr = find_tree_addr(f, tree);

    walk_tree2(f, addr, func, from);
}

static void load_chunks(fs& f) {
    walk_tree(f, btrfs::CHUNK_TREE_OBJECTID, nullopt,
              [&f](const btrfs::key& key, span<const uint8_t> item) {
        if (key.type != btrfs::key_type::CHUNK_ITEM)
            return true;

        const auto& c = *(chunk*)item.data();

        if (item.size() < offsetof(btrfs::chunk, stripe) + (c.num_stripes * sizeof(btrfs::stripe)))
            throw runtime_error("chunk item truncated");

        if (c.num_stripes > MAX_STRIPES) {
            throw formatted_error("chunk num_stripes is {}, maximum supported is {}",
                                  c.num_stripes, MAX_STRIPES);
        }

        f.chunks.insert(make_pair((uint64_t)key.offset, c));

        return true;
    });
}

static void allocate_stripe(fs& f, uint64_t offset) {
    auto& sb = f.dev.sb;

    print("FIXME - allocate_stripe {:x}\n", offset);

    // FIXME - find hole in dev extent tree

    walk_tree(f, btrfs::DEV_TREE_OBJECTID, btrfs::key{ sb.dev_item.devid, btrfs::key_type::DEV_EXTENT, 0 },
        [&](const btrfs::key& key, span<const uint8_t> item) {
            if (key.objectid > sb.dev_item.devid)
                return false;

            if (key.objectid == sb.dev_item.devid && key.type > btrfs::key_type::DEV_EXTENT)
                return false;

            print("dev extent item: {}\n", key);

            return true;
    });

    // FIXME - clear RAID flags (make SINGLE)
    // FIXME - also clear RAID flags in BG item
    // FIXME - set num_stripes to 1
    // FIXME - add stripe
    // FIXME - add dev extent item
}

static void demap_bg(fs& f, uint64_t offset) {
    print("FIXME - demap_bg {:x}\n", offset); // FIXME

    auto& [_, c] = find_chunk(f.chunks, offset);

    if (c.num_stripes == 0)
        allocate_stripe(f, offset);

    // FIXME - loop through non-identity remaps
    // FIXME - read data
    // FIXME - write data
    // FIXME - reduce remap_bytes of other BG

    // FIXME - when finished:
    // FIXME - remove remaps, remap_backrefs, and identity_remaps for range
    // FIXME - clear REMAPPED flag in chunk
    // FIXME - clear REMAPPED flag in BG

    // FIXME - avoiding superblock
    // FIXME - compressed extents need to be contiguous
}

static void demap(const filesystem::path& fn) {
    fs f(fn);

    if (f.dev.f.fail())
        throw formatted_error("Failed to open {}", fn.string()); // FIXME - include why

    read_superblock(f.dev);

    auto& sb = f.dev.sb;

    if (!(sb.incompat_flags & btrfs::FEATURE_INCOMPAT_REMAP_TREE))
        throw runtime_error("remap-tree incompat flag not set");

    if (sb.num_devices != 1)
        throw runtime_error("multi-device support not yet implemented"); // FIXME

    load_sys_chunks(f);
    load_chunks(f);

    // FIXME - die if transaction log there?

    for (const auto& c : f.chunks) {
        if (c.second.type & btrfs::BLOCK_GROUP_REMAPPED)
            demap_bg(f, c.first);
    }

    // FIXME - when finished:
    // FIXME - remove (now empty) remap tree
    // FIXME - remove all REMAP chunks
    // FIXME - add data reloc tree
    // FIXME - shorten block group items
    // FIXME - clear incompat flag
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
