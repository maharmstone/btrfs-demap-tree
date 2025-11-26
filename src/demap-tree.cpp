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

    fstream f;
    btrfs::super_block sb;
};

struct chunk : btrfs::chunk {
    btrfs::stripe next_stripes[MAX_STRIPES - 1];
};

struct chunk_info {
    chunk c;
    vector<pair<uint64_t, uint64_t>> fst;
};

struct ref_change {
    int64_t refcount_change;
};

struct fs {
    fs(const filesystem::path& fn) : dev(fn) { }

    device dev;
    map<uint64_t, chunk_info> chunks;
    map<uint64_t, string> tree_cache;
    map<uint64_t, ref_change> ref_changes;
};

static uint64_t find_tree_addr(fs& f, uint64_t tree);
static pair<btrfs::key, span<uint8_t>> find_item(fs& f, uint64_t tree,
                                                 const btrfs::key& key, bool cow);

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

        f.chunks.insert(make_pair((uint64_t)k.offset, c));
    }
}

static const pair<uint64_t, const chunk_info&> find_chunk(fs& f, uint64_t address) {
    auto it = f.chunks.upper_bound(address);

    if (it == f.chunks.begin())
        throw formatted_error("could not find address {:x} in chunks", address);

    const auto& p = *prev(it);

    if (p.first + p.second.c.length <= address)
        throw formatted_error("could not find address {:x} in chunks", address);

    return p;
}

static string read_data(fs& f, uint64_t addr, uint64_t size) {
    auto& [chunk_start, c] = find_chunk(f, addr);

    // FIXME - remaps

    string ret;

    ret.resize(size);

    // FIXME - handle degraded reads?
    // FIXME - handle csum failures (get other stripe)

    switch (btrfs::get_chunk_raid_type(c.c)) {
        // FIXME - RAID5, RAID6, RAID10, RAID0

        case btrfs::raid_type::SINGLE:
        case btrfs::raid_type::DUP:
        case btrfs::raid_type::RAID1:
        case btrfs::raid_type::RAID1C3:
        case btrfs::raid_type::RAID1C4: {
            if (f.dev.sb.dev_item.devid != c.c.stripe[0].devid)
                throw formatted_error("device {} not found", c.c.stripe[0].devid);

            f.dev.f.seekg(c.c.stripe[0].offset + addr - chunk_start);
            f.dev.f.read(ret.data(), size);

            break;
        }

        default:
            throw formatted_error("unhandled RAID type {}\n",
                                  btrfs::get_chunk_raid_type(c.c));
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

static uint64_t allocate_metadata(fs& f, uint64_t tree) {
    uint64_t type;
    auto& sb = f.dev.sb;

    switch (tree) {
        case btrfs::CHUNK_TREE_OBJECTID:
            type = btrfs::BLOCK_GROUP_SYSTEM;
            break;

        default:
            type = btrfs::BLOCK_GROUP_METADATA;
            break;
    }

    // FIXME - remap tree in REMAP

    // allocate from FST

    for (auto& [_, c] : f.chunks) {
        if (!(c.c.type & type))
            continue;

        for (auto it = c.fst.begin(); it != c.fst.end(); it++) {
            auto& e = *it;

            if (e.second < sb.nodesize)
                continue;

            auto addr = e.first;

            if (e.second == sb.nodesize)
                c.fst.erase(it);
            else {
                e.first += sb.nodesize;
                e.second -= sb.nodesize;
            }

            return addr;
        }
    }

    // FIXME - if no space, allocate new chunk

    throw runtime_error("could not find space to allocate new metadata");
}

static pair<btrfs::key, span<uint8_t>> find_item2(fs& f, uint64_t addr,
                                                  const btrfs::key& key,
                                                  bool cow, btrfs::key_ptr* parent,
                                                  uint64_t tree) {
    auto& sb = f.dev.sb;

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

    const auto& orig_tree = f.tree_cache.find(addr)->second;
    const auto& orig_h = *(btrfs::header*)orig_tree.data();
    const string* tree_ptr;

    if (cow && orig_h.flags & btrfs::HEADER_FLAG_WRITTEN) {
        auto new_addr = allocate_metadata(f, tree);

        auto [it, _] = f.tree_cache.emplace(new_addr, orig_tree);

        auto& new_tree = it->second;
        auto& h = *(btrfs::header*)new_tree.data();

        h.bytenr = new_addr;
        h.flags &= ~btrfs::HEADER_FLAG_WRITTEN;

        print("allocated metadata to {:x} (was {:x})\n", new_addr, addr);

        {
            auto [it2, _] = f.ref_changes.emplace(new_addr, ref_change{});

            it2->second.refcount_change = 1;
        }

        if (parent) {
            parent->blockptr = h.bytenr;
            // FIXME - generation
        } else {
            if (tree == btrfs::CHUNK_TREE_OBJECTID) {
                sb.chunk_root = h.bytenr;
                // FIXME - generation
            } else if (tree == btrfs::ROOT_TREE_OBJECTID) {
                sb.root = h.bytenr;
                // FIXME - generation
            } else {
                btrfs::key key{tree, btrfs::key_type::ROOT_ITEM, 0};

                auto [found_key, sp] = find_item(f, btrfs::ROOT_TREE_OBJECTID,
                                                 key, true);

                if (key.objectid != found_key.objectid || key.type != found_key.type)
                    throw formatted_error("could not find item {} in root tree", key);

                if (sp.size() < sizeof(btrfs::root_item)) {
                    throw formatted_error("{} in root tree was {} bytes, expected {}\n",
                                          found_key, sp.size(), sizeof(btrfs::root_item));
                }

                auto& ri = reinterpret_cast<btrfs::root_item&>(*sp.data());

                ri.bytenr = h.bytenr;
                // FIXME - generation
            }
        }

        // FIXME - mark as dirty (delayed ref)
        // FIXME - mark old tree as going away (delayed ref)
        // FIXME - what if COWing snapshotted tree?

        tree_ptr = &new_tree;
    } else
        tree_ptr = &orig_tree;

    const auto& h = *(btrfs::header*)tree_ptr->data();

    if (h.level == 0) {
        auto items = span((btrfs::item*)((uint8_t*)&h + sizeof(btrfs::header)), h.nritems);

        for (const auto& it : items) {
            if (it.key < key)
                continue;

            auto item = span((uint8_t*)tree_ptr->data() + sizeof(btrfs::header) + it.offset, it.size);

            return make_pair(it.key, item);
        }

        return make_pair((btrfs::key){ 0xffffffffffffffff, (enum btrfs::key_type)0xff, 0xffffffffffffffff }, span<uint8_t>());
    } else {
        auto items = span((btrfs::key_ptr*)((uint8_t*)&h + sizeof(btrfs::header)), h.nritems);

        for (size_t i = 0; i < h.nritems - 1; i++) {
            if (key >= items[i].key && key < items[i + 1].key)
                return find_item2(f, items[i].blockptr, key, cow, &items[i], tree);
        }

        return find_item2(f, items[h.nritems - 1].blockptr, key, cow,
                          &items[h.nritems - 1], tree);
    }
}

static pair<btrfs::key, span<uint8_t>> find_item(fs& f, uint64_t tree,
                                                 const btrfs::key& key, bool cow) {
    auto addr = find_tree_addr(f, tree);

    return find_item2(f, addr, key, cow, nullptr, tree);
}

static uint64_t find_tree_addr(fs& f, uint64_t tree) {
    auto& sb = f.dev.sb;

    if (tree == btrfs::CHUNK_TREE_OBJECTID)
        return sb.chunk_root;
    else if (tree == btrfs::ROOT_TREE_OBJECTID)
        return sb.root;

    auto [key, data] = find_item(f, btrfs::ROOT_TREE_OBJECTID, { tree, btrfs::key_type::ROOT_ITEM, 0 }, false);

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
    map<uint64_t, chunk_info> chunks;

    walk_tree(f, btrfs::CHUNK_TREE_OBJECTID, nullopt,
              [&chunks](const btrfs::key& key, span<const uint8_t> item) {
        if (key.type != btrfs::key_type::CHUNK_ITEM)
            return true;

        const auto& c = *(chunk*)item.data();

        if (item.size() < offsetof(btrfs::chunk, stripe) + (c.num_stripes * sizeof(btrfs::stripe)))
            throw runtime_error("chunk item truncated");

        if (c.num_stripes > MAX_STRIPES) {
            throw formatted_error("chunk num_stripes is {}, maximum supported is {}",
                                  c.num_stripes, MAX_STRIPES);
        }

        chunks.insert(make_pair((uint64_t)key.offset, c));

        return true;
    });

    swap(f.chunks, chunks);
}

static uint64_t find_hole_for_chunk(fs& f, uint64_t size) {
    auto& sb = f.dev.sb;

    // find hole in dev extent tree

    vector<pair<uint64_t, uint64_t>> allocs;

    walk_tree(f, btrfs::DEV_TREE_OBJECTID, btrfs::key{ sb.dev_item.devid, btrfs::key_type::DEV_EXTENT, 0 },
        [&](const btrfs::key& key, span<const uint8_t> item) {
            if (key.objectid > sb.dev_item.devid)
                return false;

            if (key.objectid == sb.dev_item.devid && key.type > btrfs::key_type::DEV_EXTENT)
                return false;

            if (item.size() < sizeof(btrfs::dev_extent)) {
                throw formatted_error("allocate_stripe: {} was {} bytes, expected {}\n",
                                      key, item.size(), sizeof(btrfs::dev_extent));
            }

            const auto& de = *(btrfs::dev_extent*)item.data();

            if (!allocs.empty() && allocs.back().first + allocs.back().second == key.offset)
                allocs.back().second += de.length;
            else
                allocs.emplace_back(key.offset, de.length);

            return true;
    });

    uint64_t end = 0x100000; // don't allocate in first megabyte

    for (const auto& a : allocs) {
        if (a.first - end >= size)
            return end;

        end = a.first + a.second;
    }

    if (f.dev.sb.dev_item.total_bytes - end >= size)
        return end;

    // FIXME - format size nicely
    throw formatted_error("Could not find {} bytes free to allocate chunk stripe.", size);
}

static void write_data(fs& f, uint64_t addr, span<const uint8_t> data) {
    auto& [chunk_start, c] = find_chunk(f, addr);

    switch (btrfs::get_chunk_raid_type(c.c)) {
        // FIXME - RAID5, RAID6, RAID10, RAID0

        case btrfs::raid_type::SINGLE:
        case btrfs::raid_type::DUP:
        case btrfs::raid_type::RAID1:
        case btrfs::raid_type::RAID1C3:
        case btrfs::raid_type::RAID1C4: {
            auto stripes = span(c.c.stripe, c.c.num_stripes);

            for (auto& s : stripes) {
                if (f.dev.sb.dev_item.devid != s.devid)
                    throw formatted_error("device {} not found", s.devid);

                f.dev.f.seekg(s.offset + addr - chunk_start);
                f.dev.f.write((char*)data.data(), data.size());
            }

            break;
        }

        default:
            throw formatted_error("unhandled RAID type {}\n",
                                  btrfs::get_chunk_raid_type(c.c));
    }
}

static void write_superblocks(fs& f) {
    auto& d = f.dev;

    // FIXME - sb backups

    for (auto a : btrfs::superblock_addrs) {
        if (a + sizeof(d.sb) > f.dev.sb.dev_item.total_bytes)
            break;

        d.f.seekg(a);

        d.sb.bytenr = a;

        btrfs::calc_superblock_csum(d.sb);

        d.f.write((char*)&d.sb, sizeof(d.sb));
    }
}

static void flush_transaction(fs& f) {
    auto& sb = f.dev.sb;

    // FIXME - update FST (may be recursive)
    // FIXME - update extent tree (may be recursive)
    // FIXME - update used value in BG items

    for (auto& rc : f.ref_changes) {
        if (rc.second.refcount_change < 0)
            continue;

        auto& tree = f.tree_cache.find(rc.first)->second;
        auto& h = *(btrfs::header*)tree.data();

        if (h.flags & btrfs::HEADER_FLAG_WRITTEN)
            continue;

        print("FIXME - flush_transaction metadata {:x}\n", rc.first);

        h.flags |= btrfs::HEADER_FLAG_WRITTEN;

        // FIXME - set generation
        // FIXME - calc checksum

        write_data(f, h.bytenr, span((uint8_t*)tree.data(), sb.nodesize));
    }

    f.ref_changes.clear();

    write_superblocks(f);
}

static void allocate_stripe(fs& f, uint64_t offset, uint64_t size) {
    print("FIXME - allocate_stripe {:x}, {:x}\n", offset, size);

    auto phys = find_hole_for_chunk(f, size);
    print("phys = {:x}\n", phys);

    // FIXME - adjust dev and sb total_bytes for new stripe

    auto key = btrfs::key{ btrfs::FIRST_CHUNK_TREE_OBJECTID, btrfs::key_type::CHUNK_ITEM, offset };

    auto [found_key, sp] = find_item(f, btrfs::CHUNK_TREE_OBJECTID, key, true);

    if (key != found_key)
        throw formatted_error("allocate_stripe: searched for {}, found {}\n", key, found_key);

    // FIXME - clear RAID flags (make SINGLE)
    // FIXME - also clear RAID flags in BG item
    // FIXME - set num_stripes to 1
    // FIXME - add stripe
    // FIXME - add dev extent item

    flush_transaction(f);

    // FIXME - unmark new metadata
    // FIXME - free old metadata
    // FIXME - update in-memory FST
    // FIXME - TRIM? (optional?)
}

static void demap_bg(fs& f, uint64_t offset) {
    print("FIXME - demap_bg {:x}\n", offset); // FIXME

    auto& [_, c] = find_chunk(f, offset);

    if (c.c.num_stripes == 0)
        allocate_stripe(f, offset, c.c.length);

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

static void load_fst(fs& f) {
    using vp = vector<pair<uint64_t, uint64_t>>;

    map<uint64_t, vp> fst;
    vp* c = nullptr;

    walk_tree(f, btrfs::FREE_SPACE_TREE_OBJECTID, nullopt,
              [&](const btrfs::key& key, span<const uint8_t> data) {
        switch (key.type) {
            case btrfs::key_type::FREE_SPACE_INFO: {
                auto [it, _] = fst.emplace((uint64_t)key.objectid, vp{});

                c = &it->second;
                break;
            }

            case btrfs::key_type::FREE_SPACE_EXTENT:
                c->emplace_back(key.objectid, key.offset);
                break;

            case btrfs::key_type::FREE_SPACE_BITMAP:
                throw formatted_error("FIXME - {} in FST\n", key);

            default:
                throw formatted_error("unexpected item {} in FST\n", key);
        }

        return true;
    });

    // FIXME - cut out superblocks

    // FIXME - merge into two lists, data and metadata?
    // FIXME - order entries by size?

    auto fst_it = fst.begin();
    auto c_it = f.chunks.begin();

    while (fst_it != fst.end()) {
        auto& e = *fst_it;

        while (c_it->first < e.first) {
            c_it++;
        }

        auto& c = *c_it;

        // old versions of mkfs.btrfs create spurious FST entries, ignore these
        if (c.first != e.first) {
            fst_it++;
            continue;
        }

        c.second.fst = move(e.second);

        fst_it++;
    }
}

static void demap(const filesystem::path& fn) {
    fs f(fn);

    if (f.dev.f.fail())
        throw formatted_error("Failed to open {}", fn.string()); // FIXME - include why

    read_superblock(f.dev);

    auto& sb = f.dev.sb;

    // FIXME - check incompat and compat_ro flags

    if (sb.csum_type != btrfs::csum_type::CRC32)
        throw formatted_error("FIXME - support csum type {}", sb.csum_type); // FIXME

    if (!(sb.incompat_flags & btrfs::FEATURE_INCOMPAT_REMAP_TREE))
        throw runtime_error("remap-tree incompat flag not set");

    if (sb.num_devices != 1)
        throw runtime_error("multi-device support not yet implemented"); // FIXME

    load_sys_chunks(f);
    load_chunks(f);

    // FIXME - die if transaction log there?

    load_fst(f);

    for (const auto& c : f.chunks) {
        if (c.second.c.type & btrfs::BLOCK_GROUP_REMAPPED) {
            demap_bg(f, c.first);
            break; // FIXME
        }
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
