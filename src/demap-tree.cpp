#include <iostream>
#include <filesystem>
#include <fstream>
#include <map>
#include <set>
#include <functional>
#include <print>
#include <getopt.h>
#include <string.h>
#include <assert.h>
#include "config.h"

import cxxbtrfs;
import formatted_error;

using namespace std;

#define MAX_STRIPES 16

static const size_t SZ_1M = 0x100000;

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
    uint64_t tree;
    int64_t refcount_change;
};

struct path {
    array<span<uint8_t>, btrfs::MAX_LEVEL> bufs;
    array<uint32_t, btrfs::MAX_LEVEL> slots;
};

struct fs {
    fs(const filesystem::path& fn) : dev(fn) { }

    device dev;
    map<uint64_t, chunk_info> chunks;
    map<uint64_t, string> tree_cache; // FIXME - basic_string<uint8_t> or vector<uint8_t> instead?
    map<uint64_t, ref_change> ref_changes;
    set<uint64_t> remove_chunks;
};

static pair<uint64_t, uint8_t> find_tree_addr(fs& f, uint64_t tree);
static pair<btrfs::key, span<uint8_t>> find_item(fs& f, uint64_t tree,
                                                 const btrfs::key& key, bool cow);
static uint64_t translate_remap(fs& f, uint64_t addr, uint64_t& left_in_remap);
static void remove_from_remap_tree(fs& f, uint64_t src_addr, uint64_t length);

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

    assert(c.c.num_stripes > 0);

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

static void read_metadata(fs& f, uint64_t addr, uint8_t level) {
    auto& sb = f.dev.sb;

    if (f.tree_cache.contains(addr))
        return;

    uint64_t read_addr = addr;

    if (f.dev.sb.incompat_flags & btrfs::FEATURE_INCOMPAT_REMAP_TREE) {
        auto& [chunk_start, c] = find_chunk(f, addr);

        if (c.c.type & btrfs::BLOCK_GROUP_REMAPPED) {
            uint64_t left_in_remap;

            read_addr = translate_remap(f, addr, left_in_remap);
            assert(left_in_remap >= f.dev.sb.nodesize);
        }
    }

    auto tree = read_data(f, read_addr, sb.nodesize);

    const auto& h = *(btrfs::header*)tree.data();

    // FIXME - also die on generation mismatch
    // FIXME - check csums
    // FIXME - use other chunk stripe if verification fails

    if (h.bytenr != addr)
        throw formatted_error("Address mismatch: expected {:x}, got {:x}", addr, h.bytenr);

    if (h.level != level)
        throw formatted_error("Level mismatch: expected {:x}, got {:x}", level, h.level);

    f.tree_cache.emplace(make_pair(addr, tree));
}

static void walk_tree2(fs& f, uint64_t addr, uint8_t level,
                       const function<bool(const btrfs::key&, span<const uint8_t>)>& func,
                       optional<btrfs::key> from) {
    read_metadata(f, addr, level);

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

            walk_tree2(f, it.blockptr, level - 1, func, from);
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

        case btrfs::REMAP_TREE_OBJECTID:
            type = btrfs::BLOCK_GROUP_REMAP;
            break;

        default:
            type = btrfs::BLOCK_GROUP_METADATA;
            break;
    }

    // allocate from FST

    for (auto& [_, c] : f.chunks) {
        if (c.c.type & btrfs::BLOCK_GROUP_REMAPPED)
            continue;

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

static void cow_tree(fs& f, path& p, uint8_t level) {
    auto& sb = f.dev.sb;
    const auto& orig_h = *(btrfs::header*)p.bufs[level].data();

    if (!(orig_h.flags & btrfs::HEADER_FLAG_WRITTEN))
        return;

    auto new_addr = allocate_metadata(f, orig_h.owner);

    auto [it, _] = f.tree_cache.emplace(new_addr, "");

    auto& new_tree = it->second;

    new_tree.resize(sb.nodesize);
    memcpy(new_tree.data(), p.bufs[level].data(), sb.nodesize);

    auto& h = *(btrfs::header*)new_tree.data();

    h.bytenr = new_addr;
    h.generation = sb.generation + 1;
    h.flags &= ~btrfs::HEADER_FLAG_WRITTEN;

    {
        auto [it2, inserted] = f.ref_changes.emplace(orig_h.bytenr,
                                                     ref_change{h.owner, -1});

        if (!inserted)
            it2->second.refcount_change--;
    }

    f.ref_changes.emplace(new_addr, ref_change{h.owner, 1});

    if (!p.bufs[h.level + 1].empty()) { // FIXME - and level not maxed out
        auto items = (btrfs::key_ptr*)((uint8_t*)p.bufs[h.level + 1].data() + sizeof(btrfs::header));
        auto& parent = items[p.slots[h.level + 1]];

        parent.blockptr = h.bytenr;
        parent.generation = sb.generation + 1;
    } else {
        if (h.owner == btrfs::CHUNK_TREE_OBJECTID) {
            sb.chunk_root = h.bytenr;
            sb.chunk_root_generation = sb.generation + 1;
        } else if (h.owner == btrfs::ROOT_TREE_OBJECTID)
            sb.root = h.bytenr;
        else {
            btrfs::key key{h.owner, btrfs::key_type::ROOT_ITEM, 0};

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
            ri.generation = sb.generation + 1;
            ri.generation_v2 = ri.generation;

            if (h.owner == btrfs::REMAP_TREE_OBJECTID) {
                sb.remap_root = h.bytenr;
                sb.remap_root_generation = sb.generation + 1;
            }
        }
    }

    // FIXME - mark as dirty (delayed ref)
    // FIXME - mark old tree as going away (delayed ref)
    // FIXME - what if COWing snapshotted tree?

    p.bufs[level] = span((uint8_t*)new_tree.data(), sb.nodesize);
}

static void find_item2(fs& f, uint64_t addr, uint8_t level, const btrfs::key& key,
                       bool cow, uint64_t tree, path& p) {
    auto& sb = f.dev.sb;

    // FIXME - separate COW and no-COW versions of this, so we can use
    //         const properly?

    read_metadata(f, addr, level);

    p.bufs[level] = span((uint8_t*)f.tree_cache.find(addr)->second.data(), sb.nodesize);

    if (cow)
        cow_tree(f, p, level);

    const auto& h = *(btrfs::header*)p.bufs[level].data();

    if (h.level == 0) {
        auto items = span((btrfs::item*)((uint8_t*)&h + sizeof(btrfs::header)), h.nritems);

        for (uint32_t i = 0; i < items.size(); i++) {
            auto& it = items[i];

            if (it.key < key)
                continue;

            p.slots[0] = i;

            return;
        }

        p.slots[0] = items.size();
    } else {
        auto items = span((btrfs::key_ptr*)((uint8_t*)&h + sizeof(btrfs::header)), h.nritems);

        for (size_t i = 0; i < h.nritems - 1; i++) {
            if (key >= items[i].key && key < items[i + 1].key) {
                p.slots[h.level] = i;
                find_item2(f, items[i].blockptr, level - 1, key, cow, tree, p);
                return;
            }
        }

        p.slots[h.level] = h.nritems - 1;
        find_item2(f, items[h.nritems - 1].blockptr, level - 1, key, cow,
                   tree, p);
    }
}

static span<uint8_t> item_span(path& p) {
    const auto& h = *(btrfs::header*)p.bufs[0].data();
    auto items = (btrfs::item*)((uint8_t*)&h + sizeof(btrfs::header));
    auto& it = items[p.slots[0]];

    return span((uint8_t*)p.bufs[0].data() + sizeof(btrfs::header) + it.offset, it.size);
}

static pair<btrfs::key, span<uint8_t>> find_item(fs& f, uint64_t tree,
                                                 const btrfs::key& key, bool cow) {
    auto [addr, level] = find_tree_addr(f, tree);
    path p;

    find_item2(f, addr, level, key, cow, tree, p);

    const auto& h = *(btrfs::header*)p.bufs[0].data();

    if (p.slots[0] >= h.nritems)
        return make_pair((btrfs::key){ 0xffffffffffffffff, (enum btrfs::key_type)0xff, 0xffffffffffffffff }, span<uint8_t>());

    auto items = (btrfs::item*)((uint8_t*)&h + sizeof(btrfs::header));
    auto& it = items[p.slots[0]];

    return { it.key, item_span(p) };
}

static pair<uint64_t, uint8_t> find_tree_addr(fs& f, uint64_t tree) {
    auto& sb = f.dev.sb;

    if (tree == btrfs::CHUNK_TREE_OBJECTID)
        return { sb.chunk_root, sb.chunk_root_level };
    else if (tree == btrfs::ROOT_TREE_OBJECTID)
        return { sb.root, sb.root_level };

    auto [key, data] = find_item(f, btrfs::ROOT_TREE_OBJECTID, { tree, btrfs::key_type::ROOT_ITEM, 0 }, false);

    if (key.objectid != tree || key.type != btrfs::key_type::ROOT_ITEM)
        throw formatted_error("find_tree_addr: tree {:x} not found in root\n", tree);

    if (data.size() < sizeof(btrfs::root_item)) {
        throw formatted_error("find_tree_addr: ROOT_ITEM for tree {:x} was {} bytes, expected {}\n",
                              tree, data.size(), sizeof(btrfs::root_item));
    }

    const auto& ri = *(btrfs::root_item*)data.data();

    return { ri.bytenr, ri.level };
}

static void walk_tree(fs& f, uint64_t tree, optional<btrfs::key> from,
                      const function<bool(const btrfs::key&, span<const uint8_t>)>& func) {
    auto [addr, level] = find_tree_addr(f, tree);

    walk_tree2(f, addr, level, func, from);
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
            assert(c.c.num_stripes > 0);

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

static span<uint8_t> insert_item(fs& f, uint64_t tree, const btrfs::key& key,
                                 uint32_t size) {
    auto& sb = f.dev.sb;

    if (size > sb.nodesize - sizeof(btrfs::header) - sizeof(btrfs::item)) {
        throw formatted_error("insert_item: key {} in tree {:x} would be {} bytes, too big for any tree",
                              key, tree, size);
    }

    auto [addr, level] = find_tree_addr(f, tree);
    path p;

    find_item2(f, addr, level, key, true, tree, p);

    auto& h = *(btrfs::header*)p.bufs[0].data();
    auto items = (btrfs::item*)((uint8_t*)&h + sizeof(btrfs::header));

    // FIXME - make sure this works if tree is currently empty

    if (p.slots[0] < h.nritems && key == items[p.slots[0]].key) {
        throw formatted_error("insert_item: key {} in tree {:x} already exists",
                              key, tree);
    }

    assert(p.slots[0] <= h.nritems);

    {
        unsigned int data_size = 0;

        for (uint32_t i = 0; i < h.nritems; i++) {
            data_size += items[i].size;
        }

        unsigned int size_used = data_size + (unsigned int)(h.nritems * sizeof(btrfs::item));

        if (size_used + sizeof(btrfs::item) + size > sb.nodesize - sizeof(btrfs::header))
            throw runtime_error("insert_item: FIXME - split tree"); // FIXME
    }

    // insert new btrfs::item

    if (p.slots[0] < h.nritems) {
        memmove(&items[p.slots[0] + 1], &items[p.slots[0]],
                (h.nritems - p.slots[0]) * sizeof(btrfs::item));
    }

    h.nritems++;

    items[p.slots[0]].key = key;

    if (size > 0 && p.slots[0] != h.nritems - 1) {
        unsigned int to_move = 0;

        // move data around

        uint32_t off = sizeof(btrfs::header) + items[h.nritems - 1].offset;

        for (unsigned int i = p.slots[0] + 1; i < h.nritems; i++) {
            to_move += items[i].size;
            items[i].offset -= size;
        }

        assert(off >= size + sizeof(btrfs::header));

        memmove(p.bufs[0].data() + off - size, p.bufs[0].data() + off, to_move);
    }

    if (p.slots[0] == 0)
        items[p.slots[0]].offset = (uint32_t)(sb.nodesize - sizeof(btrfs::header) - size);
    else
        items[p.slots[0]].offset = (uint32_t)(items[p.slots[0] - 1].offset - size);

    items[p.slots[0]].size = size;

    // FIXME - if first item, update internal nodes (recursively)

    return item_span(p);
}

static void delete_item2(fs& f, path& p) {
    auto& sb = f.dev.sb;
    auto& h = *(btrfs::header*)p.bufs[0].data();
    auto items = (btrfs::item*)((uint8_t*)&h + sizeof(btrfs::header));

    // move data

    if (items[p.slots[0]].size != 0) {
        unsigned int data_size = 0, after_item = 0;

        for (unsigned int i = 0; i < h.nritems; i++) {
            data_size += items[i].size;

            if (i > p.slots[0])
                after_item += items[i].size;
        }

        memmove(p.bufs[0].data() + sb.nodesize - data_size + items[p.slots[0]].size,
                p.bufs[0].data() + sb.nodesize - data_size,
                after_item);

        for (unsigned int i = p.slots[0] + 1; i < h.nritems; i++) {
            items[i].offset += (uint32_t)items[p.slots[0]].size; // FIXME - make it so cast not needed
        }
    }

    // adjust items

    memmove(&items[p.slots[0]], &items[p.slots[0] + 1],
            sizeof(btrfs::item) * (h.nritems - p.slots[0] - 1));
    h.nritems--;

    // FIXME - update parents if deleting first item

    // FIXME - if nritems is now 0 and not top, remove entry in parent
    // FIXME - adjust levels if internal tree has only one entry
    // FIXME - merging trees
    // FIXME - make sure path still valid if we have to rearrange things
}

static void delete_item(fs& f, uint64_t tree, const btrfs::key& key) {
    auto [addr, level] = find_tree_addr(f, tree);
    path p;

    find_item2(f, addr, level, key, true, tree, p);

    auto& h = *(btrfs::header*)p.bufs[0].data();
    auto items = (btrfs::item*)((uint8_t*)&h + sizeof(btrfs::header));

    if (p.slots[0] >= h.nritems || key != items[p.slots[0]].key) {
        throw formatted_error("delete_item: key {} in tree {:x} does not exist",
                              key, tree);
    }

    delete_item2(f, p);
}

static uint32_t path_nritems(const path& p, uint8_t level) {
    const auto& h = *(btrfs::header*)p.bufs[level].data();

    return h.nritems;
}

static bool prev_item(fs& f, path& p, bool cow) {
    if (p.slots[0] != 0) {
        if (cow)
            cow_tree(f, p, 0); // FIXME - also COW parents

        p.slots[0]--;
        return true;
    }

    auto orig_p = p;

    for (uint8_t i = 1; i < btrfs::MAX_LEVEL; i++) {
        if (p.bufs[i].empty())
            break;

        if (p.slots[i] == 0)
            continue;

        p.slots[i]--;

        for (auto j = (int8_t)i; j > 0; j--) {
            auto& sb = f.dev.sb;
            const auto& h = *(btrfs::header*)p.bufs[j].data();
            auto items = span((btrfs::key_ptr*)((uint8_t*)&h + sizeof(btrfs::header)), h.nritems);

            read_metadata(f, items[p.slots[j]].blockptr, j);

            p.bufs[h.level] = span((uint8_t*)f.tree_cache.find(items[p.slots[j]].blockptr)->second.data(),
                                   sb.nodesize);

            if (cow)
                cow_tree(f, p, j); // FIXME - also COW parents

            p.slots[j - 1] = path_nritems(p, j - 1) - 1;
        }

        return true;
    }

    p = orig_p;

    return false;
}

static bool next_item(fs& f, path& p, bool cow) {
    if (p.slots[0] != path_nritems(p, 0) - 1) {
        if (cow)
            cow_tree(f, p, 0); // FIXME - also COW parents

        p.slots[0]++;
        return true;
    }

    auto orig_p = p;

    for (uint8_t i = 1; i < btrfs::MAX_LEVEL; i++) {
        if (p.bufs[i].empty())
            break;

        if (p.slots[i] == path_nritems(p, i) - 1)
            continue;

        p.slots[i]++;

        for (auto j = (int8_t)i; j > 0; j--) {
            auto& sb = f.dev.sb;
            const auto& h = *(btrfs::header*)p.bufs[j].data();
            auto items = span((btrfs::key_ptr*)((uint8_t*)&h + sizeof(btrfs::header)), h.nritems);

            read_metadata(f, items[p.slots[j]].blockptr, j);

            p.bufs[h.level] = span((uint8_t*)f.tree_cache.find(items[p.slots[j]].blockptr)->second.data(),
                                   sb.nodesize);

            if (cow)
                cow_tree(f, p, j); // FIXME - also COW parents

            p.slots[j - 1] = 0;
        }

        return true;
    }

    p = orig_p;

    return false;
}

static uint64_t translate_remap(fs& f, uint64_t addr, uint64_t& left_in_remap) {
    bool moved_back = false;
    btrfs::key key{addr, btrfs::key_type::IDENTITY_REMAP, 0};

    auto [remap_addr, remap_level] = find_tree_addr(f, btrfs::REMAP_TREE_OBJECTID);
    path p;

    find_item2(f, remap_addr, remap_level, key, false,
               btrfs::REMAP_TREE_OBJECTID, p);

    {
        const auto& h = *(btrfs::header*)p.bufs[0].data();

        if (h.nritems == 0)
            throw runtime_error("translate_remap: remap tree is empty");

        if (p.slots[0] == h.nritems) {
            p.slots[0]--;
            moved_back = true;
        }

        auto items = (btrfs::item*)((uint8_t*)&h + sizeof(btrfs::header));
        auto& it = items[p.slots[0]];

        if (!moved_back && it.key.objectid > addr)
            prev_item(f, p, false);
    }

    const auto& h = *(btrfs::header*)p.bufs[0].data();
    auto items = (btrfs::item*)((uint8_t*)&h + sizeof(btrfs::header));
    auto& it = items[p.slots[0]];

    if (it.key.objectid > addr || it.key.objectid + it.key.offset <= addr)
        throw formatted_error("translate_remap: no remap entry found for {:x}", addr);

    left_in_remap = it.key.objectid + it.key.offset - addr;

    switch (it.key.type) {
        case btrfs::key_type::IDENTITY_REMAP:
            return addr;

        case btrfs::key_type::REMAP: {
            assert(it.size == sizeof(btrfs::remap));

            auto& r = *(btrfs::remap*)item_span(p).data();

            return addr - it.key.objectid + r.address;
        }

        default:
            throw formatted_error("translate_remap: found {}, expected REMAP or IDENTITY_REMAP",
                                  it.key);
    }
}

static void change_key(path& p, const btrfs::key& key) {
    const auto& h = *(btrfs::header*)p.bufs[0].data();
    auto items = (btrfs::item*)((uint8_t*)&h + sizeof(btrfs::header));
    auto& it = items[p.slots[0]];

    it.key = key;

    // FIXME - if first item, change key of parents (recursively)
}

static void change_fst_extent_count(fs& f, uint64_t start, int32_t change) {
    auto [off, c] = find_chunk(f, start);

    btrfs::key key{off, btrfs::key_type::FREE_SPACE_INFO, c.c.length};

    auto [found_key, sp] = find_item(f, btrfs::FREE_SPACE_TREE_OBJECTID, key, true);

    if (found_key != key) {
        throw formatted_error("change_fst_extent_count: looked for {}, found {}",
                              key, found_key);
    }

    if (sp.size() < sizeof(btrfs::free_space_info)) {
        throw formatted_error("change_fst_extent_count: {} was {} bytes, expected {}",
                              key, sp.size(), sizeof(btrfs::free_space_info));
    }

    auto& fsi = *(btrfs::free_space_info*)sp.data();

    fsi.extent_count += change;
}

static void remove_from_free_space2(fs& f, path& p, uint64_t start,
                                    uint64_t len) {
    const auto& h = *(btrfs::header*)p.bufs[0].data();
    auto items = (btrfs::item*)((uint8_t*)&h + sizeof(btrfs::header));
    auto& it = items[p.slots[0]];

    assert(it.key.objectid <= start);
    assert(it.key.objectid + it.key.offset >= start + len);

    if (it.key.objectid == start && it.key.offset == len) { // remove whole entry
        delete_item2(f, p);

        change_fst_extent_count(f, start, -1);
    } else if (it.key.objectid == start) // remove beginning
        change_key(p, { start + len, it.key.type, it.key.offset - len });
    else if (it.key.objectid + it.key.offset == start + len) // remove end
        change_key(p, { it.key.objectid, it.key.type, it.key.offset - len });
    else { // remove middle
        auto orig_key = it.key;

        change_key(p, { it.key.objectid, it.key.type, start - it.key.objectid });

        btrfs::key new_key{ start + len, btrfs::key_type::FREE_SPACE_EXTENT,
                            orig_key.objectid + orig_key.offset - start - len };
        insert_item(f, btrfs::FREE_SPACE_TREE_OBJECTID, new_key, 0);

        change_fst_extent_count(f, start, 1);
    }
}

static void remove_from_free_space(fs& f, uint64_t start, uint64_t len) {
    // FIXME - bitmaps

    auto [addr, level] = find_tree_addr(f, btrfs::FREE_SPACE_TREE_OBJECTID);
    path p;
    btrfs::key key{start, btrfs::key_type::FREE_SPACE_EXTENT, 0};

    find_item2(f, addr, level, key, true, btrfs::FREE_SPACE_TREE_OBJECTID, p);

    {
        const auto& h = *(btrfs::header*)p.bufs[0].data();
        auto items = (btrfs::item*)((uint8_t*)&h + sizeof(btrfs::header));

        if (p.slots[0] < h.nritems) {
            auto& it = items[p.slots[0]];

            if (it.key.type == btrfs::key_type::FREE_SPACE_EXTENT &&
                it.key.objectid <= start) {
                remove_from_free_space2(f, p, start, len);
                return;
            }
        }
    }

    if (!prev_item(f, p, true))
        throw runtime_error("remove_from_free_space: prev_item failed");

    const auto& h = *(btrfs::header*)p.bufs[0].data();
    auto items = (btrfs::item*)((uint8_t*)&h + sizeof(btrfs::header));
    auto& it = items[p.slots[0]];

    if (it.key.type == btrfs::key_type::FREE_SPACE_EXTENT &&
        it.key.objectid <= start) {
        remove_from_free_space2(f, p, start, len);
        return;
    }

    throw formatted_error("remove_from_free_space: error carving out {:x},{:x}",
                          start, len);
}

static void add_to_free_space2(fs& f, uint64_t start, uint64_t len) {
    // FIXME - throw exception if part of range already free
    // FIXME - bitmaps

    {
        auto [addr, level] = find_tree_addr(f, btrfs::FREE_SPACE_TREE_OBJECTID);
        path p;
        btrfs::key key{start, btrfs::key_type::FREE_SPACE_EXTENT, 0};

        find_item2(f, addr, level, key, true, btrfs::FREE_SPACE_TREE_OBJECTID, p);

        const auto& h = *(btrfs::header*)p.bufs[0].data();
        auto items = (btrfs::item*)((uint8_t*)&h + sizeof(btrfs::header));

        if (p.slots[0] < h.nritems) {
            auto& it = items[p.slots[0]];

            if (it.key.type == btrfs::key_type::FREE_SPACE_EXTENT &&
                it.key.objectid == start + len) {
                // extend backwards

                change_key(p, { start, it.key.type, it.key.offset + len });

                auto orig_p = p;

                if (prev_item(f, p, true)) {
                    const auto& h2 = *(btrfs::header*)p.bufs[0].data();
                    auto items2 = (btrfs::item*)((uint8_t*)&h2 + sizeof(btrfs::header));
                    auto& it2 = items2[p.slots[0]];

                    if (it2.key.type == btrfs::key_type::FREE_SPACE_EXTENT &&
                        it2.key.objectid + it2.key.offset == start) {
                        // bridging

                        change_key(orig_p, { it2.key.objectid, it2.key.type,
                                             it.key.offset + it2.key.offset });
                        delete_item2(f, p);
                        change_fst_extent_count(f, start, -1);
                    }
                }

                return;
            }
        }

        if (prev_item(f, p, true)) {
            auto& it = items[p.slots[0]];

            if (it.key.type == btrfs::key_type::FREE_SPACE_EXTENT &&
                it.key.objectid + it.key.offset == start) {

                // extend forwards

                change_key(p, { it.key.objectid, it.key.type, it.key.offset + len });
                return;
            }
        }
    }

    // new entry

    insert_item(f, btrfs::FREE_SPACE_TREE_OBJECTID,
                { start, btrfs::key_type::FREE_SPACE_EXTENT, len}, 0);
    change_fst_extent_count(f, start, 1);
}

static void add_to_free_space_remapped(fs& f, uint64_t start, uint64_t len) {
    while (true) {
        uint64_t left_in_remap;

        auto dest_addr = translate_remap(f, start, left_in_remap);

        remove_from_remap_tree(f, start, min(len, left_in_remap));

        // if (dest_addr != start)
            // add_to_free_space2(f, dest_addr, min(len, left_in_remap));

        if (left_in_remap >= len)
            break;

        start += left_in_remap;
        len += left_in_remap;
    }
}

static void add_to_free_space(fs& f, uint64_t start, uint64_t len) {
    if (f.dev.sb.incompat_flags & btrfs::FEATURE_INCOMPAT_REMAP_TREE) {
        auto& [chunk_start, c] = find_chunk(f, start);

        if (c.c.type & btrfs::BLOCK_GROUP_REMAPPED) {
            add_to_free_space_remapped(f, start, len);
            return;
        }
    }

    add_to_free_space2(f, start, len);
}

static void update_block_group_used(fs& f, uint64_t address, int64_t delta) {
    auto [addr, level] = find_tree_addr(f, btrfs::BLOCK_GROUP_TREE_OBJECTID);
    auto key = btrfs::key{ address, btrfs::key_type::BLOCK_GROUP_ITEM,
                           0xffffffffffffffff };
    path p;

    find_item2(f, addr, level, key, false, btrfs::BLOCK_GROUP_TREE_OBJECTID, p);

    if (!prev_item(f, p, true))
        throw runtime_error("update_block_group_used: prev_item failed");

    const auto& h = *(btrfs::header*)p.bufs[0].data();
    auto items = (btrfs::item*)((uint8_t*)&h + sizeof(btrfs::header));

    assert(p.slots[0] < h.nritems);

    auto& it = items[p.slots[0]];

    if (it.key.type != btrfs::key_type::BLOCK_GROUP_ITEM ||
        it.key.objectid > address || it.key.objectid + it.key.offset <= address) {
        throw formatted_error("update_block_group_used: searched for {}, found {}",
                              key, it.key);
    }

    assert(it.size >= sizeof(btrfs::block_group_item));

    auto& bgi = *(btrfs::block_group_item*)item_span(p).data();

    bgi.used += delta;

    auto& sb = f.dev.sb;

    sb.bytes_used += delta;
}

static void update_dev_item_bytes_used(fs& f, uint64_t devid, int64_t delta) {
    auto& sb = f.dev.sb;

    auto key = btrfs::key{btrfs::DEV_ITEMS_OBJECTID, btrfs::key_type::DEV_ITEM, devid};
    auto [found_key, sp] = find_item(f, btrfs::CHUNK_TREE_OBJECTID, key, true);

    if (found_key != key) {
        throw formatted_error("update_dev_item_bytes_used: found {}, expected {}",
                              found_key, key);
    }

    if (sp.size() != sizeof(btrfs::dev_item)) {
        throw formatted_error("update_dev_item_bytes_used: {} was {} bytes, expected {}",
                              key, sp.size(), sizeof(btrfs::dev_item));
    }

    auto& di = *(btrfs::dev_item*)sp.data();

    di.bytes_used += delta;

    if (sb.dev_item.devid == devid)
        sb.dev_item.bytes_used += delta;
}

static void remove_chunk(fs& f, uint64_t offset) {
    auto& sb = f.dev.sb;
    uint64_t length;

    {
        auto [addr, level] = find_tree_addr(f, btrfs::BLOCK_GROUP_TREE_OBJECTID);
        btrfs::key key{offset, btrfs::key_type::BLOCK_GROUP_ITEM,
                       0xffffffffffffffff};

        path p;

        find_item2(f, addr, level, key, false,
                   btrfs::BLOCK_GROUP_TREE_OBJECTID, p);

        if (!prev_item(f, p, true))
            throw runtime_error("remove_chunk: prev_item failed");

        const auto& h = *(btrfs::header*)p.bufs[0].data();

        auto items = (btrfs::item*)((uint8_t*)&h + sizeof(btrfs::header));
        auto& it = items[p.slots[0]];

        if (it.key.objectid != offset || it.key.type != btrfs::key_type::BLOCK_GROUP_ITEM) {
            throw formatted_error("remove_chunk: found {} when searching for block group {:x}",
                                  it.key, offset);
        }

        length = it.key.offset;

        assert(it.size >= sizeof(btrfs::block_group_item));

        auto& bgi = *(btrfs::block_group_item*)item_span(p).data();

        if (bgi.used != 0) {
            throw formatted_error("remove_chunk: block group {:x} is not empty (used == {:x})",
                                  offset, bgi.used);
        }

        // remove block group item

        delete_item2(f, p);
    }

    vector<uint64_t> extents;

    {
        auto [addr, level] = find_tree_addr(f, btrfs::CHUNK_TREE_OBJECTID);
        btrfs::key key{btrfs::FIRST_CHUNK_TREE_OBJECTID,
                       btrfs::key_type::CHUNK_ITEM, offset};
        path p;

        find_item2(f, addr, level, key, true, btrfs::CHUNK_TREE_OBJECTID, p);

        const auto& h = *(btrfs::header*)p.bufs[0].data();

        if (p.slots[0] == h.nritems)
            throw formatted_error("remove_chunk: {} not found", key);

        auto items = (btrfs::item*)((uint8_t*)&h + sizeof(btrfs::header));
        auto& it = items[p.slots[0]];

        if (it.key != key) {
            throw formatted_error("remove_chunk: found {}, expected {}",
                                  it.key, key);
        }

        assert(it.size >= offsetof(btrfs::chunk, stripe));

        auto& c = *(btrfs::chunk*)item_span(p).data();

        assert(it.size == offsetof(btrfs::chunk, stripe) + (c.num_stripes * sizeof(btrfs::stripe)));

        for (uint16_t i = 0; i < c.num_stripes; i++) {
            // FIXME - multi-device support
            assert(c.stripe[i].devid == sb.dev_item.devid);
            assert(c.stripe[i].dev_uuid == sb.dev_item.uuid);

            extents.emplace_back(c.stripe[i].offset);
        }

        // remove chunk item

        delete_item2(f, p);
    }

    // remove dev extents

    for (auto e : extents) {
        delete_item(f, btrfs::DEV_TREE_OBJECTID,
                    {sb.dev_item.devid, btrfs::key_type::DEV_EXTENT, e});

        update_dev_item_bytes_used(f, sb.dev_item.devid, -length);
    }

    // remove FST entries

    uint32_t fst_entries;

    {
        auto [addr, level] = find_tree_addr(f, btrfs::FREE_SPACE_TREE_OBJECTID);
        btrfs::key key{offset, btrfs::key_type::FREE_SPACE_INFO, length};
        path p;

        find_item2(f, addr, level, key, true,
                   btrfs::FREE_SPACE_TREE_OBJECTID, p);

        const auto& h = *(btrfs::header*)p.bufs[0].data();

        auto items = (btrfs::item*)((uint8_t*)&h + sizeof(btrfs::header));
        auto& it = items[p.slots[0]];

        if (it.key != key) {
            throw formatted_error("remove_chunk: found {}, expected {}",
                                  it.key, key);
        }

        assert(it.size == sizeof(btrfs::free_space_info));

        auto& fsi = *(btrfs::free_space_info*)item_span(p).data();

        fst_entries = fsi.extent_count;

        delete_item2(f, p);
    }

    // FIXME - FST bitmaps

    for (uint32_t i = 0; i < fst_entries; i++) {
        auto [addr, level] = find_tree_addr(f, btrfs::FREE_SPACE_TREE_OBJECTID);
        btrfs::key key{offset, btrfs::key_type::FREE_SPACE_EXTENT, 0};
        path p;

        find_item2(f, addr, level, key, true,
                   btrfs::FREE_SPACE_TREE_OBJECTID, p);

        const auto& h = *(btrfs::header*)p.bufs[0].data();

        auto items = (btrfs::item*)((uint8_t*)&h + sizeof(btrfs::header));
        auto& it = items[p.slots[0]];

        if (it.key.type != btrfs::key_type::FREE_SPACE_EXTENT) {
            throw formatted_error("remove_chunk: found {}, expected FREE_SPACE_EXTENT",
                                  it.key);
        }

        if (it.key.objectid < offset || it.key.objectid >= offset + length) {
            throw formatted_error("remove_chunk: {} not in range {:x},{:x}",
                                  it.key, offset, length);
        }

        // assert that we're not crossing chunk boundary
        assert(it.key.objectid + it.key.offset <= offset + length);

        delete_item2(f, p);
    }
}

static void flush_transaction(fs& f) {
    auto& sb = f.dev.sb;

    if (f.ref_changes.empty())
        return;

    {
        auto orig_ref_changes = f.ref_changes;

        while (true) {
            decltype(f.ref_changes) local;

            swap(local, f.ref_changes);

            for (auto& rc : local) {
                if (rc.second.refcount_change == 0)
                    continue;

                auto& tree = f.tree_cache.find(rc.first)->second;
                auto& h = *(btrfs::header*)tree.data();

                if (rc.second.refcount_change < 0) {
                    // remove extent tree item

                    // FIXME - might be snapshotted (refcount > 1)
                    // FIXME - might have non-inline elements
                    // FIXME - might be old-style (i.e. not METADATA_ITEM)

                    add_to_free_space(f, h.bytenr, sb.nodesize);

                    if (rc.second.tree != btrfs::REMAP_TREE_OBJECTID) {
                        delete_item(f, btrfs::EXTENT_TREE_OBJECTID,
                                    { h.bytenr, btrfs::key_type::METADATA_ITEM, h.level });
                    }

                    update_block_group_used(f, h.bytenr, -(int64_t)sb.nodesize);
                } else {
                    remove_from_free_space(f, h.bytenr, sb.nodesize);

                    if (rc.second.tree != btrfs::REMAP_TREE_OBJECTID) {
                        // add extent tree item

                        auto sp = insert_item(f, btrfs::EXTENT_TREE_OBJECTID,
                                              { h.bytenr, btrfs::key_type::METADATA_ITEM, h.level },
                                              sizeof(btrfs::extent_item) + sizeof(btrfs::extent_inline_ref));

                        auto& ei = *(btrfs::extent_item*)sp.data();

                        ei.refs = 1;
                        ei.generation = sb.generation + 1;
                        ei.flags = btrfs::EXTENT_FLAG_TREE_BLOCK;

                        auto& eir = *(btrfs::extent_inline_ref*)(sp.data() + sizeof(btrfs::extent_item));

                        eir.type = btrfs::key_type::TREE_BLOCK_REF;
                        eir.offset = h.owner;
                    }

                    update_block_group_used(f, h.bytenr, (int64_t)sb.nodesize);
                }
            }

            for (auto offset : f.remove_chunks) {
                remove_chunk(f, offset);
            }
            f.remove_chunks.clear();

            if (f.ref_changes.empty())
                break;

            for (auto& rc : f.ref_changes) {
                orig_ref_changes.insert(rc);
            }
        }

        swap(f.ref_changes, orig_ref_changes);
    }

    while (!f.ref_changes.empty()) {
        decltype(f.ref_changes) local;

        swap(local, f.ref_changes);

        for (auto& rc : local) {
            if (rc.second.refcount_change < 0)
                continue;

            auto& tree = f.tree_cache.find(rc.first)->second;
            auto& h = *(btrfs::header*)tree.data();

            if (h.flags & btrfs::HEADER_FLAG_WRITTEN)
                continue;

            h.flags |= btrfs::HEADER_FLAG_WRITTEN;

            calc_tree_csum(h, sb);

            write_data(f, h.bytenr, span((uint8_t*)tree.data(), sb.nodesize));
        }
    }

    sb.generation++;

    write_superblocks(f);

    // FIXME - unmark new metadata
    // FIXME - free old metadata
    // FIXME - update in-memory FST
    // FIXME - TRIM? (optional?)
}

static void update_block_group_flags(fs& f, uint64_t offset, uint64_t length,
                                     uint64_t flags) {
    auto key = btrfs::key{ offset, btrfs::key_type::BLOCK_GROUP_ITEM, length };

    auto [found_key, sp] = find_item(f, btrfs::BLOCK_GROUP_TREE_OBJECTID,
                                     key, true);
    if (key != found_key) {
        throw formatted_error("update_block_group_flags: searched for {}, found {}\n",
                              key, found_key);
    }

    if (sp.size() != sizeof(btrfs::block_group_item_v2)) {
        throw formatted_error("update_block_group_flags: {} was {} bytes, expected {}",
                              key, sp.size(), sizeof(btrfs::block_group_item_v2));
    }

    auto& bgi = *(btrfs::block_group_item*)sp.data();

    bgi.flags = flags;
}

static void extend_item(fs& f, path& p, uint32_t size) {
    auto& sb = f.dev.sb;
    const auto& h = *(btrfs::header*)p.bufs[0].data();
    auto items = (btrfs::item*)((uint8_t*)&h + sizeof(btrfs::header));
    auto& it = items[p.slots[0]];

    if (size > sb.nodesize - sizeof(btrfs::header) - sizeof(btrfs::item)) {
        throw formatted_error("extend_item: key {} would be {} bytes, too big for any tree",
                              it.key, size);
    }

    if (it.size == size)
        return;

    if (size < it.size) {
        throw formatted_error("extend_item: size {} for key {} is less than current size {}",
                              size, it.key, it.size);
    }

    uint32_t delta = size - it.size;

    uint32_t used = sizeof(btrfs::header) + (sizeof(btrfs::item) * h.nritems);

    for (unsigned int i = 0; i < h.nritems; i++) {
        used += items[i].size;
    }

    // FIXME - if now too large for node, move items left or right (share this logic with insert_item)

    if (used + delta > sb.nodesize)
        throw runtime_error("extend_item: FIXME - move items left or right");

    // adjust item offsets and move data

    {
        unsigned int to_move = 0;

        // move data around

        uint32_t off = sizeof(btrfs::header) + items[h.nritems - 1].offset;

        for (unsigned int i = p.slots[0]; i < h.nritems; i++) {
            to_move += items[i].size;
            items[i].offset -= delta;
        }

        assert(off >= size + sizeof(btrfs::header));

        memmove(p.bufs[0].data() + off - delta, p.bufs[0].data() + off, to_move);
    }

    // change item size

    it.size = size;
}

static void shorten_item(fs& f, path& p, uint32_t size) {
    auto& sb = f.dev.sb;
    const auto& h = *(btrfs::header*)p.bufs[0].data();
    auto items = (btrfs::item*)((uint8_t*)&h + sizeof(btrfs::header));
    auto& it = items[p.slots[0]];

    if (it.size == size)
        return;

    if (size > it.size) {
        throw formatted_error("shorten_item: size {} for key {} is less than current size {}",
                              size, it.key, it.size);
    }

    uint32_t delta = it.size - size;

    // adjust item offsets and move data

    {
        unsigned int to_move = 0;

        // move data around

        uint32_t off = sizeof(btrfs::header) + items[h.nritems - 1].offset;

        for (unsigned int i = p.slots[0]; i < h.nritems; i++) {
            to_move += items[i].size;
            items[i].offset += delta;
        }

        assert(off + to_move <= sb.nodesize);

        memmove(p.bufs[0].data() + off + delta, p.bufs[0].data() + off,
                to_move - delta);
    }

    // change item size

    it.size = size;
}

static void insert_dev_extent(fs& f, uint64_t devid, uint64_t phys,
                              uint64_t chunk_offset, uint64_t length) {
    auto key = btrfs::key{devid, btrfs::key_type::DEV_EXTENT, phys};
    auto sp = insert_item(f, btrfs::DEV_TREE_OBJECTID, key,
                          sizeof(btrfs::dev_extent));

    auto& de = *(btrfs::dev_extent*)sp.data();

    de.chunk_tree = btrfs::CHUNK_TREE_OBJECTID;
    de.chunk_objectid = btrfs::FIRST_CHUNK_TREE_OBJECTID;
    de.chunk_offset = chunk_offset;
    de.length = length;

    // mkfs sets this properly, Linux sets it to 0
    memset(&de.chunk_tree_uuid, 0, sizeof(de.chunk_tree_uuid));
}

static void allocate_stripe(fs& f, uint64_t offset, uint64_t size) {
    auto& sb = f.dev.sb;

    auto phys = find_hole_for_chunk(f, size);

    auto key = btrfs::key{ btrfs::FIRST_CHUNK_TREE_OBJECTID, btrfs::key_type::CHUNK_ITEM, offset };
    span<uint8_t> sp;

    {
        auto [addr, level] = find_tree_addr(f, btrfs::CHUNK_TREE_OBJECTID);
        path p;

        find_item2(f, addr, level, key, true, btrfs::CHUNK_TREE_OBJECTID, p);

        const auto& h = *(btrfs::header*)p.bufs[0].data();

        if (p.slots[0] >= h.nritems)
            throw formatted_error("allocate_stripe: could not find {}", key);

        auto items = (btrfs::item*)((uint8_t*)&h + sizeof(btrfs::header));
        auto& it = items[p.slots[0]];

        if (key != it.key) {
            throw formatted_error("allocate_stripe: searched for {}, found {}\n",
                                  key, it.key);
        }

        if (it.size != offsetof(btrfs::chunk, stripe)) {
            throw formatted_error("allocate_stripe: {} was {} bytes, expected {}",
                                  key, it.size, offsetof(btrfs::chunk, stripe));
        }

        extend_item(f, p, offsetof(btrfs::chunk, stripe) + sizeof(btrfs::stripe));

        sp = item_span(p);
    }

    auto& c = *(btrfs::chunk*)sp.data();

    assert(c.num_stripes == 0);
    assert(c.type & btrfs::BLOCK_GROUP_REMAPPED);
    assert(!(c.type & btrfs::BLOCK_GROUP_REMAP));
    assert(!(c.type & btrfs::BLOCK_GROUP_SYSTEM));

    // make chunk SINGLE
    c.type &= ~(btrfs::BLOCK_GROUP_RAID0 | btrfs::BLOCK_GROUP_RAID1 |
                btrfs::BLOCK_GROUP_DUP | btrfs::BLOCK_GROUP_RAID10 |
                btrfs::BLOCK_GROUP_RAID5 | btrfs::BLOCK_GROUP_RAID6 |
                btrfs::BLOCK_GROUP_RAID1C3 | btrfs::BLOCK_GROUP_RAID1C4);

    // add stripe

    c.num_stripes = 1;

    c.stripe[0].devid = sb.dev_item.devid;
    c.stripe[0].offset = phys;
    c.stripe[0].dev_uuid = sb.dev_item.uuid;

    // sync chunk changes to BG

    update_block_group_flags(f, offset, c.length, c.type);

    insert_dev_extent(f, sb.dev_item.devid, phys, offset, size);
    update_dev_item_bytes_used(f, sb.dev_item.devid, size);

    {
        // update in-memory chunk item

        auto& c2 = f.chunks.at(offset);

        memcpy(&c2.c, &c, offsetof(btrfs::chunk, stripe) + (c.num_stripes * sizeof(btrfs::stripe)));
    }

    flush_transaction(f);
}

static void remove_from_remap_tree2(fs& f, path& p, uint64_t addr,
                                    uint64_t length) {
    const auto& h = *(btrfs::header*)p.bufs[0].data();
    auto items = (btrfs::item*)((uint8_t*)&h + sizeof(btrfs::header));
    auto& it = items[p.slots[0]];

    if (it.key.objectid == addr) {
        if (it.key.offset == length) {
            // removing whole thing
            delete_item2(f, p);
        } else {
            // removing beginning

            auto& r = *(btrfs::remap*)item_span(p).data();

            r.address += length;

            change_key(p, {addr + length, it.key.type, it.key.offset - length});
        }
    } else if (it.key.objectid + it.key.offset == addr + length) {
        // removing end
        change_key(p, {it.key.objectid, it.key.type,
                       it.key.offset - length});
    } else {
        // removing middle

        const auto& r1 = *(btrfs::remap*)item_span(p).data();
        uint64_t other_addr = r1.address;

        auto orig_key = it.key;

        change_key(p, { it.key.objectid, it.key.type,
                        addr - it.key.objectid });

        btrfs::key new_key{ addr + length, it.key.type,
                            orig_key.objectid + orig_key.offset - addr - length };
        auto sp = insert_item(f, btrfs::REMAP_TREE_OBJECTID, new_key,
                              sizeof(btrfs::remap));

        auto& r2 = *(btrfs::remap*)sp.data();

        r2.address = other_addr + addr + length - it.key.objectid;
    }
}

static void update_block_group_remap_bytes(fs& f, uint64_t address, int64_t delta) {
    auto [addr, level] = find_tree_addr(f, btrfs::BLOCK_GROUP_TREE_OBJECTID);
    auto key = btrfs::key{ address, btrfs::key_type::BLOCK_GROUP_ITEM,
                           0xffffffffffffffff };
    path p;

    find_item2(f, addr, level, key, false, btrfs::BLOCK_GROUP_TREE_OBJECTID, p);

    if (!prev_item(f, p, true))
        throw runtime_error("update_block_group_remap_bytes: prev_item failed");

    const auto& h = *(btrfs::header*)p.bufs[0].data();
    auto items = (btrfs::item*)((uint8_t*)&h + sizeof(btrfs::header));

    assert(p.slots[0] < h.nritems);

    auto& it = items[p.slots[0]];

    if (it.key.type != btrfs::key_type::BLOCK_GROUP_ITEM ||
        it.key.objectid > address || it.key.objectid + it.key.offset <= address) {
        throw formatted_error("update_block_group_remap_bytes: searched for {}, found {}",
                              key, it.key);
    }

    if (it.size != sizeof(btrfs::block_group_item_v2)) {
        throw formatted_error("update_block_group_remap_bytes: {} was {} bytes, expected {}",
                              it.key, it.size, sizeof(btrfs::block_group_item_v2));
    }

    auto& bgi = *(btrfs::block_group_item_v2*)item_span(p).data();

    assert(delta > 0 || (int64_t)bgi.remap_bytes >= -delta);

    bgi.remap_bytes += delta;
}

static void remove_from_remap_tree(fs& f, uint64_t src_addr, uint64_t length) {
    print("remove_from_remap_tree: {:x}, {:x}\n", src_addr, length);

    btrfs::key found_key;
    uint64_t dest_addr;

    // FIXME - identity remaps

    // do remap

    {
        auto [addr, level] = find_tree_addr(f, btrfs::REMAP_TREE_OBJECTID);
        path p;
        btrfs::key key{src_addr, btrfs::key_type::REMAP, 0xffffffffffffffff};

        find_item2(f, addr, level, key, false, btrfs::REMAP_TREE_OBJECTID, p);

        if (!prev_item(f, p, true))
            throw formatted_error("remove_from_remap_tree: prev_item failed");

        const auto& h = *(btrfs::header*)p.bufs[0].data();
        auto items = (btrfs::item*)((uint8_t*)&h + sizeof(btrfs::header));
        auto& it = items[p.slots[0]];

        assert(it.key.type == btrfs::key_type::REMAP);
        assert(it.key.objectid <= src_addr);
        assert(it.key.objectid + it.key.offset >= src_addr + length);
        assert(it.size == sizeof(btrfs::remap));

        found_key = it.key;

        auto& r = *(btrfs::remap*)item_span(p).data();

        dest_addr = r.address;

        remove_from_remap_tree2(f, p, src_addr, length);
    }

    // do remap backref

    {
        auto [addr, level] = find_tree_addr(f, btrfs::REMAP_TREE_OBJECTID);
        path p;
        btrfs::key key{dest_addr, btrfs::key_type::REMAP_BACKREF, found_key.offset};

        find_item2(f, addr, level, key, true, btrfs::REMAP_TREE_OBJECTID, p);

        const auto& h = *(btrfs::header*)p.bufs[0].data();

        assert(p.slots[0] < h.nritems);

        auto items = (btrfs::item*)((uint8_t*)&h + sizeof(btrfs::header));
        auto& it = items[p.slots[0]];

        if (it.key != key) {
            throw formatted_error("remove_from_remap_tree: found {}, expected {}",
                                  it.key, key);
        }

        assert(it.size == sizeof(btrfs::remap));

        auto& r = *(btrfs::remap*)item_span(p).data();

        assert(r.address == found_key.objectid);

        remove_from_remap_tree2(f, p, dest_addr + src_addr - found_key.objectid,
                                length);
    }

    update_block_group_remap_bytes(f, dest_addr, -length);

    add_to_free_space(f, dest_addr + src_addr - found_key.objectid, length);
}

static void update_block_group_identity_remap_count(fs& f, uint64_t address,
                                                    int32_t delta) {
    auto [addr, level] = find_tree_addr(f, btrfs::BLOCK_GROUP_TREE_OBJECTID);
    auto key = btrfs::key{ address, btrfs::key_type::BLOCK_GROUP_ITEM,
                           0xffffffffffffffff };
    path p;

    find_item2(f, addr, level, key, false, btrfs::BLOCK_GROUP_TREE_OBJECTID, p);

    if (!prev_item(f, p, true))
        throw runtime_error("update_block_group_identity_remap_count: prev_item failed");

    const auto& h = *(btrfs::header*)p.bufs[0].data();
    auto items = (btrfs::item*)((uint8_t*)&h + sizeof(btrfs::header));

    assert(p.slots[0] < h.nritems);

    auto& it = items[p.slots[0]];

    if (it.key.type != btrfs::key_type::BLOCK_GROUP_ITEM ||
        it.key.objectid > address || it.key.objectid + it.key.offset <= address) {
        throw formatted_error("update_block_group_identity_remap_count: searched for {}, found {}",
                              key, it.key);
    }

    if (it.size != sizeof(btrfs::block_group_item_v2)) {
        throw formatted_error("update_block_group_identity_remap_count: {} was {} bytes, expected {}",
                              it.key, it.size, sizeof(btrfs::block_group_item_v2));
    }

    auto& bgi = *(btrfs::block_group_item_v2*)item_span(p).data();

    assert(delta > 0 || (int32_t)bgi.identity_remap_count >= -delta);

    bgi.identity_remap_count += delta;
}

static void add_identity_remap(fs& f, uint64_t src_addr, uint64_t length) {
    {
        auto [addr, level] = find_tree_addr(f, btrfs::REMAP_TREE_OBJECTID);
        path p;
        btrfs::key key{src_addr, btrfs::key_type::IDENTITY_REMAP, 0};

        find_item2(f, addr, level, key, true, btrfs::REMAP_TREE_OBJECTID, p);

        const auto& h = *(btrfs::header*)p.bufs[0].data();
        auto items = (btrfs::item*)((uint8_t*)&h + sizeof(btrfs::header));

        if (p.slots[0] < h.nritems) {
            auto& it = items[p.slots[0]];

            if (it.key.type == btrfs::key_type::IDENTITY_REMAP &&
                it.key.objectid == src_addr + length) {
                // extend backwards

                change_key(p, { src_addr, it.key.type, it.key.offset + length });

                auto orig_p = p;

                if (prev_item(f, p, true)) {
                    const auto& h2 = *(btrfs::header*)p.bufs[0].data();
                    auto items2 = (btrfs::item*)((uint8_t*)&h2 + sizeof(btrfs::header));
                    auto& it2 = items2[p.slots[0]];

                    if (it2.key.type == btrfs::key_type::IDENTITY_REMAP &&
                        it2.key.objectid + it2.key.offset == src_addr) {
                        // bridging

                        change_key(orig_p, { it2.key.objectid, it2.key.type,
                                             it.key.offset + it2.key.offset });
                        delete_item2(f, p);
                        update_block_group_identity_remap_count(f, src_addr, -1);
                    }
                }

                return;
            }
        }

        if (prev_item(f, p, true)) {
            auto& it = items[p.slots[0]];

            if (it.key.type == btrfs::key_type::IDENTITY_REMAP &&
                it.key.objectid + it.key.offset == src_addr) {

                // extend forwards

                change_key(p, { it.key.objectid, it.key.type, it.key.offset + length });
                return;
            }
        }
    }

    // new entry

    insert_item(f, btrfs::REMAP_TREE_OBJECTID,
                { src_addr, btrfs::key_type::IDENTITY_REMAP, length }, 0);
    update_block_group_identity_remap_count(f, src_addr, 1);
}

static uint64_t process_remap(fs& f, uint64_t src_addr, uint64_t length,
                              uint64_t dst_addr) {
    static const uint64_t MAX_COPY = SZ_1M; // FIXME - make option?

    print("process_remap: {:x}, {:x}, {:x}\n", src_addr, length, dst_addr);

    // FIXME - if metadata, don't split nodes
    // FIXME - compressed extents need to be contiguous(?)

    if (length > MAX_COPY)
        length = MAX_COPY;

    // FIXME - avoiding superblock

    auto buf = read_data(f, dst_addr, length);

    // FIXME - don't mix and match char and uint8_t
    write_data(f, src_addr, span((uint8_t*)buf.data(), buf.size()));

    remove_from_remap_tree(f, src_addr, length);
    add_identity_remap(f, src_addr, length);

    flush_transaction(f);

    return src_addr + length;
}

static void process_remaps(fs& f, uint64_t offset, uint64_t length) {
    uint64_t cursor = offset;

    while (true) {
        auto [addr, level] = find_tree_addr(f, btrfs::REMAP_TREE_OBJECTID);
        path p;

        find_item2(f, addr, level, { cursor, btrfs::key_type::REMAP, 0 },
                   false, btrfs::REMAP_TREE_OBJECTID, p);

        auto& h = *(btrfs::header*)p.bufs[0].data();
        auto items = (btrfs::item*)((uint8_t*)&h + sizeof(btrfs::header));

        if (p.slots[0] >= h.nritems)
            return;

        auto& it = items[p.slots[0]];

        if (it.key.objectid >= offset + length)
            return;

        switch (it.key.type) {
            case btrfs::key_type::REMAP: {
                assert(it.size == sizeof(btrfs::remap));

                auto& r = *(btrfs::remap*)((uint8_t*)p.bufs[0].data() + sizeof(btrfs::header) + it.offset);

                cursor = process_remap(f, it.key.objectid, it.key.offset,
                                       r.address);
                break;
            }

            case btrfs::key_type::IDENTITY_REMAP:
                cursor = it.key.objectid + it.key.offset;
                break;

            default:
                throw formatted_error("process_remaps: expected REMAP or IDENTITY_REMAP, found {}",
                                      it.key);
        }
    }
}

static void finish_off_bg(fs& f, uint64_t offset, uint64_t length) {
    vector<pair<uint64_t, uint64_t>> identity_remaps;

    // find identity remaps

    {
        auto [addr, level] = find_tree_addr(f, btrfs::REMAP_TREE_OBJECTID);
        path p;

        find_item2(f, addr, level, { offset, (btrfs::key_type)0, 0}, false,
                   btrfs::REMAP_TREE_OBJECTID, p);

        do {
            auto& h = *(btrfs::header*)p.bufs[0].data();
            auto items = (btrfs::item*)((uint8_t*)&h + sizeof(btrfs::header));

            if (p.slots[0] == h.nritems)
                break;

            auto& k = items[p.slots[0]].key;

            if (k.objectid >= offset + length)
                break;

            if (k.type != btrfs::key_type::IDENTITY_REMAP) {
                throw formatted_error("finish_off_bg: expected IDENTITY_REMAP, found {}",
                                      k);
            }

            identity_remaps.emplace_back(k.objectid, k.offset);

            if (!next_item(f, p, false))
                break;
        } while (true);
    }

    // add free space extents

    uint32_t num_extents = 0;

    {
        uint64_t last_end = offset;

        for (auto [remap_start, remap_length] : identity_remaps) {
            if (remap_start > last_end) {
                insert_item(f, btrfs::FREE_SPACE_TREE_OBJECTID,
                            { last_end, btrfs::key_type::FREE_SPACE_EXTENT, remap_start - last_end }, 0);
                num_extents++;
            }

            last_end = remap_start + remap_length;
        }

        if (last_end < offset + length) {
            insert_item(f, btrfs::FREE_SPACE_TREE_OBJECTID,
                        { last_end, btrfs::key_type::FREE_SPACE_EXTENT, offset + length - last_end }, 0);
            num_extents++;
        }
    }

    // add free space info

    auto sp = insert_item(f, btrfs::FREE_SPACE_TREE_OBJECTID,
                          { offset, btrfs::key_type::FREE_SPACE_INFO, length },
                          sizeof(btrfs::free_space_info));
    auto& fsi = *(btrfs::free_space_info*)sp.data();

    fsi.extent_count = num_extents;
    fsi.flags = 0;

    // remove identity remaps for range

    for (auto [remap_start, remap_length] : identity_remaps) {
        delete_item(f, btrfs::REMAP_TREE_OBJECTID,
                    {remap_start, btrfs::key_type::IDENTITY_REMAP, remap_length});
    }

    // clear REMAPPED flag in chunk

    uint64_t flags;

    {
        btrfs::key key{btrfs::FIRST_CHUNK_TREE_OBJECTID,
                       btrfs::key_type::CHUNK_ITEM, offset};
        auto [found_key, sp] = find_item(f, btrfs::CHUNK_TREE_OBJECTID,
                                         key, true);

        if (found_key != key) {
            throw formatted_error("finish_off_bg: searched for {}, found {}",
                                  key, found_key);
        }

        assert(sp.size() >= offsetof(btrfs::chunk, stripe));

        auto& c = *(btrfs::chunk*)sp.data();

        c.type &= ~btrfs::BLOCK_GROUP_REMAPPED;

        flags = c.type;
    }

    // clear REMAPPED flag in BG

    update_block_group_flags(f, offset, length, flags);

    flush_transaction(f);
}

static void demap_bg(fs& f, uint64_t offset) {
    print("FIXME - demap_bg {:x}\n", offset); // FIXME

    auto& [_, c] = find_chunk(f, offset);

    if (c.c.num_stripes == 0)
        allocate_stripe(f, offset, c.c.length);

    // FIXME - if metadata BG, might be carving out remaps on transaction commit

    process_remaps(f, offset, c.c.length);

    finish_off_bg(f, offset, c.c.length);
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

static void shorten_block_group_items(fs& f) {
    auto [addr, level] = find_tree_addr(f, btrfs::BLOCK_GROUP_TREE_OBJECTID);
    path p;

    find_item2(f, addr, level, { 0, (btrfs::key_type)0, 0}, true,
               btrfs::BLOCK_GROUP_TREE_OBJECTID, p);

    do {
        auto& h = *(btrfs::header*)p.bufs[0].data();
        auto items = (btrfs::item*)((uint8_t*)&h + sizeof(btrfs::header));

        if (p.slots[0] == h.nritems)
            break;

        auto& it = items[p.slots[0]];

        if (it.key.type != btrfs::key_type::BLOCK_GROUP_ITEM) {
            throw formatted_error("shorten_block_group_items: found {}, expected BLOCK_GROUP_ITEM",
                                  it.key);
        }

        assert(it.size == sizeof(btrfs::block_group_item_v2));

        shorten_item(f, p, sizeof(btrfs::block_group_item));

        if (!next_item(f, p, false))
            break;
    } while (true);
}

static btrfs::uuid get_chunk_tree_uuid(fs& f) {
    auto [addr, level] = find_tree_addr(f, btrfs::ROOT_TREE_OBJECTID);
    path p;

    find_item2(f, addr, level, {0, (btrfs::key_type)0, 0}, false,
               btrfs::ROOT_TREE_OBJECTID, p);

    const auto& h = *(btrfs::header*)p.bufs[0].data();

    return h.chunk_tree_uuid;
}

static void add_tree(fs& f, uint64_t num) {
    auto& sb = f.dev.sb;

    // add empty tree node

    auto addr = allocate_metadata(f, num);

    auto [it, _] = f.tree_cache.emplace(addr, "");

    auto& new_tree = it->second;

    new_tree.resize(sb.nodesize); // zero-initializes

    auto& h = *(btrfs::header*)new_tree.data();

    h.fsid = sb.fsid;
    h.bytenr = addr;
    h.flags = btrfs::HEADER_FLAG_MIXED_BACKREF;
    h.chunk_tree_uuid = get_chunk_tree_uuid(f);
    h.generation = sb.generation + 1;
    h.owner = num;
    h.nritems = 0;
    h.level = 0;

    f.ref_changes.emplace(addr, ref_change{h.owner, 1});

    // add new root item

    btrfs::key key{h.owner, btrfs::key_type::ROOT_ITEM, 0};

    auto sp = insert_item(f, btrfs::ROOT_TREE_OBJECTID, key,
                          sizeof(btrfs::root_item));

    auto& ri = *(btrfs::root_item*)sp.data();

    memset(&ri, 0, sizeof(ri));

    ri.inode.flags = btrfs::INODE_ROOT_ITEM_INIT;
    ri.generation = sb.generation + 1;

    ri.root_dirid = btrfs::FIRST_FREE_OBJECTID;
    ri.bytenr = h.bytenr;
    ri.bytes_used = sb.nodesize;
    ri.refs = 1;
    ri.generation_v2 = ri.generation;
}

static void add_data_reloc_tree(fs& f) {
    auto& sb = f.dev.sb;

    static const uint32_t S_IFDIR = 040000; // FIXME - stick this somewhere better

    static const char dotdot[] = "..";

    add_tree(f, btrfs::DATA_RELOC_TREE_OBJECTID);

    {
        auto sp = insert_item(f, btrfs::DATA_RELOC_TREE_OBJECTID,
                              { btrfs::FIRST_FREE_OBJECTID, btrfs::key_type::INODE_ITEM, 0 },
                              sizeof(btrfs::inode_item));
        auto& ii = *(btrfs::inode_item*)sp.data();

        memset(&ii, 0, sizeof(ii));

        ii.generation = sb.generation + 1;
        ii.nbytes = sb.nodesize;
        ii.nlink = 1;
        ii.mode = S_IFDIR | 0755;
        // FIXME - set atime, ctime, mtime, and otime to now(?)
    }

    {
        auto sp = insert_item(f, btrfs::DATA_RELOC_TREE_OBJECTID,
                              { btrfs::FIRST_FREE_OBJECTID, btrfs::key_type::INODE_REF, btrfs::FIRST_FREE_OBJECTID },
                              sizeof(btrfs::inode_ref) + sizeof(dotdot) - 1);

        auto& ir = *(btrfs::inode_ref*)sp.data();

        ir.index = 0;
        ir.name_len = sizeof(dotdot) - 1;
        memcpy((char*)&ir + sizeof(btrfs::inode_ref), dotdot, ir.name_len);
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

    // FIXME - double-check that FST and BGT flags are set

    if (sb.num_devices != 1)
        throw runtime_error("multi-device support not yet implemented"); // FIXME

    load_sys_chunks(f);
    load_chunks(f);

    // FIXME - die if transaction log there?

    load_fst(f);

    for (const auto& c : f.chunks) {
        if (c.second.c.type & btrfs::BLOCK_GROUP_REMAPPED)
            demap_bg(f, c.first);
    }

    // check remap tree is now empty

    auto [remap_tree_addr, remap_tree_level] = find_tree_addr(f, btrfs::REMAP_TREE_OBJECTID);

    {
        path p;

        if (remap_tree_level != 0) {
            throw formatted_error("remap tree level was {}, expected 0",
                                  remap_tree_level);
        }

        find_item2(f, remap_tree_addr, remap_tree_level,
                   {0, (btrfs::key_type)0, 0}, false, btrfs::REMAP_TREE_OBJECTID,
                   p);

        const auto& h = *(btrfs::header*)p.bufs[0].data();

        if (h.nritems != 0)
            throw runtime_error("remap tree was not empty");
    }

    // remove remap tree

    delete_item(f, btrfs::ROOT_TREE_OBJECTID,
                {btrfs::REMAP_TREE_OBJECTID, btrfs::key_type::ROOT_ITEM, 0});
    f.ref_changes.emplace(remap_tree_addr,
                          ref_change{btrfs::REMAP_TREE_OBJECTID, -1});

    // remove all REMAP chunks

    for (const auto& c : f.chunks) {
        if (c.second.c.type & btrfs::BLOCK_GROUP_REMAP)
            f.remove_chunks.emplace(c.first);
    }

    add_data_reloc_tree(f);

    shorten_block_group_items(f);

    f.dev.sb.incompat_flags &= ~btrfs::FEATURE_INCOMPAT_REMAP_TREE;

    flush_transaction(f);
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
