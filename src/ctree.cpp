module;

#include <span>
#include <optional>
#include <filesystem>
#include <fstream>
#include <map>
#include <set>
#include <functional>
#include <stdint.h>
#include <assert.h>
#include <string.h>

export module ctree;

import cxxbtrfs;
import formatted_error;

using namespace std;

export const size_t MAX_STRIPES = 16;

export struct device {
    device(const filesystem::path& fn) : f(fn) { }

    fstream f;
    btrfs::super_block sb;
};

export struct chunk : btrfs::chunk {
    btrfs::stripe next_stripes[MAX_STRIPES - 1];
};

export struct chunk_info {
    chunk c;
    vector<pair<uint64_t, uint64_t>> fst;
};

export struct ref_change {
    uint64_t tree;
    int64_t refcount_change;
};

export struct fs {
    fs(const filesystem::path& fn) : dev(fn) { }

    device dev;
    map<uint64_t, chunk_info> chunks;
    map<uint64_t, string> tree_cache; // FIXME - basic_string<uint8_t> or vector<uint8_t> instead?
    map<uint64_t, ref_change> ref_changes;
    set<uint64_t> remove_chunks;
};

export struct path {
    array<span<uint8_t>, btrfs::MAX_LEVEL> bufs;
    array<uint32_t, btrfs::MAX_LEVEL> slots;
};

export pair<btrfs::key, span<uint8_t>> find_item(fs& f, uint64_t tree,
                                                 const btrfs::key& key, bool cow);
export void read_metadata(fs& f, uint64_t addr, uint8_t level);

export pair<uint64_t, uint8_t> find_tree_addr(fs& f, uint64_t tree) {
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

export void find_item2(fs& f, uint64_t addr, uint8_t level, const btrfs::key& key,
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

export span<uint8_t> item_span(path& p) {
    const auto& h = *(btrfs::header*)p.bufs[0].data();
    auto items = (btrfs::item*)((uint8_t*)&h + sizeof(btrfs::header));
    auto& it = items[p.slots[0]];

    return span((uint8_t*)p.bufs[0].data() + sizeof(btrfs::header) + it.offset, it.size);
}

export pair<btrfs::key, span<uint8_t>> find_item(fs& f, uint64_t tree,
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

export const pair<uint64_t, const chunk_info&> find_chunk(fs& f, uint64_t address) {
    auto it = f.chunks.upper_bound(address);

    if (it == f.chunks.begin())
        throw formatted_error("could not find address {:x} in chunks", address);

    const auto& p = *prev(it);

    if (p.first + p.second.c.length <= address)
        throw formatted_error("could not find address {:x} in chunks", address);

    return p;
}

export string read_data(fs& f, uint64_t addr, uint64_t size) {
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

static uint32_t path_nritems(const path& p, uint8_t level) {
    const auto& h = *(btrfs::header*)p.bufs[level].data();

    return h.nritems;
}

export bool prev_item(fs& f, path& p, bool cow) {
    if (p.slots[0] != 0) {
        if (cow) {
            for (int8_t k = btrfs::MAX_LEVEL - 1; k >= 0; k--) {
                if (p.bufs[k].empty())
                    continue;

                cow_tree(f, p, k);
            }
        }

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
            auto& it = items[p.slots[j]];

            assert(h.level == j);

            read_metadata(f, it.blockptr, h.level - 1);

            p.bufs[h.level - 1] = span((uint8_t*)f.tree_cache.find(it.blockptr)->second.data(),
                                       sb.nodesize);

            if (cow) {
                for (int8_t k = btrfs::MAX_LEVEL - 1; k >= h.level - 1; k--) {
                    if (p.bufs[k].empty())
                        continue;

                    cow_tree(f, p, k);
                }
            }

            p.slots[j - 1] = path_nritems(p, j - 1) - 1;
        }

        return true;
    }

    p = orig_p;

    return false;
}

export bool next_item(fs& f, path& p, bool cow) {
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

export uint64_t translate_remap(fs& f, uint64_t addr, uint64_t& left_in_remap) {
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

export void read_metadata(fs& f, uint64_t addr, uint8_t level) {
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

export void walk_tree2(fs& f, uint64_t addr, uint8_t level,
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

export span<uint8_t> insert_item(fs& f, uint64_t tree, const btrfs::key& key,
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

static btrfs::uuid get_chunk_tree_uuid(fs& f) {
    auto [addr, level] = find_tree_addr(f, btrfs::ROOT_TREE_OBJECTID);
    path p;

    find_item2(f, addr, level, {0, (btrfs::key_type)0, 0}, false,
               btrfs::ROOT_TREE_OBJECTID, p);

    const auto& h = *(btrfs::header*)p.bufs[0].data();

    return h.chunk_tree_uuid;
}

export void add_tree(fs& f, uint64_t num) {
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

export void delete_item2(fs& f, path& p) {
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

export void delete_item(fs& f, uint64_t tree, const btrfs::key& key) {
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

export void extend_item(fs& f, path& p, uint32_t size) {
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

export void shorten_item(fs& f, path& p, uint32_t size) {
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

export void change_key(path& p, const btrfs::key& key) {
    const auto& h = *(btrfs::header*)p.bufs[0].data();
    auto items = (btrfs::item*)((uint8_t*)&h + sizeof(btrfs::header));
    auto& it = items[p.slots[0]];

    it.key = key;

    // FIXME - if first item, change key of parents (recursively)
}
