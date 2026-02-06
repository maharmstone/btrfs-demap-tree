module;

#include <span>
#include <optional>
#include <filesystem>
#include <map>
#include <set>
#include <functional>
#include <stdint.h>
#include <assert.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <linux/fs.h>

export module ctree;

import cxxbtrfs;
import formatted_error;

using namespace std;

static const uint64_t SZ_1G = 0x40000000;

export const size_t MAX_STRIPES = 16;

export struct device {
    device(const filesystem::path& fn) {
        struct stat st;

        if (auto ret = open(fn.string().c_str(), O_RDWR); ret == -1)
            throw formatted_error("open failed (errno {})", errno);
        else
            fd = ret;

        if (fstat(fd, &st) == -1)
            throw formatted_error("fstat failed (errno {})", errno);

        if (S_ISBLK(st.st_mode)) {
            if (ioctl(fd, BLKGETSIZE64, &size))
                throw formatted_error("BLKGETSIZE64 failed (errno {})", errno);
        } else
            size = st.st_size;

        if (size == 0)
            throw runtime_error("file size is 0");

        if (size < btrfs::superblock_addrs[0] + sizeof(btrfs::super_block))
            throw runtime_error("file was too small to have superblock");

        for (size_t i = 0; i < btrfs::superblock_addrs.size(); i++) {
            if (btrfs::superblock_addrs[i] + sizeof(btrfs::super_block) > size)
                break;

            auto ret = mmap(nullptr, sizeof(btrfs::super_block),
                            PROT_READ | PROT_WRITE, MAP_SHARED, fd,
                            btrfs::superblock_addrs[i]);
            if (ret == MAP_FAILED)
                throw formatted_error("mmap failed (errno {})", errno);

            mmap_sb[i] = (btrfs::super_block*)ret;
        }
    }

    ~device() {
        if (fd != 0)
            close(fd);

        for (auto m : mmap_sb) {
            if (!m)
                break;

            munmap(m, sizeof(btrfs::super_block));
        }
    }

    int fd = 0;
    btrfs::super_block sb;
    uint64_t size;
    array<btrfs::super_block*, btrfs::superblock_addrs.size()> mmap_sb;
};

export struct chunk : btrfs::chunk {
    btrfs::stripe next_stripes[MAX_STRIPES - 1];
};

export struct chunk_info {
    ~chunk_info() {
        for (auto m : maps) {
            munmap(m, c.length);
        }
    }

    chunk c;
    vector<pair<uint64_t, uint64_t>> fst;
    bool fst_using_bitmaps = false;
    array<void*, MAX_STRIPES> maps{};
    set<uint64_t> metadata_checked;
};

export struct ref_change {
    uint64_t tree;
    int64_t refcount_change;
};

export struct fs {
    fs(const filesystem::path& fn) : dev(fn) { }

    device dev;
    map<uint64_t, chunk_info> chunks;
    map<uint64_t, ref_change> ref_changes;
    set<uint64_t> changed_chunks;
    set<uint64_t> remove_chunks;
    set<uint64_t> written_chunks;
};

export struct path {
    array<uint8_t*, btrfs::MAX_LEVEL> bufs{};
    array<uint32_t, btrfs::MAX_LEVEL> slots;
};

export pair<btrfs::key, span<uint8_t>> find_item(fs& f, uint64_t tree,
                                                 const btrfs::key& key, bool cow);
export void read_metadata(fs& f, uint64_t addr, uint64_t gen, uint8_t level);
export const pair<uint64_t, chunk_info&> find_chunk(fs& f, uint64_t address);
export void walk_tree(fs& f, uint64_t tree, optional<btrfs::key> from,
                      const function<bool(const btrfs::key&, span<const uint8_t>)>& func);
export span<uint8_t> insert_item(fs& f, uint64_t tree, const btrfs::key& key,
                                 uint32_t size);

static void insert_internal_node(fs& f, path& p, uint64_t tree, uint8_t level,
                                 const btrfs::key& k, uint64_t address);
static uint64_t find_next_chunk_offset(fs& f);

export tuple<uint64_t, uint64_t, uint8_t> find_tree_addr(fs& f, uint64_t tree) {
    auto& sb = f.dev.sb;

    if (tree == btrfs::CHUNK_TREE_OBJECTID)
        return { sb.chunk_root, sb.chunk_root_generation, sb.chunk_root_level };
    else if (tree == btrfs::ROOT_TREE_OBJECTID)
        return { sb.root, sb.generation, sb.root_level };

    auto [key, data] = find_item(f, btrfs::ROOT_TREE_OBJECTID, { tree, btrfs::key_type::ROOT_ITEM, 0 }, false);

    if (key.objectid != tree || key.type != btrfs::key_type::ROOT_ITEM)
        throw formatted_error("find_tree_addr: tree {:x} not found in root\n", tree);

    if (data.size() < sizeof(btrfs::root_item)) {
        throw formatted_error("find_tree_addr: ROOT_ITEM for tree {:x} was {} bytes, expected {}\n",
                              tree, data.size(), sizeof(btrfs::root_item));
    }

    const auto& ri = *(btrfs::root_item*)data.data();

    return { ri.bytenr, ri.generation, ri.level };
}

export void insert_dev_extent(fs& f, uint64_t devid, uint64_t phys,
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

export uint64_t find_hole_for_chunk(fs& f, uint64_t size) {
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

export void update_dev_item_bytes_used(fs& f, uint64_t devid, int64_t delta) {
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

static void allocate_metadata_chunk(fs& f) {
    auto& sb = f.dev.sb;
    uint64_t stripe_size, type;
    uint64_t stripes_needed;
    array<uint64_t, MAX_STRIPES> offs;
    uint64_t chunk_offset;

    // FIXME - chunk tree (SYSTEM, goes in superblock
    // FIXME - remap tree (METADATA_REMAP)
    type = btrfs::BLOCK_GROUP_METADATA;

    // FIXME - determine how big a chunk we want
    stripe_size = SZ_1G;

    // FIXME - determine what RAID type we want (look at what we've got already)
    type |= btrfs::BLOCK_GROUP_DUP;
    stripes_needed = 2;

    chunk_offset = find_next_chunk_offset(f);

    for (uint16_t i = 0; i < stripes_needed; i++) {
        offs[i] = find_hole_for_chunk(f, stripe_size);

        insert_dev_extent(f, f.dev.sb.dev_item.devid, offs[i], chunk_offset,
                          stripe_size);
    }

    chunk_info ci;

    ci.fst.emplace_back(chunk_offset, stripe_size);
    // FIXME - cut out superblocks
    // FIXME - mmap stripes


    // add CHUNK_ITEM

    ci.c.length = stripe_size;
    ci.c.owner = btrfs::EXTENT_TREE_OBJECTID;
    ci.c.stripe_len = 0x10000;
    ci.c.type = type;
    ci.c.io_align = 0x10000;
    ci.c.io_width = 0x10000;
    ci.c.sector_size = sb.sectorsize;
    ci.c.num_stripes = stripes_needed;
    ci.c.sub_stripes = 1;

    for (uint16_t i = 0; i < stripes_needed; i++) {
        ci.c.stripe[i].devid = f.dev.sb.dev_item.devid;
        ci.c.stripe[i].offset = offs[i];
        ci.c.stripe[i].dev_uuid = f.dev.sb.dev_item.uuid;
    }

    {
        btrfs::key key{ btrfs::FIRST_CHUNK_TREE_OBJECTID,
                        btrfs::key_type::CHUNK_ITEM, chunk_offset };
        size_t item_len = offsetof(btrfs::chunk, stripe) + (sizeof(btrfs::stripe) * ci.c.num_stripes);
        auto sp = insert_item(f, btrfs::CHUNK_TREE_OBJECTID, key, item_len);

        memcpy(sp.data(), &ci.c, item_len);
    }

    // add BLOCK_GROUP_ITEM

    btrfs::block_group_item_v2 bgi;

    bgi.used = 0;
    bgi.chunk_objectid = btrfs::FIRST_CHUNK_TREE_OBJECTID;
    bgi.flags = type;
    bgi.remap_bytes = 0;
    bgi.identity_remap_count = 0;

    btrfs::key key{ chunk_offset, btrfs::key_type::BLOCK_GROUP_ITEM,
                    ci.c.length };

    if (sb.incompat_flags & btrfs::FEATURE_INCOMPAT_REMAP_TREE) {
        auto sp = insert_item(f, btrfs::BLOCK_GROUP_TREE_OBJECTID, key,
                              sizeof(btrfs::block_group_item_v2));
        memcpy(sp.data(), &bgi, sizeof(btrfs::block_group_item_v2));
    } else {
        uint64_t bgt;

        if (sb.compat_ro_flags & btrfs::FEATURE_COMPAT_RO_BLOCK_GROUP_TREE)
            bgt = btrfs::BLOCK_GROUP_TREE_OBJECTID;
        else
            bgt = btrfs::EXTENT_TREE_OBJECTID;

        auto sp = insert_item(f, bgt, key, sizeof(btrfs::block_group_item));
        memcpy(sp.data(), &bgi, sizeof(btrfs::block_group_item));
    }

    // add FREE_SPACE_INFO (FIXME - old-style free space cache?)

    {
        btrfs::free_space_info fsi;

        fsi.extent_count = 1;
        fsi.flags = 0;

        auto sp = insert_item(f, btrfs::FREE_SPACE_TREE_OBJECTID,
                            { chunk_offset, btrfs::key_type::FREE_SPACE_INFO, stripe_size },
                            sizeof(btrfs::free_space_info));
        memcpy(sp.data(), &fsi, sizeof(btrfs::free_space_info));
    }

    // add FREE_SPACE_EXTENT

    insert_item(f, btrfs::FREE_SPACE_TREE_OBJECTID,
                { chunk_offset, btrfs::key_type::FREE_SPACE_EXTENT, stripe_size },
                0);

    // update DEV_ITEM's bytes_used (and in superblock)

    update_dev_item_bytes_used(f, f.dev.sb.dev_item.devid,
                               stripes_needed * stripe_size);

    // FIXME - insert into chunks list

    // FIXME - return reference to chunk_info in chunks list
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

    auto try_alloc = [&sb](chunk_info& c) -> optional<uint64_t> {
        // allocate from FST

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

        return nullopt;
    };

    for (auto& [_, c] : f.chunks) {
        if (c.c.type & btrfs::BLOCK_GROUP_REMAPPED)
            continue;

        if (!(c.c.type & type))
            continue;

        if (auto ret = try_alloc(c); ret.has_value())
            return *ret;
    }

    // FIXME - if no space, allocate new chunk

    throw runtime_error("could not find space to allocate new metadata");
}

static void cow_tree(fs& f, path& p, uint8_t level) {
    auto& sb = f.dev.sb;
    const auto& orig_h = *(btrfs::header*)p.bufs[level];

    if (!(orig_h.flags & btrfs::HEADER_FLAG_WRITTEN))
        return;

    auto new_addr = allocate_metadata(f, orig_h.owner);

    auto& [chunk_start, c] = find_chunk(f, new_addr);
    auto& h = *(btrfs::header*)((uint8_t*)c.maps[0] + new_addr - chunk_start);

    memcpy(&h, p.bufs[level], sb.nodesize);

    c.metadata_checked.insert(new_addr);

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

    if (p.bufs[h.level + 1]) { // FIXME - and level not maxed out
        auto items = (btrfs::key_ptr*)((uint8_t*)p.bufs[h.level + 1] + sizeof(btrfs::header));
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

    p.bufs[level] = (uint8_t*)c.maps[0] + new_addr - chunk_start;
}

export void find_item2(fs& f, uint64_t addr, uint64_t gen, uint8_t level,
                       const btrfs::key& key, bool cow, uint64_t tree, path& p) {
    // FIXME - separate COW and no-COW versions of this, so we can use
    //         const properly?

    read_metadata(f, addr, gen, level);

    auto& [chunk_start, c] = find_chunk(f, addr);
    p.bufs[level] = (uint8_t*)c.maps[0] + addr - chunk_start;

    if (cow)
        cow_tree(f, p, level);

    const auto& h = *(btrfs::header*)p.bufs[level];

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

        if (h.nritems > 0 && key < items[0].key) {
            p.slots[h.level] = 0;
            find_item2(f, items[0].blockptr, items[0].generation,
                       level - 1, key, cow, tree, p);
            return;
        }

        for (size_t i = 0; i < h.nritems - 1; i++) {
            if (key >= items[i].key && key < items[i + 1].key) {
                p.slots[h.level] = i;
                find_item2(f, items[i].blockptr, items[i].generation,
                           level - 1, key, cow, tree, p);
                return;
            }
        }

        p.slots[h.level] = h.nritems - 1;
        find_item2(f, items[h.nritems - 1].blockptr, items[h.nritems - 1].generation,
                   level - 1, key, cow, tree, p);
    }
}

export span<uint8_t> item_span(path& p) {
    const auto& h = *(btrfs::header*)p.bufs[0];
    auto items = (btrfs::item*)((uint8_t*)&h + sizeof(btrfs::header));
    auto& it = items[p.slots[0]];

    return span((uint8_t*)p.bufs[0] + sizeof(btrfs::header) + it.offset, it.size);
}

export pair<btrfs::key, span<uint8_t>> find_item(fs& f, uint64_t tree,
                                                 const btrfs::key& key, bool cow) {
    auto [addr, gen, level] = find_tree_addr(f, tree);
    path p;

    find_item2(f, addr, gen, level, key, cow, tree, p);

    const auto& h = *(btrfs::header*)p.bufs[0];

    if (p.slots[0] >= h.nritems)
        return make_pair((btrfs::key){ 0xffffffffffffffff, (enum btrfs::key_type)0xff, 0xffffffffffffffff }, span<uint8_t>());

    auto items = (btrfs::item*)((uint8_t*)&h + sizeof(btrfs::header));
    auto& it = items[p.slots[0]];

    return { it.key, item_span(p) };
}

export const pair<uint64_t, chunk_info&> find_chunk(fs& f, uint64_t address) {
    auto it = f.chunks.upper_bound(address);

    if (it == f.chunks.begin())
        throw formatted_error("could not find address {:x} in chunks", address);

    auto& p = *prev(it);

    if (p.first + p.second.c.length <= address)
        throw formatted_error("could not find address {:x} in chunks", address);

    return p;
}

export uint32_t path_nritems(const path& p, uint8_t level) {
    const auto& h = *(btrfs::header*)p.bufs[level];

    return h.nritems;
}

export btrfs::key path_key(const path& p, uint8_t level) {
    const auto& h = *(btrfs::header*)p.bufs[level];

    assert(p.bufs[level]);
    assert(p.slots[level] < h.nritems);

    if (level == 0) {
        auto items = (btrfs::item*)((uint8_t*)&h + sizeof(btrfs::header));

        return items[p.slots[level]].key;
    } else {
        auto items = (btrfs::key_ptr*)((uint8_t*)&h + sizeof(btrfs::header));

        return items[p.slots[level]].key;
    }
}

export bool prev_item(fs& f, path& p, bool cow) {
    if (p.slots[0] != 0) {
        if (cow) {
            for (int8_t k = btrfs::MAX_LEVEL - 1; k >= 0; k--) {
                if (!p.bufs[k])
                    continue;

                cow_tree(f, p, k);
            }
        }

        p.slots[0]--;
        return true;
    }

    auto orig_p = p;

    for (uint8_t i = 1; i < btrfs::MAX_LEVEL; i++) {
        if (!p.bufs[i])
            break;

        if (p.slots[i] == 0)
            continue;

        p.slots[i]--;

        for (auto j = (int8_t)i; j > 0; j--) {
            const auto& h = *(btrfs::header*)p.bufs[j];
            auto items = span((btrfs::key_ptr*)((uint8_t*)&h + sizeof(btrfs::header)), h.nritems);
            auto& it = items[p.slots[j]];

            assert(h.level == j);

            read_metadata(f, it.blockptr, it.generation, h.level - 1);

            auto& [chunk_start, c] = find_chunk(f, it.blockptr);
            p.bufs[h.level - 1] = (uint8_t*)c.maps[0] + it.blockptr - chunk_start;

            if (cow) {
                for (int8_t k = btrfs::MAX_LEVEL - 1; k >= h.level - 1; k--) {
                    if (!p.bufs[k])
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

export bool next_leaf(fs& f, path& p, bool cow) {
    auto orig_p = p;

    for (uint8_t i = 1; i < btrfs::MAX_LEVEL; i++) {
        if (!p.bufs[i])
            break;

        if (p.slots[i] == path_nritems(p, i) - 1)
            continue;

        p.slots[i]++;

        for (auto j = (int8_t)i; j > 0; j--) {
            const auto& h = *(btrfs::header*)p.bufs[j];
            auto items = span((btrfs::key_ptr*)((uint8_t*)&h + sizeof(btrfs::header)), h.nritems);
            auto& it = items[p.slots[j]];

            assert(h.level == j);

            read_metadata(f, it.blockptr, it.generation, h.level - 1);

            auto& [chunk_start, c] = find_chunk(f, it.blockptr);
            p.bufs[h.level - 1] = (uint8_t*)c.maps[0] + it.blockptr - chunk_start;

            if (cow) {
                for (int8_t k = btrfs::MAX_LEVEL - 1; k >= 0; k--) {
                    if (!p.bufs[k])
                        continue;

                    cow_tree(f, p, k);
                }
            }

            p.slots[j - 1] = 0;
        }

        return true;
    }

    p = orig_p;

    return false;
}

export bool next_item(fs& f, path& p, bool cow) {
    if (p.slots[0] != path_nritems(p, 0) - 1) {
        if (cow) {
            for (int8_t k = btrfs::MAX_LEVEL - 1; k >= 0; k--) {
                if (!p.bufs[k])
                    continue;

                cow_tree(f, p, k);
            }
        }

        p.slots[0]++;
        return true;
    }

    return next_leaf(f, p, cow);
}

export uint64_t translate_remap(fs& f, uint64_t addr, uint64_t& left_in_remap) {
    bool moved_back = false;
    btrfs::key key{addr, btrfs::key_type::IDENTITY_REMAP, 0};

    auto [remap_addr, remap_gen, remap_level] = find_tree_addr(f, btrfs::REMAP_TREE_OBJECTID);
    path p;

    find_item2(f, remap_addr, remap_gen, remap_level, key, false,
               btrfs::REMAP_TREE_OBJECTID, p);

    {
        const auto& h = *(btrfs::header*)p.bufs[0];

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

    const auto& h = *(btrfs::header*)p.bufs[0];
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

export void read_metadata(fs& f, uint64_t addr, uint64_t gen, uint8_t level) {
    auto& sb = f.dev.sb;
    auto& [chunk_start, c] = find_chunk(f, addr);

    if (c.metadata_checked.contains(addr))
        return;

    uint8_t* ptr;

    if (c.c.type & btrfs::BLOCK_GROUP_REMAPPED) {
        uint64_t left_in_remap;

        auto read_addr = translate_remap(f, addr, left_in_remap);
        assert(left_in_remap >= f.dev.sb.nodesize);

        auto& [chunk_start2, c2] = find_chunk(f, read_addr);
        ptr = (uint8_t*)c2.maps[0] + read_addr - chunk_start2;
    } else
        ptr = (uint8_t*)c.maps[0] + addr - chunk_start;

    const auto& h = *(btrfs::header*)ptr;

    // FIXME - use other chunk stripe if verification fails (and write back good version)

    // FIXME - print values
    if (!check_tree_csum(h, sb))
        throw formatted_error("{:x}: csum mismatch", addr);

    if (h.bytenr != addr)
        throw formatted_error("{:x}: address mismatch: expected {:x}, got {:x}", addr, addr, h.bytenr);

    if (h.level != level)
        throw formatted_error("{:x}: level mismatch: expected {:x}, got {:x}", addr, level, h.level);

    if (h.generation != gen)
        throw formatted_error("{:x}: generation mismatch: expected {:x}, got {:x}", addr, gen, h.generation);

    c.metadata_checked.insert(addr);
}

export void walk_tree2(fs& f, uint64_t addr, uint64_t gen, uint8_t level,
                       const function<bool(const btrfs::key&, span<const uint8_t>)>& func,
                       optional<btrfs::key> from) {
    read_metadata(f, addr, gen, level);

    auto& [chunk_start, c] = find_chunk(f, addr);

    const auto& h = *(btrfs::header*)((uint8_t*)c.maps[0] + addr - chunk_start);

    if (h.level == 0) {
        auto items = span((btrfs::item*)((uint8_t*)&h + sizeof(btrfs::header)), h.nritems);

        for (const auto& it : items) {
            if (from.has_value() && it.key < *from)
                continue;

            auto item = span((uint8_t*)&h + sizeof(btrfs::header) + it.offset, it.size);

            if (!func(it.key, item))
                break;
        }
    } else {
        auto items = span((btrfs::key_ptr*)((uint8_t*)&h + sizeof(btrfs::header)), h.nritems);

        for (size_t i = 0; i < items.size(); i++) {
            const auto& it = items[i];

            if (from.has_value() && i < items.size() - 1 && *from < items[i + 1].key)
                continue;

            walk_tree2(f, it.blockptr, it.generation, level - 1, func, from);
        }
    }
}

export void walk_tree(fs& f, uint64_t tree, optional<btrfs::key> from,
                      const function<bool(const btrfs::key&, span<const uint8_t>)>& func) {
    auto [addr, gen, level] = find_tree_addr(f, tree);

    walk_tree2(f, addr, gen, level, func, from);
}

static unsigned int find_midpoint(const btrfs::header& th, size_t total,
                                  size_t& sum) {
    auto* items = (btrfs::item*)((uint8_t*)&th + sizeof(btrfs::header));

    sum = 0;

    for (unsigned int i = 0; i < th.nritems; i++) {
        if (sum + sizeof(btrfs::item) + items[i].size > total / 2)
            return i;

        sum += sizeof(btrfs::item) + items[i].size;
    }

    return th.nritems - 1;
}

static void add_new_level(fs& f, path& p, uint64_t tree, uint8_t level) {
    auto& sb = f.dev.sb;
    btrfs::key first_key;

    auto new_addr = allocate_metadata(f, tree);
    auto& [chunk_start, c] = find_chunk(f, new_addr);

    auto& th2 = *(btrfs::header*)((uint8_t*)c.maps[0] + new_addr - chunk_start);
    memcpy(&th2, p.bufs[level - 1], sizeof(btrfs::header));
    memset((uint8_t*)&th2 + sizeof(btrfs::header), 0,
           sb.nodesize - sizeof(btrfs::header));

    c.metadata_checked.insert(new_addr);

    auto& th = *(btrfs::header*)p.bufs[level - 1];

    if (level == 1) {
        auto* items = (btrfs::item*)((uint8_t*)&th + sizeof(btrfs::header));

        first_key = items[0].key;
    } else {
        auto* items = (btrfs::key_ptr*)((uint8_t*)&th + sizeof(btrfs::header));

        first_key = items[0].key;
    }

    th2.bytenr = new_addr;
    th2.flags &= ~btrfs::HEADER_FLAG_WRITTEN;
    th2.level = level;
    th2.nritems = 1;

    f.ref_changes.emplace(new_addr, ref_change{th2.owner, 1});

    auto* items2 = (btrfs::key_ptr*)((uint8_t*)&th2 + sizeof(btrfs::header));

    items2[0].key = first_key;
    items2[0].blockptr = th.bytenr;
    items2[0].generation = sb.generation + 1;

    memset(&items2[1], 0, sb.nodesize - sizeof(btrfs::header) - sizeof(btrfs::key_ptr));

    p.bufs[level] = (uint8_t*)&th2;
    p.slots[level] = 0;

    if (th2.owner == btrfs::CHUNK_TREE_OBJECTID) {
        sb.chunk_root = th2.bytenr;
        sb.chunk_root_generation = sb.generation + 1;
        sb.chunk_root_level = level;
    } else if (th2.owner == btrfs::ROOT_TREE_OBJECTID) {
        sb.root = th2.bytenr;
        sb.root_level = level;
    } else {
        btrfs::key key{th2.owner, btrfs::key_type::ROOT_ITEM, 0};

        auto [found_key, sp] = find_item(f, btrfs::ROOT_TREE_OBJECTID,
                                         key, true);

        if (key.objectid != found_key.objectid || key.type != found_key.type)
            throw formatted_error("could not find item {} in root tree", key);

        if (sp.size() < sizeof(btrfs::root_item)) {
            throw formatted_error("{} in root tree was {} bytes, expected {}\n",
                                  found_key, sp.size(), sizeof(btrfs::root_item));
        }

        auto& ri = reinterpret_cast<btrfs::root_item&>(*sp.data());

        ri.bytenr = th2.bytenr;
        ri.generation = sb.generation + 1;
        ri.generation_v2 = ri.generation;
        ri.level = level;

        if (th2.owner == btrfs::REMAP_TREE_OBJECTID) {
            sb.remap_root = th2.bytenr;
            sb.remap_root_generation = sb.generation + 1;
            sb.remap_root_level = level;
        }
    }
}

static void split_internal_tree(fs& f, path& p, uint64_t tree, uint8_t level) {
    auto& sb = f.dev.sb;
    auto& th = *(btrfs::header*)p.bufs[level];
    unsigned int split_point = th.nritems / 2;

    assert(level < btrfs::MAX_LEVEL - 2);

    auto new_addr = allocate_metadata(f, tree);
    auto& [chunk_start, c] = find_chunk(f, new_addr);

    auto& th2 = *(btrfs::header*)((uint8_t*)c.maps[0] + new_addr - chunk_start);

    memcpy(&th2, &th, sizeof(btrfs::header));
    memset((uint8_t*)&th2 + sizeof(btrfs::header), 0,
           sb.nodesize - sizeof(btrfs::header));

    c.metadata_checked.insert(new_addr);

    th2.bytenr = new_addr;
    th2.flags &= ~btrfs::HEADER_FLAG_WRITTEN;
    th2.nritems = th.nritems - split_point;

    auto* items = (btrfs::key_ptr*)((uint8_t*)&th + sizeof(btrfs::header));
    auto* items2 = (btrfs::key_ptr*)((uint8_t*)&th2 + sizeof(btrfs::header));

    memcpy(items2, &items[split_point], th2.nritems * sizeof(btrfs::key_ptr));
    th.nritems = split_point;

    f.ref_changes.emplace(new_addr, ref_change{th2.owner, 1});

    if (!p.bufs[level + 1])
        add_new_level(f, p, tree, level + 1);

    p.slots[level + 1]++;

    insert_internal_node(f, p, tree, level + 1, items2[0].key, new_addr);

    if (p.slots[level] < split_point)
        p.slots[level + 1]--;
    else {
        p.slots[level] -= split_point;
        p.bufs[level] = (uint8_t*)&th2;
    }
}

static void insert_internal_node(fs& f, path& p, uint64_t tree, uint8_t level,
                                 const btrfs::key& k, uint64_t address) {
    auto& sb = f.dev.sb;
    size_t max_items = (sb.nodesize - sizeof(btrfs::header)) / sizeof(btrfs::key_ptr);

    {
        auto& th = *(btrfs::header*)p.bufs[level];

        if (th.nritems == max_items)
            split_internal_tree(f, p, tree, level);
    }

    auto& th = *(btrfs::header*)p.bufs[level];

    auto* items = (btrfs::key_ptr*)((uint8_t*)&th + sizeof(btrfs::header));

    memmove(&items[p.slots[level] + 1], &items[p.slots[level]],
            (th.nritems - p.slots[level]) * sizeof(btrfs::key_ptr));

    items[p.slots[level]].key = k;
    items[p.slots[level]].blockptr = address;
    items[p.slots[level]].generation = sb.generation + 1;

    th.nritems++;
}

static void split_tree_at(fs& f, path& p, uint64_t tree,
                          unsigned int split_point) {
    auto& sb = f.dev.sb;

    auto new_addr = allocate_metadata(f, tree);

    auto& th = *(btrfs::header*)p.bufs[0];
    auto* items = (btrfs::item*)((uint8_t*)&th + sizeof(btrfs::header));
    size_t to_copy = 0, total_data = 0;

    for (unsigned int i = 0; i < th.nritems; i++) {
        total_data += items[i].size;

        if (i >= split_point)
            to_copy += items[i].size;
    }

    auto& [chunk_start, c] = find_chunk(f, new_addr);

    auto& th2 = *(btrfs::header*)((uint8_t*)c.maps[0] + new_addr - chunk_start);
    memcpy(&th2, p.bufs[0], sizeof(btrfs::header));
    memset((uint8_t*)&th2 + sizeof(btrfs::header), 0,
           sb.nodesize - sizeof(btrfs::header));

    c.metadata_checked.insert(new_addr);

    th2.bytenr = new_addr;
    th2.flags &= ~btrfs::HEADER_FLAG_WRITTEN;
    th2.nritems = th.nritems - split_point;

    // copy btrfs::item items
    auto* items2 = (btrfs::item*)((uint8_t*)&th2 + sizeof(btrfs::header));
    memcpy(items2, &items[split_point], sizeof(btrfs::item) * (th.nritems - split_point));

    // move trailing entries to new tree
    memcpy((uint8_t*)&th2 + sb.nodesize - to_copy,
           p.bufs[0] + sb.nodesize - total_data, to_copy);

    for (unsigned int i = 0; i < th2.nritems; i++) {
        items2[i].offset += (uint32_t)(total_data - to_copy);
    }

    th.nritems = split_point;

    memset((uint8_t*)&th2 + sizeof(btrfs::header) + (th2.nritems * sizeof(btrfs::item)),
           0, sb.nodesize - to_copy - sizeof(btrfs::header) - (th2.nritems * sizeof(btrfs::item)));

    f.ref_changes.emplace(new_addr, ref_change{th.owner, 1});

    if (!p.bufs[1])
        add_new_level(f, p, tree, 1);

    p.slots[1]++;
    insert_internal_node(f, p, tree, 1, items2[0].key, new_addr);

    if (p.slots[0] < split_point || split_point == 0)
        p.slots[1]--;
    else {
        p.slots[0] -= split_point;
        p.bufs[0] = (uint8_t*)&th2;
    }
}

static void split_tree(fs& fs, path& p, uint64_t tree, size_t size_used,
                       size_t space_needed) {
    // FIXME - first try to push left and right

    auto nodesize = fs.dev.sb.nodesize;
    auto& th = *(btrfs::header*)p.bufs[0];
    auto* items = (btrfs::item*)((uint8_t*)&th + sizeof(btrfs::header));

    size_t sum;
    auto split_point = find_midpoint(th, size_used, sum);
    bool need_double_split = false;

    if (p.slots[0] >= split_point)
        sum = size_used - sum;

    if (nodesize - sizeof(btrfs::header) - sum < space_needed) {
        if (p.slots[0] < split_point) {
            while (split_point > 0) {
                sum += sizeof(btrfs::item) + items[split_point - 1].size;
                split_point--;

                if (nodesize - sizeof(btrfs::header) - sum >= space_needed)
                    break;
            }

            if (split_point == 0)
                need_double_split = true;
        } else {
            while (split_point < th.nritems) {
                sum += sizeof(btrfs::item) + items[split_point].size;
                split_point++;

                if (nodesize - sizeof(btrfs::header) - sum >= space_needed)
                    break;
            }

            if (split_point == th.nritems)
                need_double_split = true;
        }
    }

    if (!need_double_split) {
        split_tree_at(fs, p, tree, split_point);
        return;
    }

    if (p.slots[0] != 0)
        split_tree_at(fs, p, tree, p.slots[0]);

    auto num_items = ((btrfs::header*)p.bufs[0])->nritems;

    if (num_items != 0 && p.slots[0] < num_items - 1)
        split_tree_at(fs, p, tree, p.slots[0] + 1);
}

export span<uint8_t> insert_item(fs& f, uint64_t tree, const btrfs::key& key,
                                 uint32_t size) {
    auto& sb = f.dev.sb;

    if (size > sb.nodesize - sizeof(btrfs::header) - sizeof(btrfs::item)) {
        throw formatted_error("insert_item: key {} in tree {:x} would be {} bytes, too big for any tree",
                              key, tree, size);
    }

    auto [addr, gen, level] = find_tree_addr(f, tree);
    path p;

    find_item2(f, addr, gen, level, key, true, tree, p);

    {
        auto& h = *(btrfs::header*)p.bufs[0];
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
                split_tree(f, p, tree, size_used, sizeof(btrfs::item) + size);
        }
    }

    auto& h = *(btrfs::header*)p.bufs[0];
    auto items = (btrfs::item*)((uint8_t*)&h + sizeof(btrfs::header));

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

        memmove(p.bufs[0] + off - size, p.bufs[0] + off, to_move);
    }

    if (p.slots[0] == 0)
        items[p.slots[0]].offset = (uint32_t)(sb.nodesize - sizeof(btrfs::header) - size);
    else
        items[p.slots[0]].offset = (uint32_t)(items[p.slots[0] - 1].offset - size);

    items[p.slots[0]].size = size;

    if (p.slots[0] == 0) {
        for (uint8_t i = 1; i < btrfs::MAX_LEVEL; i++) {
            if (!p.bufs[i])
                break;

            const auto& h = *(btrfs::header*)p.bufs[i];
            auto items = (btrfs::key_ptr*)((uint8_t*)&h + sizeof(btrfs::header));
            auto& it = items[p.slots[i]];

            it.key = key;

            if (p.slots[i] != 0)
                break;
        }
    }

    return item_span(p);
}

static btrfs::uuid get_chunk_tree_uuid(fs& f) {
    auto [addr, gen, level] = find_tree_addr(f, btrfs::ROOT_TREE_OBJECTID);
    path p;

    find_item2(f, addr, gen, level, {0, (btrfs::key_type)0, 0}, false,
               btrfs::ROOT_TREE_OBJECTID, p);

    const auto& h = *(btrfs::header*)p.bufs[0];

    return h.chunk_tree_uuid;
}

export void add_tree(fs& f, uint64_t num) {
    auto& sb = f.dev.sb;

    // add empty tree node

    auto addr = allocate_metadata(f, num);

    auto& [chunk_start, c] = find_chunk(f, addr);

    auto& h = *(btrfs::header*)((uint8_t*)c.maps[0] + addr - chunk_start);
    memset(&h, 0, sb.nodesize);

    c.metadata_checked.insert(addr);

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
    auto& h = *(btrfs::header*)p.bufs[0];
    auto items = (btrfs::item*)((uint8_t*)&h + sizeof(btrfs::header));

    // move data

    if (items[p.slots[0]].size != 0) {
        unsigned int data_size = 0, after_item = 0;

        for (unsigned int i = 0; i < h.nritems; i++) {
            data_size += items[i].size;

            if (i > p.slots[0])
                after_item += items[i].size;
        }

        memmove(p.bufs[0] + sb.nodesize - data_size + items[p.slots[0]].size,
                p.bufs[0] + sb.nodesize - data_size,
                after_item);

        for (unsigned int i = p.slots[0] + 1; i < h.nritems; i++) {
            items[i].offset += (uint32_t)items[p.slots[0]].size; // FIXME - make it so cast not needed
        }
    }

    // adjust items

    memmove(&items[p.slots[0]], &items[p.slots[0] + 1],
            sizeof(btrfs::item) * (h.nritems - p.slots[0] - 1));
    h.nritems--;

    if (p.slots[0] == 0) {
        auto new_key = items[0].key;

        for (uint8_t i = 1; i < btrfs::MAX_LEVEL; i++) {
            if (!p.bufs[i])
                break;

            const auto& h = *(btrfs::header*)p.bufs[i];
            auto items = (btrfs::key_ptr*)((uint8_t*)&h + sizeof(btrfs::header));
            auto& it = items[p.slots[i]];

            it.key = new_key;

            if (p.slots[i] != 0)
                break;
        }
    } else
        p.slots[0]--;

    // FIXME - merging trees?
}

export void delete_item(fs& f, uint64_t tree, const btrfs::key& key) {
    auto [addr, gen, level] = find_tree_addr(f, tree);
    path p;

    find_item2(f, addr, gen, level, key, true, tree, p);

    auto& h = *(btrfs::header*)p.bufs[0];
    auto items = (btrfs::item*)((uint8_t*)&h + sizeof(btrfs::header));

    if (p.slots[0] >= h.nritems || key != items[p.slots[0]].key) {
        throw formatted_error("delete_item: key {} in tree {:x} does not exist",
                              key, tree);
    }

    delete_item2(f, p);
}

export void extend_item(fs& f, path& p, uint32_t size) {
    auto& sb = f.dev.sb;
    uint32_t delta;

    {
        const auto& h = *(btrfs::header*)p.bufs[0];
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

        delta = size - it.size;

        uint32_t used = sizeof(btrfs::header) + (sizeof(btrfs::item) * h.nritems);

        for (unsigned int i = 0; i < h.nritems; i++) {
            used += items[i].size;
        }

        // FIXME - try moving items left or right before splitting (share this logic with insert_item)

        if (used + delta > sb.nodesize)
            split_tree(f, p, h.owner, used, delta);
    }

    {
        // adjust item offsets and move data

        const auto& h = *(btrfs::header*)p.bufs[0];
        auto items = (btrfs::item*)((uint8_t*)&h + sizeof(btrfs::header));
        unsigned int to_move = 0;

        // move data around

        uint32_t off = sizeof(btrfs::header) + items[h.nritems - 1].offset;

        for (unsigned int i = p.slots[0]; i < h.nritems; i++) {
            to_move += items[i].size;
            items[i].offset -= delta;
        }

        assert(off >= size + sizeof(btrfs::header));

        memmove(p.bufs[0] + off - delta, p.bufs[0] + off, to_move);

        // change item size

        items[p.slots[0]].size = size;
    }
}

export void shorten_item(fs& f, path& p, uint32_t size) {
    auto& sb = f.dev.sb;
    const auto& h = *(btrfs::header*)p.bufs[0];
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

        memmove(p.bufs[0] + off + delta, p.bufs[0] + off,
                to_move - delta);
    }

    // change item size

    it.size = size;
}

export void change_key(path& p, const btrfs::key& key) {
    for (uint8_t i = 0; i < btrfs::MAX_LEVEL; i++) {
        if (!p.bufs[i])
            break;

        const auto& h = *(btrfs::header*)p.bufs[i];

        // assert that tree has been COWed
        assert(!(h.flags & btrfs::HEADER_FLAG_WRITTEN));

        if (i == 0) {
            auto items = (btrfs::item*)((uint8_t*)&h + sizeof(btrfs::header));
            auto& it = items[p.slots[i]];

            it.key = key;
        } else {
            auto items = (btrfs::key_ptr*)((uint8_t*)&h + sizeof(btrfs::header));
            auto& it = items[p.slots[i]];

            it.key = key;
        }

        if (p.slots[i] != 0)
            break;
    }
}

static void prune_trees_recurse(fs& f, uint64_t addr) {
    auto& [chunk_start, c] = find_chunk(f, addr);
    auto& h = *(btrfs::header*)((uint8_t*)c.maps[0] + addr - chunk_start);

    assert(h.level > 0);

    auto items = (btrfs::key_ptr*)((uint8_t*)&h + sizeof(btrfs::header));

    for (size_t i = 0; i < h.nritems; i++) {
        auto& it = items[i];

        if (items[i].generation != h.generation)
            continue;

        if (h.level > 1)
            prune_trees_recurse(f, it.blockptr);

        auto& [chunk_start2, c2] = find_chunk(f, it.blockptr);
        auto& h2 = *(btrfs::header*)((uint8_t*)c2.maps[0] + it.blockptr - chunk_start2);

        if (h2.nritems != 0)
            continue;

        {
            auto [it2, inserted] = f.ref_changes.emplace(it.blockptr,
                                                         ref_change{h.owner, -1});

            if (!inserted)
                it2->second.refcount_change--;
        }

        memmove(&items[i], &items[i + 1], (h.nritems - i - 1) * sizeof(btrfs::key_ptr));
        i--;
        h.nritems--;
    }
}

static void prune_trees2(fs& f, uint64_t root, uint64_t addr) {
    auto& sb = f.dev.sb;

    prune_trees_recurse(f, addr);

    while (true) {
        auto& [chunk_start, c] = find_chunk(f, addr);
        auto& h = *(btrfs::header*)((uint8_t*)c.maps[0] + addr - chunk_start);

        if (h.level == 0 || h.nritems != 1)
            break;

        // FIXME - ROOT_ITEMs can have non-zero offsets?

        auto items = (btrfs::key_ptr*)((uint8_t*)&h + sizeof(btrfs::header));
        auto& it = items[0];
        btrfs::key key{root, btrfs::key_type::ROOT_ITEM, 0};
        path p;

        if (root == btrfs::ROOT_TREE_OBJECTID) {
            sb.root = it.blockptr;
            sb.root_level--;
        } else if (root == btrfs::CHUNK_TREE_OBJECTID) {
            sb.chunk_root = it.blockptr;
            sb.chunk_root_level--;
        } else {
            auto [addr, gen, level] = find_tree_addr(f, btrfs::ROOT_TREE_OBJECTID);

            find_item2(f, addr, gen, level, key, true,
                       btrfs::ROOT_TREE_OBJECTID, p);

            assert(p.slots[0] < path_nritems(p, 0));
            assert(path_key(p, 0) == key);

            auto sp = item_span(p);

            assert(sp.size() == sizeof(btrfs::root_item));

            auto& ri = *(btrfs::root_item*)sp.data();

            ri.bytenr = it.blockptr;
            ri.level--;
        }

        {
            auto [it2, inserted] = f.ref_changes.emplace(h.bytenr,
                                                            ref_change{root, -1});
            if (!inserted)
                it2->second.refcount_change--;
        }

        addr = it.blockptr;
    }
}

export void prune_trees(fs& f) {
    auto& sb = f.dev.sb;
    path p;
    auto [addr, gen, level] = find_tree_addr(f, btrfs::ROOT_TREE_OBJECTID);

    btrfs::key key{0, btrfs::key_type::ROOT_ITEM, 0};

    // FIXME - ignore any internal nodes where generation hasn't changed

    find_item2(f, addr, gen, level, key, true,
               btrfs::ROOT_TREE_OBJECTID, p);

    while (true) {
        if (p.slots[0] == path_nritems(p, 0)) {
            if (!next_leaf(f, p, true))
                break;
        }

        auto key = path_key(p, 0);

        if (key.type == btrfs::key_type::ROOT_ITEM) {
            auto sp = item_span(p);

            assert(sp.size() == sizeof(btrfs::root_item));

            auto& ri = *(btrfs::root_item*)sp.data();

            if (ri.generation == sb.generation + 1 && ri.level != 0)
                prune_trees2(f, key.objectid, ri.bytenr);
        }

        p.slots[0]++;
    }

    if (sb.root_level != 0)
        prune_trees2(f, btrfs::ROOT_TREE_OBJECTID, sb.root);

    if (sb.chunk_root_generation == sb.generation + 1 && sb.chunk_root_level != 0)
        prune_trees2(f, btrfs::CHUNK_TREE_OBJECTID, sb.chunk_root);
}

static uint64_t find_next_chunk_offset(fs& f) {
    auto [addr, gen, level] = find_tree_addr(f, btrfs::CHUNK_TREE_OBJECTID);
    auto key = btrfs::key{ btrfs::FIRST_CHUNK_TREE_OBJECTID, btrfs::key_type::CHUNK_ITEM,
                           0xffffffffffffffff };
    path p;

    find_item2(f, addr, gen, level, key, false, btrfs::CHUNK_TREE_OBJECTID, p);

    while (true) {
        if (!prev_item(f, p, false))
            throw runtime_error("find_next_chunk_offset: prev_item failed");

        auto key = path_key(p, 0);

        if (key.objectid != btrfs::FIRST_CHUNK_TREE_OBJECTID ||
            key.type != btrfs::key_type::CHUNK_ITEM) {
            continue;
        }

        auto sp = item_span(p);

        assert(sp.size() >= offsetof(btrfs::chunk, stripe));

        auto& ci = *(btrfs::chunk*)sp.data();

        return key.offset + ci.length;
    }
}
