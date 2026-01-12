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
import ctree;

using namespace std;

static const size_t SZ_1M = 0x100000;

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
    bool identity_remap = it.key.type == btrfs::key_type::IDENTITY_REMAP;

    if (it.key.objectid == addr) {
        if (it.key.offset == length) {
            // removing whole thing
            delete_item2(f, p);
        } else {
            // removing beginning

            if (!identity_remap) {
                assert(it.size == sizeof(btrfs::remap));

                auto& r = *(btrfs::remap*)item_span(p).data();

                r.address += length;
            }

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
                              identity_remap ? 0 : sizeof(btrfs::remap));

        if (!identity_remap) {
            auto& r2 = *(btrfs::remap*)sp.data();

            r2.address = other_addr + addr + length - it.key.objectid;
        }
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
    bool identity_remap;

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

        assert((it.key.type == btrfs::key_type::REMAP && it.size == sizeof(btrfs::remap)) ||
               (it.key.type == btrfs::key_type::IDENTITY_REMAP && it.size == 0));
        assert(it.key.objectid <= src_addr);
        assert(it.key.objectid + it.key.offset >= src_addr + length);

        identity_remap = it.key.type == btrfs::key_type::IDENTITY_REMAP;

        found_key = it.key;

        if (!identity_remap) {
            auto& r = *(btrfs::remap*)item_span(p).data();

            dest_addr = r.address;
        }

        remove_from_remap_tree2(f, p, src_addr, length);
    }

    if (identity_remap)
        return;

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
