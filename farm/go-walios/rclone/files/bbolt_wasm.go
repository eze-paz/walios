package common

// MaxMapSize represents the largest mmap size supported by Bolt.
// linux/wasm has a 2 GiB address space, so the 32-bit values apply.
const MaxMapSize = 0x7FFFFFFF // 2GB

// MaxAllocSize is the size used when creating array pointers.
const MaxAllocSize = 0xFFFFFFF
