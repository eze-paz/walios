/* The kernel's stat record: x86_64's layout, as with WALI's wasm32 (the walios kernel writes
 * it), spelled with fixed-width types now that long is 32-bit. fstatat copies it field by
 * field into the userspace struct stat. */
struct kstat {
	unsigned long long st_dev;
	unsigned long long st_ino;
	unsigned long long st_nlink;

	unsigned st_mode;
	unsigned st_uid;
	unsigned st_gid;
	unsigned int __pad0;
	unsigned long long st_rdev;
	long long st_size;
	long long st_blksize;
	long long st_blocks;

	long long st_atime_sec;
	long long st_atime_nsec;
	long long st_mtime_sec;
	long long st_mtime_nsec;
	long long st_ctime_sec;
	long long st_ctime_nsec;
	long long __unused[3];
};
