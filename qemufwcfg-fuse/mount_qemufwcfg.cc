#ifndef WITHOUT_CAPSICUM
#if __has_include(<sys/capsicum.h>)
#include <sys/capsicum.h>
#else
#define WITHOUT_CAPSICUM
#endif
#endif

#include <sys/stat.h>

#include <netinet/in.h>

#include <fcntl.h>
#include <time.h>
#include <unistd.h>

#include "../include/dev/ic/qemufwcfgio.h"

#include "tinyfuse.hh"
#include <cassert>
#include <iostream>
#include <limits>
#include <map>
#include <memory>
#include <ranges>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <variant>

namespace {

/**
 * Enable debugging messages if we are compiling a debug build.
 */
constexpr bool Debug = false;

/**
 * Class implementing a FUSE filesystem for the QEMU FW CFG device.
 *
 * The underlying device contains a set of blobs indexed by a 16-bit
 * identifier.  One of these is a catalogue, providing name to index mappings.
 * Those names may contain slashes and so can be interpreted as paths.  This
 * filesystem builds a virtual directory structure from the names and exposes
 * them as a real filesystem.
 */
class QemuFWCfgFuseFS : public FuseFS<QemuFWCfgFuseFS, Debug> {

	/**
	 * File structure.  Contains the information from the device: the size
	 * and the selector used to access this 'file'.
	 */
	struct File {
		/// The file size.
		uint32_t size = 0;
		/// The selector for this file.
		uint16_t selector = 0;
	};

	/**
	 * QEMU Firmware Config 'file'.  This is the catalog entry returned from
	 * the device to describe the names of the other entries.
	 */
	struct FWCfgFile {
		/// The number of bytes of the 'file' that this describes.
		uint32_t size; /* size of referenced fw_cfg item, big-endian */
		/// The selector used to access this file.
		uint16_t selector; /* selector key of fw_cfg item, big-endian */
		/// Padding
		uint16_t reserved;
		/// Full file path, null-terminated string.
		char name[56]; /* fw_cfg item name, NUL-terminated ascii */
	};

	struct Directory;

	/**
	 * Helper for (shared) pointers to directories.
	 */
	using DirectoryPointer = std::shared_ptr<Directory>;

	/**
	 * Objects in the 'filesystem' are either other directories or files.
	 */
	using FilesystemObject = std::variant<File, DirectoryPointer>;

	/**
	 * Directory.  Contains a map of names to children, which may be files
	 * or other directories.
	 */
	struct Directory {
		/**
		 * The first inode to allocate to a directory.
		 */
		static constexpr uint32_t FirstDirectoryInode =
		    std::numeric_limits<decltype(File::selector)>::max() + 1;

		/**
		 * Next inode number to assign to directories.  Directory inodes
		 * are allocated after selectors.
		 */
		inline static uint32_t nextDirectoryInode = FirstDirectoryInode;

		/**
		 * Ordered map from file names to children.
		 */
		std::map<std::string, FilesystemObject> children;

		/**
		 * Cached version of the directory entries.
		 */
		VariableSizeResponse direntCache;

		/**
		 * Inode for this directory.
		 */
		const uint32_t inode;

		/**
		 * Default constructor, allocates a directory with the next
		 * available inode.
		 */
		Directory()
		    : Directory(nextDirectoryInode++)
		{
		}

		/**
		 * Construct a directory with the specified inode.
		 */
		Directory(uint32_t inode)
		    : inode(inode)
		{
		}
	};

	/**
	 * Look up the inode for an object in the filesystem.  This is either
	 * the selector for 'files' or a number outside the valid selector range
	 * for directories.
	 */
	uint32_t inode_for_filesystem_object(FilesystemObject filesystemObject)
	{
		uint32_t ret = 0;
		std::visit(
		    [&ret](auto &&object) {
			    if constexpr (std::is_same_v<File,
					      std::remove_cvref_t<
						  decltype(object)>>) {
				    ret = object.selector;
			    } else if constexpr (std::is_same_v<
						     DirectoryPointer,
						     std::remove_cvref_t<
							 decltype(object)>>) {
				    ret = object->inode;
			    } else {
			    }
		    },
		    filesystemObject);
		return ret;
	}

	/**
	 * Add a subdirectory to the current directory.  If the directory
	 * already exists, the existing one is returned, otherwise a new one is
	 * allocated and returned.
	 */
	DirectoryPointer add_subdirectory(Directory &parent,
	    const std::string &name)
	{
		auto it = parent.children.find(name);
		if (it != parent.children.end()) {
			if (std::holds_alternative<DirectoryPointer>(
				it->second)) {
				return std::get<DirectoryPointer>(it->second);
			}
			throw std::invalid_argument(
			    "Directory is a regular file");
		}
		auto newDirectory = std::make_shared<Directory>();
		parent.children[name] = newDirectory;
		inodes[newDirectory->inode] = newDirectory;
		return newDirectory;
	}

	/**
	 * Add a file in the specified directory.
	 */
	void add_file(Directory &parent, const std::string &name, uint32_t size,
	    uint16_t selector)
	{
		parent.children[name] = File { size, selector };
		inodes[selector] = parent.children[name];
	}

	/**
	 * Returns true if the inode is a directory inode, false if not.  This
	 * does not require any file or directory to actually exist for this
	 * inode number.
	 */
	bool is_directory(uint64_t inode)
	{
		return (inode == FUSE_ROOT_ID) ||
		    inode >= Directory::FirstDirectoryInode;
	}

	/**
	 * Root directory.
	 */
	DirectoryPointer root = std::make_shared<Directory>(FUSE_ROOT_ID);

	/**
	 * Map from inode number to the object that they refer to.
	 */
	std::unordered_map<uint64_t, FilesystemObject> inodes;

	/**
	 * Next number to use for a file descriptor.
	 */
	uint64_t nextFH = 1;

	/**
	 * Buffers that cache the contents of files.  We currently never
	 * invalidate these because the interface is not used to deliver very
	 * large files. The filesystem can be unmounted and remounted to clear
	 * the cache.
	 *
	 * If this is a problem, it's easy to add some cache invalidation later.
	 */
	std::unordered_map<uint16_t, Buffer> fileCaches;

	/**
	 * Time (in seconds) when the filesystem was mounted.  All files are
	 * treated as being created at that time.
	 */
	const uint32_t timeS;

	/**
	 * File descriptor for the QEMU FWCFG device.
	 */
	int qemuFWCfgFD;

	/**
	 * The GID used for files in this filesystem
	 */
	gid_t defaultGid;

	/**
	 * The UID used for files in this filesystem
	 */
	uid_t defaultUid;

	/**
	 * The mode for directories in this filesystem.
	 */
	mode_t defaultDirectoryMode;

	/**
	 * The mode for files in this filesystem.
	 */
	mode_t defaultFileMode;

    public:
	/**
	 * Constructor.  Reads the catalog from the device and prepares the
	 * filesystem structure.
	 */
	QemuFWCfgFuseFS(const char *devicePath, gid_t defaultGid,
	    uid_t defaultUid, mode_t defaultDirectoryMode,
	    mode_t defaultFileMode)
	    : timeS(time(nullptr))
	    , defaultGid(defaultGid)
	    , defaultUid(defaultUid)
	    , defaultDirectoryMode(defaultDirectoryMode)
	    , defaultFileMode(defaultFileMode)
	{
		// Open the qemufwcfg device.  This can fail if this filesystem
		// is already mounted: it is designed for a single userspace
		// consumer.
		qemuFWCfgFD = open(devicePath, O_RDWR);
		if (qemuFWCfgFD < 0) {
			throw std::system_error(errno, std::generic_category(),
			    "Failed to open qemufwcfg device");
		}
		// Set the selector to the index for the well-known blob
		// containing the catalogue.
		uint16_t selector = FW_CFG_FILE_DIR;
		ioctl(qemuFWCfgFD, FWCFGIO_SET_INDEX, &selector);
		// Read the number of entries (big endian).
		uint32_t count;
		if (int ret = read(qemuFWCfgFD, &count, sizeof(count));
		    ret != sizeof(count)) {
			throw std::system_error(errno, std::generic_category(),
			    "Failed to read number of entries in qemufwcfg device");
		}
		debug_message("Found {} firmware entries", count);
		count = ntohl(count);
		// Read each entry and build the required directory structure.
		for (uint32_t i = 0; i < count; i++) {
			FWCfgFile file;
			read(qemuFWCfgFD, &file, sizeof(file));
			debug_message("File name: {}, size: {}, selector: {}",
			    file.name, ntohl(file.size), ntohs(file.selector));
			std::string_view path { file.name };
			size_t nextSlash;
			auto dir = root;
			// If this name contains any slashes, construct a
			// directory hierarchy leading up to the directory
			// containing the file.
			while ((nextSlash = path.find('/')) !=
			    std::string_view::npos) {
				std::string pathComponent { path.substr(0,
				    nextSlash) };
				dir = add_subdirectory(*dir, pathComponent);
				path = path.substr(nextSlash + 1);
			}
			// Insert the file into the directory.
			add_file(*dir, std::string { path }, ntohl(file.size),
			    ntohs(file.selector));
		}
		// Insert the root directory into the inodes map.
		inodes[FUSE_ROOT_ID] = root;
	}

	/**
	 * Implement stat functionality.
	 */
	ErrorOr<fuse_attr_out> fuse_getattr(const fuse_in_header &header,
	    const fuse_getattr_in &attrIn)
	{
		uint64_t inode = header.nodeid;
		debug_message("GetAttr flags: {}, inode: {}",
		    attrIn.getattr_flags, inode);
		bool isDirectory = is_directory(inode);
		// If this is a directory, the size is zero, otherwise look up
		// the size.
		uint64_t size = 0;
		if (!isDirectory) {
			size = std::get<File>(inodes[inode]).size;
		}
		fuse_attr_out out;
		memset(&out, 0, sizeof(out));
		// Read-only filesystem, make the cache timeout the distant
		// future.
		out.attr_valid = 1;
		// std::numeric_limits<decltype(out.attr_valid)>::max();
		out.attr_valid_nsec = 0; // 0x10000;
		out.dummy = 0;
		// Attributes
		set_attrs(out.attr, inode, size, isDirectory);
		return out;
	}

	/**
	 * Open a directory descriptor.
	 */
	ErrorOr<fuse_open_out> fuse_opendir(const fuse_in_header &header,
	    const fuse_open_in &)
	{
		if (!is_directory(header.nodeid)) {
			debug_message(
			    "Trying to open directory with non-directory inode {}",
			    header.nodeid);
			return ENOENT;
		}
		auto it = inodes.find(header.nodeid);
		if (it == inodes.end()) {
			debug_message(
			    "Trying to open unknown directory with inode {}",
			    header.nodeid);
			return ENOENT;
		}
		fuse_open_out ret;
		memset(&ret, 0, sizeof(ret));
		ret.fh = nextFH++;
		debug_message("New open directory has handle {}", ret.fh);
		return ret;
	}

	/**
	 * Open a file descriptor.
	 */
	ErrorOr<fuse_open_out> fuse_open(const fuse_in_header &header,
	    const fuse_open_in &)
	{
		if (is_directory(header.nodeid)) {
			debug_message(
			    "Trying to open file with directory inode: {}",
			    header.nodeid);
			return ENOENT;
		}
		auto it = inodes.find(header.nodeid);
		if (it == inodes.end()) {
			debug_message(
			    "Trying to open unknown file with inode: {}",
			    header.nodeid);
			return ENOENT;
		}
		fuse_open_out ret;
		memset(&ret, 0, sizeof(ret));
		ret.fh = nextFH++;
		debug_message("New open file has handle {}", ret.fh);
		return ret;
	}

	/**
	 * Read from a file.
	 *
	 * The underlying device does not support seeking and so this will read
	 * the entire file and cache it.
	 */
	ErrorOr<std::ranges::subrange<Buffer::iterator>>
	fuse_read(const fuse_in_header &header, const fuse_read_in &readIn)
	{
		debug_message(
		    "read {{ fh: {}, offset: {}, size: {}, read_flags: {}, lock_owner: {}, flags: {} }}",
		    readIn.fh, readIn.offset, readIn.size, readIn.read_flags,
		    readIn.lock_owner, readIn.flags);
		auto &item = inodes[header.nodeid];
		if (!std::holds_alternative<File>(item)) {
			return EINVAL;
		}
		auto file = std::get<File>(item);
		Buffer out;
		out.resize(readIn.size);
		int ret = ioctl(qemuFWCfgFD, FWCFGIO_SET_INDEX, &file.selector);
		if (ret != 0) {
			throw std::system_error(errno, std::generic_category(),
			    "Failed to switch selector in qemufwcfg device");
		}
		auto &cache = fileCaches[file.selector];
		if (cache.size() < file.size) {
			Buffer tmp;
			tmp.resize(file.size);
			size_t readData = 0;
			while (readData < readIn.size) {
				ssize_t result = read(qemuFWCfgFD,
				    tmp.data() + readData,
				    out.size() - readData);
				if (result < 0) {
					if (errno == EAGAIN) {
						continue;
					}
					throw std::system_error(errno,
					    std::generic_category(),
					    "Failed to read from qemufwcfg device");
				}
				readData += result;
			}
			cache = std::move(tmp);
		}
		return std::ranges::subrange(cache.begin() + readIn.offset,
		    cache.begin() + readIn.offset + readIn.size);
	}

	/**
	 * Read one or more directory entries.
	 */
	ErrorOr<std::ranges::subrange<Buffer::iterator>>
	fuse_readdir(const fuse_in_header &header, const fuse_read_in &readIn)
	{
		debug_message(
		    "readdir {{ fh: {}, offset: {}, size: {}, read_flags: {}, lock_owner: {}, flags: {} }}",
		    readIn.fh, readIn.offset, readIn.size, readIn.read_flags,
		    readIn.lock_owner, readIn.flags);
		auto &item = inodes[header.nodeid];
		if (!std::holds_alternative<DirectoryPointer>(item)) {
			return EINVAL;
		}
		auto &directory = *std::get<DirectoryPointer>(item);
		VariableSizeResponse &dirents = directory.direntCache;
		if (dirents.empty()) {
			auto roundUp8 = [](size_t size) {
				return ((size + 8 - 1) / 8) * 8;
			};
			// For some reason (to be debugged) the kernel doesn't
			// like these if you give them the correct inode values,
			// but is happy with -1 as a 32-bit integer.
			//
			// Normal dirents use 0 as the indicator of the position
			// of the next one, but FUSE uses -1.  This, like
			// everything else about FUSE, is undocumented.
			auto addDirent = [&](std::string_view name,
					     bool isLast = false,
					     uint32_t inode = 0xffff'ffff) {
				auto initialSize = dirents.size();
				auto next = roundUp8(
				    sizeof(fuse_dirent) + name.size());
				dirents << fuse_dirent { inode,
					isLast ? -1 : next,
					static_cast<uint32_t>(name.size()), 0 }
					<< name;
				dirents.pad_to_alignment(8);
				auto length = dirents.size() - initialSize;
				debug_message(
				    "Added dirent at offset {}, next: {}",
				    initialSize, next);
				assert(length == next);
			};
			addDirent(".");
			addDirent("..");
			if (directory.children.size() > 0) {
				for (auto i : std::ranges::subrange(
					 directory.children.begin(),
					 --directory.children.end())) {
					addDirent(i.first);
				}
			}
			// Add the last entry.
			addDirent((--directory.children.end())->first, true);
		}
		debug_message("Dirents size: {}, number of entries: {}",
		    dirents.size(), directory.children.size());
		if (readIn.offset >= dirents.size()) {
			debug_message("Writing no dirent for >0 offset {}",
			    readIn.offset);
			return 0;
		}
		size_t size = std::min<size_t>(readIn.size,
		    dirents.size() - readIn.offset);
		return std::ranges::subrange(dirents.begin() + readIn.offset,
		    dirents.begin() + size);
	}

	/**
	 * Look up a path component in a directory.
	 */
	ErrorOr<fuse_entry_out> fuse_lookup(const fuse_in_header &header,
	    const char *path)
	{
		// Find the directory from the inode.
		auto &containingDirectory = inodes[header.nodeid];
		if (!std::holds_alternative<DirectoryPointer>(
			containingDirectory)) {
			return EINVAL;
		}

		auto &directory = *std::get<DirectoryPointer>(
		    containingDirectory);

		// Find the entry in the directory.
		std::string filename { path };
		auto &item = directory.children[filename];
		debug_message("Look up: {}", path);

		fuse_entry_out out;
		memset(&out, 0, sizeof(out));
		out.nodeid = inode_for_filesystem_object(item);
		out.generation = 0;
		// Maximum possible timeout.  We are an immutable filesystem.
		out.entry_valid =
		    std::numeric_limits<decltype(out.entry_valid)>::max();
		out.attr_valid = 1;
		out.entry_valid_nsec = 0;
		out.attr_valid_nsec = 0;
		uint64_t size = 0;
		bool isDirectory = true;
		if (std::holds_alternative<File>(item)) {
			size = std::get<File>(item).size;
			debug_message("File size is {}", size);
			isDirectory = false;
		} else {
			debug_message("{} is a directory", path);
		}
		set_attrs(out.attr, inode_for_filesystem_object(item), size,
		    isDirectory);
		return out;
	}

	/**
	 * Set the fuse attributes for a file or directory given an inode number
	 * and size.
	 */
	void set_attrs(fuse_attr &attr, uint64_t inode, uint64_t size,
	    bool isDirectory)
	{
		static constexpr uint64_t BlockSize = 512;
		// Inode number
		attr.ino = inode;
		// Fake size, it's a directory.
		attr.size = size;
		attr.blocks = size / BlockSize;
		// Read-only filesystem, everything was created at the time when
		// we mounted the filesystem.
		attr.atime = attr.mtime = attr.ctime = timeS;
		attr.atimensec = attr.mtimensec = attr.ctimensec = 0;
		// Read-only
		attr.mode = isDirectory ? (defaultDirectoryMode | S_IFDIR) :
					  (defaultFileMode | S_IFREG);
		// No links on this filesystem, give everything a link count of
		// one.
		attr.nlink = 1;
		attr.uid = defaultUid;
		attr.gid = defaultGid;
		attr.rdev = 0;
		attr.blksize = BlockSize;
	}
};

}

int
main(int argc, char **argv)
{
	// Is this a direct invocation, or via mount_fusefs?
	bool directInvocation = (getenv("FUSE_DEV_FD") == nullptr);

	// Default configuration options.
	const char *devicePath = "/dev/qemufwcfg";
	gid_t defaultGid = getgid();
	uid_t defaultUid = getuid();
	mode_t defaultDirectoryMode = S_IRUSR | S_IRGRP | S_IROTH | S_IXGRP |
	    S_IXOTH;
	mode_t defaultFileMode = S_IRUSR | S_IRGRP | S_IROTH;

	// Parse command-line flags.
	const char *argv0 = argv[0];
	int ch;
	// Don't report illegal options, they are ones that we should forward to
	// mount_fusefs
	opterr = !directInvocation;
	while ((ch = getopt(argc, argv, "F:g:M:m:u:h")) != -1) {
		// Unknown options are assumed to be for mount_fusefs
		if (directInvocation && (ch == '?')) {
			optind--;
			break;
		}
		switch (ch) {
		case 'F':
			devicePath = optarg;
			break;
		case 'm':
			defaultFileMode = std::stoi(optarg, nullptr, 8) &
			    ACCESSPERMS;
			break;
		case 'M':
			defaultDirectoryMode = std::stoi(optarg, nullptr, 8) &
			    ACCESSPERMS;
			break;
		case 'g':
			defaultGid = std::stoi(optarg);
			break;
		case 'u':
			defaultUid = std::stoi(optarg);
			break;
		case 'h':
		default:
			std::cerr
			    << "Usage: " << argv[0]
			    << " [-F path] [-g gid] [-M dir-mode] [-m file-mode] [-u uid] [fuse-options] node"
			    << std::endl;
			return EXIT_SUCCESS;
		}
	}
	argc -= optind;
	argv += optind;

	// If we are not invoked by mount_fusefs, exec mount_fusefs.
	if (getenv("FUSE_DEV_FD") == nullptr) {
		const char *mount_fusefs = "/sbin/mount_fusefs";
		std::string daemonArgs = std::format(
		    "-F {} -g {} -M {} -m {} -u {}", devicePath, defaultGid,
		    defaultDirectoryMode, defaultUid, defaultUid);
		std::vector<const char *> args;
		args.push_back(mount_fusefs);
		args.push_back("auto");
		args.push_back("-O");
		args.push_back(daemonArgs.c_str());
		args.push_back("-D");
		args.push_back(argv0);
		for (int i = 0; i < argc; i++) {
			args.push_back(argv[i]);
		}
		args.push_back(nullptr);
		execv(mount_fusefs, const_cast<char *const *>(args.data()));
		return EXIT_FAILURE;
	}

	QemuFWCfgFuseFS fs(devicePath, defaultGid, defaultUid,
	    defaultDirectoryMode, defaultFileMode);
#ifndef WITHOUT_CAPSICUM
	// Close standard in and out, restrict the rights on standard error to
	// output (no ioctls, no read, and so on).
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	cap_rights_t setrights;
	cap_rights_init(&setrights, CAP_WRITE);
	cap_rights_limit(STDERR_FILENO, &setrights);
	cap_enter();
#endif
	try {
		fs.run();
	} catch (std::exception &e) {
		std::cerr << "QEMU Firmware Filesystem failed: " << e.what()
			  << std::endl;
	}
}
