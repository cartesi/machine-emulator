// Copyright Cartesi and individual authors (see AUTHORS)
// SPDX-License-Identifier: LGPL-3.0-or-later
//
// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU Lesser General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option) any
// later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
// PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License along
// with this program (see COPYING). If not, see <https://www.gnu.org/licenses/>.
//

#ifndef VIRTIO_P9FS_H
#define VIRTIO_P9FS_H

#include "os-features.h"
#include "compiler-defines.h"

#ifdef HAVE_POSIX_FS

#include "virtio-device.h"
#include "virtio-serializer.h"
#include "compiler-defines.h"

#include <unordered_map>

namespace cartesi {

/// \brief VirtIO Plan 9 filesystem features
enum virtio_p9fs_features : uint64_t {
    VIRTIO_9P_F_MOUNT_TAG = (UINT64_C(1) << 0), ///< Mount tag supported.
};

/// \brief VirtIO Plan 9 filesystem constants
enum virtio_p9fs_constants : uint32_t {
    P9_MAXWELEM = 16,        ///< Maximum number of elements in a walk operation
    P9_NAME_MAX = 256,       ///< Maximum file name length
    P9_PATH_MAX = 4096,      ///< Maximum filesystem path length
    P9_ROOT_PATH_MAX = 1024, ///< Maximum root path size
    P9_MOUNT_TAG_MAX = VIRTIO_MAX_CONFIG_SPACE_SIZE - sizeof(uint16_t), ///< Maximum mount tag size
    P9_IOUNIT_MAX = 8192,                                 ///< Maximum buffer size for IO operations (read/write)
    P9_IOUNIT_HEADER_SIZE = 24,                           ///< Message header size of IO operations (read/write)
    P9_MAX_MSIZE = P9_IOUNIT_MAX + P9_IOUNIT_HEADER_SIZE, ///< Maximum message size, including message headers
    P9_OUT_MSG_OFFSET = 7,                                ///< Offset for 9P reply messages
};

/// \brief 9P2000.L opcodes
enum p9_opcode : uint8_t {
    P9_TLERROR = 6,
    P9_RLERROR,
    P9_TSTATFS = 8,
    P9_RSTATFS,
    P9_TLOPEN = 12,
    P9_RLOPEN,
    P9_TLCREATE = 14,
    P9_RLCREATE,
    P9_TSYMLINK = 16,
    P9_RSYMLINK,
    P9_TMKNOD = 18,
    P9_RMKNOD,
    P9_TRENAME = 20,
    P9_RRENAME,
    P9_TREADLINK = 22,
    P9_RREADLINK,
    P9_TGETATTR = 24,
    P9_RGETATTR,
    P9_TSETATTR = 26,
    P9_RSETATTR,
    P9_TXATTRWALK = 30,
    P9_RXATTRWALK,
    P9_TXATTRCREATE = 32,
    P9_RXATTRCREATE,
    P9_TREADDIR = 40,
    P9_RREADDIR,
    P9_TFSYNC = 50,
    P9_RFSYNC,
    P9_TLOCK = 52,
    P9_RLOCK,
    P9_TGETLOCK = 54,
    P9_RGETLOCK,
    P9_TLINK = 70,
    P9_RLINK,
    P9_TMKDIR = 72,
    P9_RMKDIR,
    P9_TRENAMEAT = 74,
    P9_RRENAMEAT,
    P9_TUNLINKAT = 76,
    P9_RUNLINKAT,
    P9_TVERSION = 100,
    P9_RVERSION,
    P9_TAUTH = 102,
    P9_RAUTH,
    P9_TATTACH = 104,
    P9_RATTACH,
    P9_TERROR = 106,
    P9_RERROR,
    P9_TFLUSH = 108,
    P9_RFLUSH,
    P9_TWALK = 110,
    P9_RWALK,
    P9_TOPEN = 112,
    P9_ROPEN,
    P9_TCREATE = 114,
    P9_RCREATE,
    P9_TREAD = 116,
    P9_RREAD,
    P9_TWRITE = 118,
    P9_RWRITE,
    P9_TCLUNK = 120,
    P9_RCLUNK,
    P9_TREMOVE = 122,
    P9_RREMOVE,
    P9_TSTAT = 124,
    P9_RSTAT,
    P9_TWSTAT = 126,
    P9_RWSTAT,
};

/// \brief 9P2000.L errors
enum p9_error : uint32_t {
    P9_EOK = 0,              ///< No error
    P9_EPERM = 1,            ///< Operation not permitted
    P9_ENOENT = 2,           ///< No such file or directory
    P9_ESRCH = 3,            ///< No such process
    P9_EINTR = 4,            ///< Interrupted system call
    P9_EIO = 5,              ///< I/O error
    P9_ENXIO = 6,            ///< No such device or address
    P9_E2BIG = 7,            ///< Argument list too long
    P9_ENOEXEC = 8,          ///< Exec format error
    P9_EBADF = 9,            ///< Bad file number
    P9_ECHILD = 10,          ///< No child processes
    P9_EAGAIN = 11,          ///< Try again
    P9_ENOMEM = 12,          ///< Out of memory
    P9_EACCES = 13,          ///< Permission denied
    P9_EFAULT = 14,          ///< Bad address
    P9_ENOTBLK = 15,         ///< Block device required
    P9_EBUSY = 16,           ///< Device or resource busy
    P9_EEXIST = 17,          ///< File exists
    P9_EXDEV = 18,           ///< Cross-device link
    P9_ENODEV = 19,          ///< No such device
    P9_ENOTDIR = 20,         ///< Not a directory
    P9_EISDIR = 21,          ///< Is a directory
    P9_EINVAL = 22,          ///< Invalid argument
    P9_ENFILE = 23,          ///< File table overflow
    P9_EMFILE = 24,          ///< Too many open files
    P9_ENOTTY = 25,          ///< Not a typewriter
    P9_ETXTBSY = 26,         ///< Text file busy
    P9_EFBIG = 27,           ///< File too large
    P9_ENOSPC = 28,          ///< No space left on device
    P9_ESPIPE = 29,          ///< Illegal seek
    P9_EROFS = 30,           ///< Read-only file system
    P9_EMLINK = 31,          ///< Too many links
    P9_EPIPE = 32,           ///< Broken pipe
    P9_EDOM = 33,            ///< Math argument out of domain of func
    P9_ERANGE = 34,          ///< Math result not representable
    P9_EDEADLK = 35,         ///< Resource deadlock would occur
    P9_ENAMETOOLONG = 36,    ///< File name too long
    P9_ENOLCK = 37,          ///< No record locks available
    P9_ENOSYS = 38,          ///< Invalid system call number
    P9_ENOTEMPTY = 39,       ///< Directory not empty
    P9_ELOOP = 40,           ///< Too many symbolic links encountered
    P9_EWOULDBLOCK = EAGAIN, ///< Operation would block
    P9_ENOMSG = 42,          ///< No message of desired type
    P9_EIDRM = 43,           ///< Identifier removed
    P9_ECHRNG = 44,          ///< Channel number out of range
    P9_EL2NSYNC = 45,        ///< Level 2 not synchronized
    P9_EL3HLT = 46,          ///< Level 3 halted
    P9_EL3RST = 47,          ///< Level 3 reset
    P9_ELNRNG = 48,          ///< Link number out of range
    P9_EUNATCH = 49,         ///< Protocol driver not attached
    P9_ENOCSI = 50,          ///< No CSI structure available
    P9_EL2HLT = 51,          ///< Level 2 halted
    P9_EBADE = 52,           ///< Invalid exchange
    P9_EBADR = 53,           ///< Invalid request descriptor
    P9_EXFULL = 54,          ///< Exchange full
    P9_ENOANO = 55,          ///< No anode
    P9_EBADRQC = 56,         ///< Invalid request code
    P9_EBADSLT = 57,         ///< Invalid slot
    P9_EDEADLOCK = EDEADLK,
    P9_EBFONT = 59,           ///< Bad font file format
    P9_ENOSTR = 60,           ///< Device not a stream
    P9_ENODATA = 61,          ///< No data available
    P9_ETIME = 62,            ///< Timer expired
    P9_ENOSR = 63,            ///< Out of streams resources
    P9_ENONET = 64,           ///< Machine is not on the network
    P9_ENOPKG = 65,           ///< Package not installed
    P9_EREMOTE = 66,          ///< Object is remote
    P9_ENOLINK = 67,          ///< Link has been severed
    P9_EADV = 68,             ///< Advertise error
    P9_ESRMNT = 69,           ///< Srmount error
    P9_ECOMM = 70,            ///< Communication error on send
    P9_EPROTO = 71,           ///< Protocol error
    P9_EMULTIHOP = 72,        ///< Multihop attempted
    P9_EDOTDOT = 73,          ///< RFS specific error
    P9_EBADMSG = 74,          ///< Not a data message
    P9_EOVERFLOW = 75,        ///< Value too large for defined data type
    P9_ENOTUNIQ = 76,         ///< Name not unique on network
    P9_EBADFD = 77,           ///< File descriptor in bad state
    P9_EREMCHG = 78,          ///< Remote address changed
    P9_ELIBACC = 79,          ///< Can not access a needed shared library
    P9_ELIBBAD = 80,          ///< Accessing a corrupted shared library
    P9_ELIBSCN = 81,          ///< .lib section in a.out corrupted
    P9_ELIBMAX = 82,          ///< Attempting to link in too many shared libraries
    P9_ELIBEXEC = 83,         ///< Cannot exec a shared library directly
    P9_EILSEQ = 84,           ///< Illegal byte sequence
    P9_ERESTART = 85,         ///< Interrupted system call should be restarted
    P9_ESTRPIPE = 86,         ///< Streams pipe error
    P9_EUSERS = 87,           ///< Too many users
    P9_ENOTSOCK = 88,         ///< Socket operation on non-socket
    P9_EDESTADDRREQ = 89,     ///< Destination address required
    P9_EMSGSIZE = 90,         ///< Message too long
    P9_EPROTOTYPE = 91,       ///< Protocol wrong type for socket
    P9_ENOPROTOOPT = 92,      ///< Protocol not available
    P9_EPROTONOSUPPORT = 93,  ///< Protocol not supported
    P9_ESOCKTNOSUPPORT = 94,  ///< Socket type not supported
    P9_EOPNOTSUPP = 95,       ///< Operation not supported on transport endpoint
    P9_EPFNOSUPPORT = 96,     ///< Protocol family not supported
    P9_EAFNOSUPPORT = 97,     ///< Address family not supported by protocol
    P9_EADDRINUSE = 98,       ///< Address already in use
    P9_EADDRNOTAVAIL = 99,    ///< Cannot assign requested address
    P9_ENETDOWN = 100,        ///< Network is down
    P9_ENETUNREACH = 101,     ///< Network is unreachable
    P9_ENETRESET = 102,       ///< Network dropped connection because of reset
    P9_ECONNABORTED = 103,    ///< Software caused connection abort
    P9_ECONNRESET = 104,      ///< Connection reset by peer
    P9_ENOBUFS = 105,         ///< No buffer space available
    P9_EISCONN = 106,         ///< Transport endpoint is already connected
    P9_ENOTCONN = 107,        ///< Transport endpoint is not connected
    P9_ESHUTDOWN = 108,       ///< Cannot send after transport endpoint shutdown
    P9_ETOOMANYREFS = 109,    ///< Too many references: cannot splice
    P9_ETIMEDOUT = 110,       ///< Connection timed out
    P9_ECONNREFUSED = 111,    ///< Connection refused
    P9_EHOSTDOWN = 112,       ///< Host is down
    P9_EHOSTUNREACH = 113,    ///< No route to host
    P9_EALREADY = 114,        ///< Operation already in progress
    P9_EINPROGRESS = 115,     ///< Operation now in progress
    P9_ESTALE = 116,          ///< Stale file handle
    P9_EUCLEAN = 117,         ///< Structure needs cleaning
    P9_ENOTNAM = 118,         ///< Not a XENIX named type file
    P9_ENAVAIL = 119,         ///< No XENIX semaphores available
    P9_EISNAM = 120,          ///< Is a named type file
    P9_EREMOTEIO = 121,       ///< Remote I/O error
    P9_EDQUOT = 122,          ///< Quota exceeded
    P9_ENOMEDIUM = 123,       ///< No medium found
    P9_EMEDIUMTYPE = 124,     ///< Wrong medium type
    P9_ECANCELED = 125,       ///< Operation Canceled
    P9_ENOKEY = 126,          ///< Required key not available
    P9_EKEYEXPIRED = 127,     ///< Key has expired
    P9_EKEYREVOKED = 128,     ///< Key has been revoked
    P9_EKEYREJECTED = 129,    ///< Key was rejected by service
    P9_EOWNERDEAD = 130,      ///< Owner died
    P9_ENOTRECOVERABLE = 131, ///< State not recoverable
    P9_ERFKILL = 132,         ///< Operation not possible due to RF-kill
    P9_EHWPOISON = 133        ///< Memory page has hardware error
};

/// \brief 9P2000.L qid type
enum p9_qid_type : uint8_t {
    P9_QID_FILE = 0x00,
    P9_QID_LINK = 0x01,
    P9_QID_SYMLINK = 0x02,
    P9_QID_TMP = 0x04,
    P9_QID_AUTH = 0x08,
    P9_QID_MOUNT = 0x10,
    P9_QID_EXCL = 0x20,
    P9_QID_APPEND = 0x40,
    P9_QID_DIR = 0x80,
};

/// \brief 9P2000.L open flags
enum p9_open_flags : uint32_t {
    P9_O_RDONLY = 0x000000,
    P9_O_WRONLY = 0x000001,
    P9_O_RDWR = 0x000002,
    P9_O_NOACCESS = 0x000003,
    P9_O_CREAT = 0x000040,
    P9_O_EXCL = 0x000080,
    P9_O_NOCTTY = 0x000100,
    P9_O_TRUNC = 0x000200,
    P9_O_APPEND = 0x000400,
    P9_O_NONBLOCK = 0x000800,
    P9_O_DSYNC = 0x001000,
    P9_O_FASYNC = 0x002000,
    P9_O_DIRECT = 0x004000,
    P9_O_LARGEFILE = 0x008000,
    P9_O_DIRECTORY = 0x010000,
    P9_O_NOFOLLOW = 0x020000,
    P9_O_NOATIME = 0x040000,
    P9_O_CLOEXEC = 0x080000,
    P9_O_SYNC = 0x100000,
};

/// \brief 9P2000.L getattr flags
enum p9_getattr_flags : uint32_t {
    P9_GETATTR_MODE = 0x0001,
    P9_GETATTR_NLINK = 0x0002,
    P9_GETATTR_UID = 0x0004,
    P9_GETATTR_GID = 0x0008,
    P9_GETATTR_RDEV = 0x0010,
    P9_GETATTR_ATIME = 0x0020,
    P9_GETATTR_MTIME = 0x0040,
    P9_GETATTR_CTIME = 0x0080,
    P9_GETATTR_INO = 0x0100,
    P9_GETATTR_SIZE = 0x0200,
    P9_GETATTR_BLOCKS = 0x0400,
    P9_GETATTR_BTIME = 0x0800,
    P9_GETATTR_GEN = 0x1000,
    P9_GETATTR_DATA_VERSION = 0x2000,
};

/// \brief 9P2000.L setattr flags
enum p9_setattr_flags : uint32_t {
    P9_SETATTR_MODE = 0x001,
    P9_SETATTR_UID = 0x002,
    P9_SETATTR_GID = 0x004,
    P9_SETATTR_SIZE = 0x008,
    P9_SETATTR_ATIME = 0x010,
    P9_SETATTR_MTIME = 0x020,
    P9_SETATTR_CTIME = 0x040,
    P9_SETATTR_ATIME_SET = 0x080,
    P9_SETATTR_MTIME_SET = 0x100
};

/// \brief 9P2000.L at flags
enum p9_at_flags : uint32_t { P9_AT_REMOVEDIR = 0x200 };

/// \brief 9P2000.L lock flags
enum p9_lock_flags : uint8_t { P9_LOCK_FLAGS_BLOCK = 1, P9_LOCK_FLAGS_RECLAIM = 2 };

/// \brief 9P2000.L lock status
enum p9_lock_status : uint8_t {
    P9_LOCK_SUCCESS = 0,
    P9_LOCK_BLOCKED = 1,
    P9_LOCK_ERROR = 2,
    P9_LOCK_GRACE = 3,
};

/// \brief 9P2000.L lock type
enum p9_lock_type : uint8_t {
    P9_LOCK_TYPE_RDLCK = 0,
    P9_LOCK_TYPE_WRLCK = 1,
    P9_LOCK_TYPE_UNLCK = 2,
};

/// \brief 9P2000.L qid
/// \details A qid is a 13 byte value representing a unique file system object.
struct PACKED p9_qid {
    uint8_t type;     ///< File type (directory/symlink/file)
    uint32_t version; ///< Cache version
    uint64_t path;    ///< The inode representing the path
};

/// \brief 9P2000.L file stat
struct PACKED p9_stat {
    uint32_t mode;
    uint32_t uid;
    uint32_t gid;
    uint64_t nlink;
    uint64_t rdev;
    uint64_t size;
    uint64_t blksize;
    uint64_t blocks;
    uint64_t atime_sec;    ///< Access time (seconds)
    uint64_t atime_nsec;   ///< Access time (nanoseconds)
    uint64_t mtime_sec;    ///< Modification time (seconds)
    uint64_t mtime_nsec;   ///< Modification time (nanoseconds)
    uint64_t ctime_sec;    ///< Status change time (seconds)
    uint64_t ctime_nsec;   ///< Status change time (nanoseconds)
    uint64_t btime_sec;    ///< Reserved for future use
    uint64_t btime_nsec;   ///< Reserved for future use
    uint64_t gen;          ///< Reserved for future use
    uint64_t data_version; ///< Reserved for future use
};

/// \brief 9P2000.L fid state
/// \details A fid is a file system object identifier, each one has its own state.
struct p9_fid_state {
    uint32_t uid = 0;     ///< Guest user id
    std::string path;     ///< File system path
    int fd = -1;          ///< Host file descriptor (valid only for opened files)
    void *dirp = nullptr; ///< Host directory (valid only for opened directories)
};

/// \brief VirtIO Plan 9 filesystem configuration space
struct virtio_p9fs_config_space {
    uint16_t mount_tag_len;                       ///< Length of mount tag
    std::array<char, P9_MOUNT_TAG_MAX> mount_tag; ///< Mount tag, an arbitrary name used in mount command
};

/// \brief VirtIO Plan 9 filesystem device
class virtio_p9fs_device final : public virtio_device {
    uint32_t m_msize = 0;
    std::string m_root_path;
    std::unordered_map<uint32_t, p9_fid_state> m_fids;

public:
    virtio_p9fs_device(uint32_t virtio_idx, const std::string &mount_tag, const std::string &root_path);
    ~virtio_p9fs_device() override;
    virtio_p9fs_device(const virtio_p9fs_device &other) = delete;
    virtio_p9fs_device(virtio_p9fs_device &&other) = delete;
    virtio_p9fs_device &operator=(const virtio_p9fs_device &other) = delete;
    virtio_p9fs_device &operator=(virtio_p9fs_device &&other) = delete;

    void on_device_reset() override;
    void on_device_ok(i_device_state_access *a) override;
    bool on_device_queue_available(i_device_state_access *a, uint32_t queue_idx, uint16_t desc_idx,
        uint32_t read_avail_len, uint32_t write_avail_len) override;

    bool op_statfs(virtq_unserializer &&msg, uint16_t tag);
    bool op_lopen(virtq_unserializer &&msg, uint16_t tag);
    bool op_lcreate(virtq_unserializer &&msg, uint16_t tag);
    bool op_symlink(virtq_unserializer &&msg, uint16_t tag);
    bool op_mknod(virtq_unserializer &&msg, uint16_t tag);
    bool op_readlink(virtq_unserializer &&msg, uint16_t tag);
    bool op_getattr(virtq_unserializer &&msg, uint16_t tag);
    bool op_setattr(virtq_unserializer &&msg, uint16_t tag);
    bool op_readdir(virtq_unserializer &&msg, uint16_t tag);
    bool op_fsync(virtq_unserializer &&msg, uint16_t tag);
    bool op_lock(virtq_unserializer &&msg, uint16_t tag);
    bool op_getlock(virtq_unserializer &&msg, uint16_t tag);
    bool op_link(virtq_unserializer &&msg, uint16_t tag);
    bool op_mkdir(virtq_unserializer &&msg, uint16_t tag);
    bool op_renameat(virtq_unserializer &&msg, uint16_t tag);
    bool op_unlinkat(virtq_unserializer &&msg, uint16_t tag);
    bool op_version(virtq_unserializer &&msg, uint16_t tag);
    bool op_attach(virtq_unserializer &&msg, uint16_t tag);
    bool op_walk(virtq_unserializer &&msg, uint16_t tag);
    bool op_read(virtq_unserializer &&msg, uint16_t tag);
    bool op_write(virtq_unserializer &&msg, uint16_t tag);
    bool op_clunk(virtq_unserializer &&msg, uint16_t tag);

    bool send_reply(virtq_serializer &&msg, uint16_t tag, p9_opcode opcode);
    bool send_ok(const virtq_unserializer &in_msg, uint16_t tag, p9_opcode opcode);
    bool send_error(const virtq_unserializer &in_msg, uint16_t tag, p9_error error);

    virtio_p9fs_config_space *get_config() {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        return reinterpret_cast<virtio_p9fs_config_space *>(config_space.data());
    }

    p9_fid_state *get_fid_state(uint32_t fid) {
        auto it = m_fids.find(fid);
        return (it != m_fids.end()) ? &it->second : nullptr;
    }

    uint32_t get_iounit() const {
        return std::min<uint32_t>(m_msize - P9_IOUNIT_HEADER_SIZE, P9_IOUNIT_MAX);
    }
};

} // namespace cartesi

#endif // HAVE_POSIX_FS

#endif
