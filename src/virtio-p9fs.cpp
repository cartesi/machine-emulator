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

/// \file
/// \brief VirtIO Plan 9 filesystem.
/// \details \{
///
/// The Plan 9 filesystem allows to share host directories
/// with the guest.
///
/// To mount a filesystem in the guest, execute the following command:
///
///   mount -t 9p vfs0 /mnt
///
/// Where "vfs0" is the mount tag chosen on device creation.
///
/// \}

// Enable this define to debug VirtIO Plan 9 filesystem operations
// #define DEBUG_VIRTIO_P9FS

#include "virtio-p9fs.h"

#ifdef HAVE_POSIX_FS

#include <cerrno>
#include <cstring>

#include <dirent.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#ifdef __APPLE__
#include <sys/mount.h>
#include <sys/param.h>
#else
#include <sys/statfs.h>
#include <sys/sysmacros.h>
#endif
#include <unistd.h>

namespace cartesi {

// Aliases for struct names that conflicts with function names
using stat_t = struct stat;
using statfs_t = struct statfs;
using flock_t = struct flock;

static p9_error host_errno_to_p9(int err) {
    switch (err) {
        case 0:
            return P9_EOK;
        case EPERM:
            return P9_EPERM;
        case ENOENT:
            return P9_ENOENT;
        case ESRCH:
            return P9_ESRCH;
        case EINTR:
            return P9_EINTR;
        case EIO:
            return P9_EIO;
        case ENXIO:
            return P9_ENXIO;
        case E2BIG:
            return P9_E2BIG;
        case ENOEXEC:
            return P9_ENOEXEC;
        case EBADF:
            return P9_EBADF;
        case ECHILD:
            return P9_ECHILD;
        case EAGAIN:
            return P9_EAGAIN;
        case ENOMEM:
            return P9_ENOMEM;
        case EACCES:
            return P9_EACCES;
        case EFAULT:
            return P9_EFAULT;
        case ENOTBLK:
            return P9_ENOTBLK;
        case EBUSY:
            return P9_EBUSY;
        case EEXIST:
            return P9_EEXIST;
        case EXDEV:
            return P9_EXDEV;
        case ENODEV:
            return P9_ENODEV;
        case ENOTDIR:
            return P9_ENOTDIR;
        case EISDIR:
            return P9_EISDIR;
        case EINVAL:
            return P9_EINVAL;
        case ENFILE:
            return P9_ENFILE;
        case EMFILE:
            return P9_EMFILE;
        case ENOTTY:
            return P9_ENOTTY;
        case ETXTBSY:
            return P9_ETXTBSY;
        case EFBIG:
            return P9_EFBIG;
        case ENOSPC:
            return P9_ENOSPC;
        case ESPIPE:
            return P9_ESPIPE;
        case EROFS:
            return P9_EROFS;
        case EMLINK:
            return P9_EMLINK;
        case EPIPE:
            return P9_EPIPE;
        case EDOM:
            return P9_EDOM;
        case ERANGE:
            return P9_ERANGE;
        case EDEADLK:
            return P9_EDEADLK;
        case ENAMETOOLONG:
            return P9_ENAMETOOLONG;
        case ENOLCK:
            return P9_ENOLCK;
        case ENOSYS:
            return P9_ENOSYS;
        case ENOTEMPTY:
            return P9_ENOTEMPTY;
        case ELOOP:
            return P9_ELOOP;
        case ENOMSG:
            return P9_ENOMSG;
        case EIDRM:
            return P9_EIDRM;
        case ENOSTR:
            return P9_ENOSTR;
        case ENODATA:
            return P9_ENODATA;
        case ETIME:
            return P9_ETIME;
        case ENOSR:
            return P9_ENOSR;
        case EREMOTE:
            return P9_EREMOTE;
        case ENOLINK:
            return P9_ENOLINK;
        case EPROTO:
            return P9_EPROTO;
        case EMULTIHOP:
            return P9_EMULTIHOP;
        case EBADMSG:
            return P9_EBADMSG;
        case EOVERFLOW:
            return P9_EOVERFLOW;
        case EILSEQ:
            return P9_EILSEQ;
        case EUSERS:
            return P9_EUSERS;
        case ENOTSOCK:
            return P9_ENOTSOCK;
        case EDESTADDRREQ:
            return P9_EDESTADDRREQ;
        case EMSGSIZE:
            return P9_EMSGSIZE;
        case EPROTOTYPE:
            return P9_EPROTOTYPE;
        case ENOPROTOOPT:
            return P9_ENOPROTOOPT;
        case EPROTONOSUPPORT:
            return P9_EPROTONOSUPPORT;
        case ESOCKTNOSUPPORT:
            return P9_ESOCKTNOSUPPORT;
        case EOPNOTSUPP:
            return P9_EOPNOTSUPP;
        case EPFNOSUPPORT:
            return P9_EPFNOSUPPORT;
        case EAFNOSUPPORT:
            return P9_EAFNOSUPPORT;
        case EADDRINUSE:
            return P9_EADDRINUSE;
        case EADDRNOTAVAIL:
            return P9_EADDRNOTAVAIL;
        case ENETDOWN:
            return P9_ENETDOWN;
        case ENETUNREACH:
            return P9_ENETUNREACH;
        case ENETRESET:
            return P9_ENETRESET;
        case ECONNABORTED:
            return P9_ECONNABORTED;
        case ECONNRESET:
            return P9_ECONNRESET;
        case ENOBUFS:
            return P9_ENOBUFS;
        case EISCONN:
            return P9_EISCONN;
        case ENOTCONN:
            return P9_ENOTCONN;
        case ESHUTDOWN:
            return P9_ESHUTDOWN;
        case ETOOMANYREFS:
            return P9_ETOOMANYREFS;
        case ETIMEDOUT:
            return P9_ETIMEDOUT;
        case ECONNREFUSED:
            return P9_ECONNREFUSED;
        case EHOSTDOWN:
            return P9_EHOSTDOWN;
        case EHOSTUNREACH:
            return P9_EHOSTUNREACH;
        case EALREADY:
            return P9_EALREADY;
        case EINPROGRESS:
            return P9_EINPROGRESS;
        case ESTALE:
            return P9_ESTALE;
        case EDQUOT:
            return P9_EDQUOT;
        case ECANCELED:
            return P9_ECANCELED;
        case EOWNERDEAD:
            return P9_EOWNERDEAD;
        case ENOTRECOVERABLE:
            return P9_ENOTRECOVERABLE;
#ifdef __APPLE__
        case ENOATTR:
            return P9_ENODATA;
        case ENOTSUP:
            return P9_EOPNOTSUPP;
#else
        case ECHRNG:
            return P9_ECHRNG;
        case EL2NSYNC:
            return P9_EL2NSYNC;
        case EL3HLT:
            return P9_EL3HLT;
        case EL3RST:
            return P9_EL3RST;
        case ELNRNG:
            return P9_ELNRNG;
        case EUNATCH:
            return P9_EUNATCH;
        case ENOCSI:
            return P9_ENOCSI;
        case EL2HLT:
            return P9_EL2HLT;
        case EBADE:
            return P9_EBADE;
        case EBADR:
            return P9_EBADR;
        case EXFULL:
            return P9_EXFULL;
        case ENOANO:
            return P9_ENOANO;
        case EBADRQC:
            return P9_EBADRQC;
        case EBADSLT:
            return P9_EBADSLT;
        case EBFONT:
            return P9_EBFONT;
        case ENONET:
            return P9_ENONET;
        case ENOPKG:
            return P9_ENOPKG;
        case EADV:
            return P9_EADV;
        case ESRMNT:
            return P9_ESRMNT;
        case ECOMM:
            return P9_ECOMM;
        case EDOTDOT:
            return P9_EDOTDOT;
        case ENOTUNIQ:
            return P9_ENOTUNIQ;
        case EBADFD:
            return P9_EBADFD;
        case EREMCHG:
            return P9_EREMCHG;
        case ELIBACC:
            return P9_ELIBACC;
        case ELIBBAD:
            return P9_ELIBBAD;
        case ELIBSCN:
            return P9_ELIBSCN;
        case ELIBMAX:
            return P9_ELIBMAX;
        case ELIBEXEC:
            return P9_ELIBEXEC;
        case ERESTART:
            return P9_ERESTART;
        case ESTRPIPE:
            return P9_ESTRPIPE;
        case EUCLEAN:
            return P9_EUCLEAN;
        case ENOTNAM:
            return P9_ENOTNAM;
        case ENAVAIL:
            return P9_ENAVAIL;
        case EISNAM:
            return P9_EISNAM;
        case EREMOTEIO:
            return P9_EREMOTEIO;
        case ENOMEDIUM:
            return P9_ENOMEDIUM;
        case EMEDIUMTYPE:
            return P9_EMEDIUMTYPE;
        case ENOKEY:
            return P9_ENOKEY;
        case EKEYEXPIRED:
            return P9_EKEYEXPIRED;
        case EKEYREVOKED:
            return P9_EKEYREVOKED;
        case EKEYREJECTED:
            return P9_EKEYREJECTED;
        case ERFKILL:
            return P9_ERFKILL;
        case EHWPOISON:
            return P9_EHWPOISON;
#endif
        default:
            return P9_EINVAL;
    }
}

static int p9_open_flags_to_host(uint32_t flags) {
    int oflags = 0;
    for (uint32_t i = 1; i <= P9_O_SYNC; i = i << 1) {
        if ((flags & i) != 0) {
            switch (i) {
                case P9_O_RDONLY:
                    oflags |= O_RDONLY;
                    break;
                case P9_O_WRONLY:
                    oflags |= O_WRONLY;
                    break;
                case P9_O_RDWR:
                    oflags |= O_RDWR;
                    break;
                case P9_O_CREAT:
                    oflags |= O_CREAT;
                    break;
                case P9_O_EXCL:
                    oflags |= O_EXCL;
                    break;
                case P9_O_NOCTTY:
                    oflags |= O_NOCTTY;
                    break;
                case P9_O_TRUNC:
                    oflags |= O_TRUNC;
                    break;
                case P9_O_APPEND:
                    oflags |= O_APPEND;
                    break;
                case P9_O_NONBLOCK:
                    oflags |= O_NONBLOCK;
                    break;
                case P9_O_DSYNC:
                    oflags |= O_DSYNC;
                    break;
                case P9_O_FASYNC:
                    oflags |= FASYNC;
                    break;
                case P9_O_DIRECTORY:
                    oflags |= O_DIRECTORY;
                    break;
                case P9_O_NOFOLLOW:
                    oflags |= O_NOFOLLOW;
                    break;
                case P9_O_CLOEXEC:
                    oflags |= O_CLOEXEC;
                    break;
                case P9_O_SYNC:
                    oflags |= O_SYNC;
                    break;
#ifndef __APPLE__
                case P9_O_DIRECT:
                    oflags |= O_DIRECT;
                    break;
                case P9_O_LARGEFILE:
                    oflags |= O_LARGEFILE;
                    break;
                case P9_O_NOATIME:
                    oflags |= O_NOATIME;
                    break;
#endif
                default:
                    break;
            }
        }
    }
    // Filter non-supported flags
    oflags &= ~(O_NOCTTY | O_ASYNC | O_CREAT);
    return oflags;
}

static int16_t p9_lock_type_to_host(uint8_t type) {
    switch (type) {
        case P9_LOCK_TYPE_RDLCK:
            return F_RDLCK;
        case P9_LOCK_TYPE_WRLCK:
            return F_WRLCK;
        case P9_LOCK_TYPE_UNLCK:
            return F_UNLCK;
        default:
            return -1;
    }
}

static uint8_t host_lock_type_to_p9(int16_t type) {
    switch (type) {
        case F_RDLCK:
            return P9_LOCK_TYPE_RDLCK;
        case F_WRLCK:
            return P9_LOCK_TYPE_WRLCK;
        case F_UNLCK:
            return P9_LOCK_TYPE_UNLCK;
        default:
            return 0xff;
    }
}

static p9_qid stat_to_qid(const stat_t &st) {
    p9_qid qid{};
    qid.type = P9_QID_FILE;
    if (S_ISDIR(st.st_mode)) {
        qid.type |= P9_QID_DIR;
    }
    if (S_ISLNK(st.st_mode)) {
        qid.type |= P9_QID_SYMLINK;
    }
    qid.version = 0; // No caching
    qid.path = st.st_ino;
    return qid;
}

static bool is_same_stat_ino(const stat_t *a, const stat_t *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino;
}

static int close_fid_state(p9_fid_state *fidp) {
    if (fidp == nullptr) {
        return 0;
    }
    int err = 0;
    if (fidp->dirp != nullptr) {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        DIR *dirp = reinterpret_cast<DIR *>(fidp->dirp);
        if (closedir(dirp) != 0) {
            err = errno;
        }
        fidp->dirp = nullptr;
    }
    if (fidp->fd >= 0) {
        if (close(fidp->fd) != 0) {
            err = errno;
        }
        fidp->fd = -1;
    }
    return err;
}

static std::string join_path_name(const std::string &path, const std::string &name) {
    if (path.empty()) {
        return name;
    }
    if (path[path.length() - 1] == '/') {
        return path + name;
    }
    std::string s;
    s.append(path);
    s.append("/");
    s.append(name);
    return s;
}

static std::string remove_path_name(const std::string &path) {
    const size_t pos = path.rfind('/');
    if (pos != std::string::npos && pos > 0) {
        return path.substr(0, pos);
    }
    return path;
}

static bool is_name_legal(const std::string &name) {
    if (name.empty()) {
        return false;
    }
    if (name.find('/') != std::string::npos) {
        return false;
    }
    if (name == "." || name == "..") {
        return false;
    }
    return true;
}

virtio_p9fs_device::virtio_p9fs_device(uint32_t virtio_idx, const std::string &mount_tag,
    const std::string &root_path) :
    virtio_device(virtio_idx, VIRTIO_DEVICE_9P, VIRTIO_9P_F_MOUNT_TAG, mount_tag.length() + sizeof(uint16_t)),
    m_msize(P9_MAX_MSIZE),
    m_root_path(root_path) {
    if (root_path.length() + 1 >= P9_ROOT_PATH_MAX) {
        throw std::runtime_error{"host directory length is too large"};
    }
    if (mount_tag.length() >= P9_MOUNT_TAG_MAX) {
        throw std::runtime_error{"host directory mount tag length is too large"};
    }
    stat_t st{};
    if (stat(root_path.c_str(), &st) < 0 || !S_ISDIR(st.st_mode)) {
        throw std::runtime_error{"host directory '" + root_path + "' is not a valid directory"};
    }
    // Initialize config space
    virtio_p9fs_config_space *config = get_config();
    strncpy(config->mount_tag.data(), mount_tag.c_str(), mount_tag.length());
    config->mount_tag_len = mount_tag.length();
}

virtio_p9fs_device::~virtio_p9fs_device() {
    // Close all file descriptors
    for (auto &it : m_fids) {
        p9_fid_state *fidp = &it.second;
        close_fid_state(fidp);
    }
    m_fids.clear();
}

void virtio_p9fs_device::on_device_reset() {
    m_msize = P9_MAX_MSIZE;
    // Close all file descriptors
    for (auto &it : m_fids) {
        p9_fid_state *fidp = &it.second;
        close_fid_state(fidp);
    }
    m_fids.clear();
}

void virtio_p9fs_device::on_device_ok(i_device_state_access * /*a*/) {
    // Nothing to do.
}

bool virtio_p9fs_device::on_device_queue_available(i_device_state_access *a, uint32_t queue_idx, uint16_t desc_idx,
    uint32_t /*read_avail_len*/, uint32_t /*write_avail_len*/) {
    // We are only interested in queue 0 notifications
    if (queue_idx != 0) {
        return false;
    }
    virtq_unserializer msg(a, queue[queue_idx], queue_idx, desc_idx);
    uint32_t size{};
    uint8_t opcode{};
    uint16_t tag{};
    if (!msg.unpack(&size, &opcode, &tag)) {
        notify_device_needs_reset(a);
        return false;
    }
    // Some operations may allocate temporary strings or grow the fids unordered map,
    // which can theoretically throw std::bad_alloc exceptions (although very unlikely).
    // We don't want any exception to leak outside this function, so we try to catch any exception here.
    try {
        switch (opcode) {
            case P9_TSTATFS:
                return op_statfs(std::move(msg), tag);
            case P9_TLOPEN:
                return op_lopen(std::move(msg), tag);
            case P9_TLCREATE:
                return op_lcreate(std::move(msg), tag);
            case P9_TSYMLINK:
                return op_symlink(std::move(msg), tag);
            case P9_TMKNOD:
                return op_mknod(std::move(msg), tag);
            case P9_TREADLINK:
                return op_readlink(std::move(msg), tag);
            case P9_TGETATTR:
                return op_getattr(std::move(msg), tag);
            case P9_TSETATTR:
                return op_setattr(std::move(msg), tag);
            case P9_TREADDIR:
                return op_readdir(std::move(msg), tag);
            case P9_TFSYNC:
                return op_fsync(std::move(msg), tag);
            case P9_TLOCK:
                return op_lock(std::move(msg), tag);
            case P9_TGETLOCK:
                return op_getlock(std::move(msg), tag);
            case P9_TLINK:
                return op_link(std::move(msg), tag);
            case P9_TMKDIR:
                return op_mkdir(std::move(msg), tag);
            case P9_TRENAMEAT:
                return op_renameat(std::move(msg), tag);
            case P9_TUNLINKAT:
                return op_unlinkat(std::move(msg), tag);
            case P9_TVERSION:
                return op_version(std::move(msg), tag);
            case P9_TATTACH:
                return op_attach(std::move(msg), tag);
            case P9_TWALK:
                return op_walk(std::move(msg), tag);
            case P9_TREAD:
                return op_read(std::move(msg), tag);
            case P9_TWRITE:
                return op_write(std::move(msg), tag);
            case P9_TCLUNK:
                return op_clunk(std::move(msg), tag);
            // The following opcode are not needed or unsupported.
            case P9_TERROR:       // The driver will never send errors
            case P9_TXATTRWALK:   // File extended attributes is not supported yet
            case P9_TXATTRCREATE: // File extended attributes is not supported yet
            case P9_TAUTH:        // Authentication is not supported
            case P9_TFLUSH:       // Asynchronous requests is not supported
            case P9_TSTAT:        // Replaced by P9_TGETATTR in 9P2000.L
            case P9_TWSTAT:       // Replaced by P9_TSETATTR in 9P2000.L
            case P9_TOPEN:        // Replaced by P9_TLOPEN in 9P2000.L
            case P9_TRENAME:      // Replaced by P9_TRENAMEAT in 9P2000.L
            case P9_TCREATE:      // Replaced by P9_TLCREATE in 9P2000.L
            case P9_TREMOVE:      // Replaced by P9_TUNLINKAT in 9P2000.L
#ifdef DEBUG_VIRTIO_P9FS
                std::ignore = fprintf(stderr, "p9fs unsupported: tag=%d opcode=%d size=%d\n", tag, opcode, size);
#endif
                return send_error(msg, tag, P9_EOPNOTSUPP);
            default:
#ifdef DEBUG_VIRTIO_P9FS
                std::ignore = fprintf(stderr, "p9fs UNEXPECTED: tag=%d opcode=%d size=%d\n", tag, opcode, size);
#endif
                return send_error(msg, tag, P9_EPROTO);
        }
    } catch (std::bad_alloc &e) {
        // Both std::string and std::unordered_map may throw std::bad_alloc when out of memory
        return send_error(msg, tag, P9_EOPNOTSUPP);
    } catch (...) {
        // Some other unexpected exception
        return send_error(msg, tag, P9_EPROTO);
    }
}

bool virtio_p9fs_device::op_statfs(virtq_unserializer &&mmsg, uint16_t tag) {
    virtq_unserializer msg = std::move(mmsg);
    uint32_t fid{};
    if (!msg.unpack(&fid)) {
        return send_error(msg, tag, P9_EPROTO);
    }
#ifdef DEBUG_VIRTIO_P9FS
    std::ignore = fprintf(stderr, "p9fs statfs: tag=%d fid=%d\n", tag, fid);
#endif
    // Get the fid state
    p9_fid_state *fidp = get_fid_state(fid);
    if (fidp == nullptr) {
        return send_error(msg, tag, P9_EPROTO);
    }
    statfs_t stfs{};
    // Use fd when available, because its path might have been removed while fd still open
    if (fidp->fd >= 0) {
        // Get the filesystem statistics
        if (fstatfs(fidp->fd, &stfs) < 0) {
            return send_error(msg, tag, host_errno_to_p9(errno));
        }
    } else {
        // Get the filesystem statistics
        if (statfs(fidp->path.c_str(), &stfs) < 0) {
            return send_error(msg, tag, host_errno_to_p9(errno));
        }
    }
    auto type = static_cast<uint32_t>(stfs.f_type);
    auto bsize = static_cast<uint32_t>(stfs.f_bsize);
    auto blocks = static_cast<uint64_t>(stfs.f_blocks);
    auto bfree = static_cast<uint64_t>(stfs.f_bfree);
    auto bavail = static_cast<uint64_t>(stfs.f_bavail);
    auto files = static_cast<uint64_t>(stfs.f_files);
    auto ffree = static_cast<uint64_t>(stfs.f_ffree);
#ifdef __APPLE__
    uint64_t fsid = static_cast<uint64_t>(stfs.f_fsid.val[0]) | (static_cast<uint64_t>(stfs.f_fsid.val[1]) << 32);
    uint32_t namelen =
        std::min<uint32_t>(static_cast<uint32_t>(NAME_MAX), P9_NAME_MAX); // f_namelen does not exist on Darwin
#else
    uint64_t fsid = static_cast<uint64_t>(stfs.f_fsid.__val[0]) | (static_cast<uint64_t>(stfs.f_fsid.__val[1]) << 32);
    uint32_t namelen = std::min<uint32_t>(static_cast<uint32_t>(stfs.f_namelen), P9_NAME_MAX);
#endif
    // Reply
    virtq_serializer out_msg(msg.a, msg.vq, msg.queue_idx, msg.desc_idx, P9_OUT_MSG_OFFSET);
    if (!out_msg.pack(&type, &bsize, &blocks, &bfree, &bavail, &files, &ffree, &fsid, &namelen)) {
        return send_error(msg, tag, P9_EPROTO);
    }
    return send_reply(std::move(out_msg), tag, P9_RSTATFS);
}

bool virtio_p9fs_device::op_lopen(virtq_unserializer &&mmsg, uint16_t tag) {
    virtq_unserializer msg = std::move(mmsg);
    uint32_t fid{};
    uint32_t flags{};
    if (!msg.unpack(&fid, &flags)) {
        return send_error(msg, tag, P9_EPROTO);
    }
#ifdef DEBUG_VIRTIO_P9FS
    std::ignore = fprintf(stderr, "p9fs lopen: tag=%d fid=%d flags=%d\n", tag, fid, flags);
#endif
    // Get the fid state
    p9_fid_state *fidp = get_fid_state(fid);
    if (fidp == nullptr) {
        return send_error(msg, tag, P9_EPROTO);
    }
    // It's an error if the fid is already open
    if (fidp->fd >= 0) {
        return send_error(msg, tag, P9_EPROTO);
    }
    // Open the file
    const int oflags = p9_open_flags_to_host(flags);
    const int fd = open(fidp->path.c_str(), oflags);
    if (fd < 0) {
        return send_error(msg, tag, host_errno_to_p9(errno));
    }
    // Get the path qid
    stat_t st{};
    if (fstat(fd, &st) != 0) {
        std::ignore = close(fd);
        return send_error(msg, tag, host_errno_to_p9(errno));
    }
    p9_qid qid = stat_to_qid(st);
    // Reply
    uint32_t iounit = get_iounit();
    virtq_serializer out_msg(msg.a, msg.vq, msg.queue_idx, msg.desc_idx, P9_OUT_MSG_OFFSET);
    if (!out_msg.pack(&qid, &iounit)) {
        std::ignore = close(fd);
        return send_error(msg, tag, P9_EPROTO);
    }
    if (!send_reply(std::move(out_msg), tag, P9_RLOPEN)) {
        std::ignore = close(fd);
        return false;
    }
    // Update fid
    fidp->fd = fd;
    return true;
}

bool virtio_p9fs_device::op_lcreate(virtq_unserializer &&mmsg, uint16_t tag) {
    virtq_unserializer msg = std::move(mmsg);
    uint32_t fid{};
    uint32_t flags{};
    uint32_t mode{};
    uint32_t gid{};
    char name[P9_NAME_MAX]{};
    if (!msg.unpack(&fid, &name, &flags, &mode, &gid)) {
        return send_error(msg, tag, P9_EPROTO);
    }
#ifdef DEBUG_VIRTIO_P9FS
    std::ignore = fprintf(stderr, "p9fs lcreate: tag=%d fid=%d name=%s flags=%d mode=%d gid=%d\n", tag, fid, name,
        flags, mode, gid);
#endif
    // Check if name is valid
    if (!is_name_legal(name)) {
        return send_error(msg, tag, P9_ENOENT);
    }
    // Get the fid state
    p9_fid_state *fidp = get_fid_state(fid);
    if (fidp == nullptr) {
        return send_error(msg, tag, P9_EPROTO);
    }
    // It's an error if the fid is already open
    if (fidp->fd >= 0) {
        return send_error(msg, tag, P9_EPROTO);
    }
    // Create the file
    const std::string path = join_path_name(fidp->path, name);
    const int oflags = p9_open_flags_to_host(flags) | O_CREAT;
    const auto omode = static_cast<mode_t>(mode);
    const int fd = open(path.c_str(), oflags, omode);
    if (fd < 0) {
        return send_error(msg, tag, host_errno_to_p9(errno));
    }
    // If we fail to change ownership, we silent ignore the error
    if (fchown(fd, static_cast<uid_t>(fidp->uid), static_cast<gid_t>(gid)) != 0) {
        errno = 0;
    }
    // Get the path qid
    stat_t st{};
    if (fstat(fd, &st) != 0) {
        std::ignore = close(fd);
        std::ignore = unlink(path.c_str());
        return send_error(msg, tag, host_errno_to_p9(errno));
    }
    p9_qid qid = stat_to_qid(st);
    // Reply
    uint32_t iounit = get_iounit();
    virtq_serializer out_msg(msg.a, msg.vq, msg.queue_idx, msg.desc_idx, P9_OUT_MSG_OFFSET);
    if (!out_msg.pack(&qid, &iounit)) {
        std::ignore = close(fd);
        std::ignore = unlink(path.c_str());
        return send_error(msg, tag, P9_EPROTO);
    }
    if (!send_reply(std::move(out_msg), tag, P9_RLCREATE)) {
        std::ignore = close(fd);
        std::ignore = unlink(path.c_str());
        return false;
    }
    // Update fid to represent the newly opened file
    fidp->path = path;
    fidp->fd = fd;
    return true;
}

bool virtio_p9fs_device::op_symlink(virtq_unserializer &&mmsg, uint16_t tag) {
    virtq_unserializer msg = std::move(mmsg);
    uint32_t dfid{};
    uint32_t gid{};
    char name[P9_NAME_MAX]{};
    char symtgt[P9_PATH_MAX]{};
    if (!msg.unpack(&dfid, &name, &symtgt, &gid)) {
        return send_error(msg, tag, P9_EPROTO);
    }
#ifdef DEBUG_VIRTIO_P9FS
    std::ignore =
        fprintf(stderr, "p9fs symlink: tag=%d dfid=%d name=%s symtgt=%s gid=%d\n", tag, dfid, name, symtgt, gid);
#endif
    // Check if name is valid
    if (!is_name_legal(name)) {
        return send_error(msg, tag, P9_ENOENT);
    }
    // Get the fid state
    p9_fid_state *dfidp = get_fid_state(dfid);
    if (dfidp == nullptr) {
        return send_error(msg, tag, P9_EPROTO);
    }
    // Create the symlink
    const std::string path = join_path_name(dfidp->path, name);
    if (symlink(symtgt, path.c_str()) != 0) {
        return send_error(msg, tag, host_errno_to_p9(errno));
    }
    // If we fail to change ownership, we silent ignore the error
    if (lchown(path.c_str(), static_cast<uid_t>(dfidp->uid), static_cast<gid_t>(gid)) != 0) {
        errno = 0;
    }
    // Get the path qid
    stat_t st{};
    if (lstat(path.c_str(), &st) != 0) {
        std::ignore = unlink(path.c_str());
        return send_error(msg, tag, host_errno_to_p9(errno));
    }
    p9_qid qid = stat_to_qid(st);
    // Reply
    virtq_serializer out_msg(msg.a, msg.vq, msg.queue_idx, msg.desc_idx, P9_OUT_MSG_OFFSET);
    if (!out_msg.pack(&qid)) {
        std::ignore = unlink(path.c_str());
        return send_error(msg, tag, P9_EPROTO);
    }
    if (!send_reply(std::move(out_msg), tag, P9_RSYMLINK)) {
        std::ignore = unlink(path.c_str());
        return false;
    }
    return true;
}

bool virtio_p9fs_device::op_mknod(virtq_unserializer &&mmsg, uint16_t tag) {
    virtq_unserializer msg = std::move(mmsg);
    uint32_t dfid{};
    uint32_t mode{};
    uint32_t major{};
    uint32_t minor{};
    uint32_t gid{};
    char name[P9_NAME_MAX]{};
    if (!msg.unpack(&dfid, &name, &mode, &major, &minor, &gid)) {
        return send_error(msg, tag, P9_EPROTO);
    }
#ifdef DEBUG_VIRTIO_P9FS
    std::ignore = fprintf(stderr, "p9fs mknod: tag=%d dfid=%d name=%s mode=%d major=%d minor=%d gid=%d\n", tag, dfid,
        name, mode, major, minor, gid);
#endif
    // Check if name is valid
    if (!is_name_legal(name)) {
        return send_error(msg, tag, P9_ENOENT);
    }
    // Get the fid state
    p9_fid_state *dfidp = get_fid_state(dfid);
    if (dfidp == nullptr) {
        return send_error(msg, tag, P9_EPROTO);
    }
    // Create the special or ordinary file
    const std::string path = join_path_name(dfidp->path, name);
    const dev_t dev = makedev(major, minor);
    if (mknod(path.c_str(), static_cast<mode_t>(mode), dev) != 0) {
        return send_error(msg, tag, host_errno_to_p9(errno));
    }
    // If we fail to change ownership, we silent ignore the error
    if (lchown(path.c_str(), static_cast<uid_t>(dfidp->uid), static_cast<gid_t>(gid)) != 0) {
        errno = 0;
    }
    // Get the path qid
    stat_t st{};
    if (lstat(path.c_str(), &st) != 0) {
        std::ignore = unlink(path.c_str());
        return send_error(msg, tag, host_errno_to_p9(errno));
    }
    p9_qid qid = stat_to_qid(st);
    // Reply
    virtq_serializer out_msg(msg.a, msg.vq, msg.queue_idx, msg.desc_idx, P9_OUT_MSG_OFFSET);
    if (!out_msg.pack(&qid)) {
        std::ignore = unlink(path.c_str());
        return send_error(msg, tag, P9_EPROTO);
    }
    if (!send_reply(std::move(out_msg), tag, P9_RMKNOD)) {
        std::ignore = unlink(path.c_str());
        return false;
    }
    return true;
}

bool virtio_p9fs_device::op_setattr(virtq_unserializer &&mmsg, uint16_t tag) {
    virtq_unserializer msg = std::move(mmsg);
    uint32_t fid{};
    uint32_t mask{};
    uint32_t mode{};
    uint32_t uid{};
    uint32_t gid{};
    uint64_t size{};
    uint64_t atime_sec{};
    uint64_t atime_nsec{};
    uint64_t mtime_sec{};
    uint64_t mtime_nsec{};
    if (!msg.unpack(&fid, &mask, &mode, &uid, &gid, &size, &atime_sec, &atime_nsec, &mtime_sec, &mtime_nsec)) {
        return send_error(msg, tag, P9_EPROTO);
    }
#ifdef DEBUG_VIRTIO_P9FS
    std::ignore = fprintf(stderr,
        "p9fs setattr: tag=%d fid=%d mask=%d uid=%d gid=%d size=%ld atime_sec=%ld atime_nsec=%ld mtime_sec=%ld "
        "mtime_nsec=%ld\n",
        tag, fid, mask, uid, gid, size, atime_sec, atime_nsec, mtime_sec, mtime_nsec);
#endif
    // Get the fid state
    const p9_fid_state *fidp = get_fid_state(fid);
    if (fidp == nullptr) {
        return send_error(msg, tag, P9_EPROTO);
    }
    bool ctime_updated = false;
    // Modify ownership
    if ((mask & (P9_SETATTR_UID | P9_SETATTR_GID)) != 0) {
        const uid_t newuid = ((mask & P9_SETATTR_UID) != 0) ? static_cast<uid_t>(uid) : -1;
        const gid_t newgid = ((mask & P9_SETATTR_GID) != 0) ? static_cast<gid_t>(gid) : -1;
        // Use fd when available, because its path might have been removed while fd still open
        if (fidp->fd >= 0) {
            if (fchown(fidp->fd, newuid, newgid) != 0) {
                return send_error(msg, tag, host_errno_to_p9(errno));
            }
        } else {
            if (lchown(fidp->path.c_str(), newuid, newgid) != 0) {
                return send_error(msg, tag, host_errno_to_p9(errno));
            }
        }
        ctime_updated = true;
    }
    // Modify mode
    if ((mask & P9_SETATTR_MODE) != 0) {
        // Use fd when available, because its path might have been removed while fd still open
        if (fidp->fd >= 0) {
            if (fchmod(fidp->fd, static_cast<mode_t>(mode)) != 0) {
                return send_error(msg, tag, host_errno_to_p9(errno));
            }
        } else {
            if (chmod(fidp->path.c_str(), static_cast<mode_t>(mode)) != 0) {
                return send_error(msg, tag, host_errno_to_p9(errno));
            }
        }
        ctime_updated = true;
    }
    // Modify size
    if ((mask & P9_SETATTR_SIZE) != 0) {
        // Use fd when available, because its path might have been removed while fd still open
        if (fidp->fd >= 0) {
            if (ftruncate(fidp->fd, static_cast<off_t>(size)) != 0) {
                return send_error(msg, tag, host_errno_to_p9(errno));
            }
        } else {
            if (truncate(fidp->path.c_str(), static_cast<off_t>(size)) != 0) {
                return send_error(msg, tag, host_errno_to_p9(errno));
            }
        }
        ctime_updated = true;
    }
    // Modify times
    if ((mask & (P9_SETATTR_ATIME | P9_SETATTR_MTIME)) != 0) {
        timespec ts[2]{};
        if ((mask & P9_SETATTR_ATIME) != 0) {
            if ((mask & P9_SETATTR_ATIME_SET) != 0) {
                ts[0].tv_sec = static_cast<time_t>(atime_sec);
                ts[0].tv_nsec = static_cast<int64_t>(atime_nsec);
            } else {
                ts[0].tv_sec = 0;
                ts[0].tv_nsec = UTIME_NOW;
            }
        } else {
            ts[0].tv_sec = 0;
            ts[0].tv_nsec = UTIME_OMIT;
        }
        if ((mask & P9_SETATTR_MTIME) != 0) {
            if ((mask & P9_SETATTR_MTIME_SET) != 0) {
                ts[1].tv_sec = static_cast<time_t>(mtime_sec);
                ts[1].tv_nsec = static_cast<int64_t>(mtime_nsec);
            } else {
                ts[1].tv_sec = 0;
                ts[1].tv_nsec = UTIME_NOW;
            }
        } else {
            ts[1].tv_sec = 0;
            ts[1].tv_nsec = UTIME_OMIT;
        }
        // Use fd when available, because its path might have been removed while fd still open
        if (fidp->fd >= 0) {
            if (futimens(fidp->fd, ts) != 0) {
                return send_error(msg, tag, host_errno_to_p9(errno));
            }
        } else {
            if (utimensat(AT_FDCWD, fidp->path.c_str(), ts, AT_SYMLINK_NOFOLLOW) != 0) {
                return send_error(msg, tag, host_errno_to_p9(errno));
            }
        }
        ctime_updated = true;
    }
    // Modify change time
    if (((mask & P9_SETATTR_CTIME) != 0) && !ctime_updated) {
        // Use fd when available, because its path might have been removed while fd still open
        if (fidp->fd >= 0) {
            if (fchown(fidp->fd, -1, -1) != 0) {
                return send_error(msg, tag, host_errno_to_p9(errno));
            }
        } else {
            if (lchown(fidp->path.c_str(), -1, -1) != 0) {
                return send_error(msg, tag, host_errno_to_p9(errno));
            }
        }
    }
    // Reply
    return send_ok(msg, tag, P9_RSETATTR);
}

bool virtio_p9fs_device::op_readlink(virtq_unserializer &&mmsg, uint16_t tag) {
    virtq_unserializer msg = std::move(mmsg);
    uint32_t fid{};
    if (!msg.unpack(&fid)) {
        return send_error(msg, tag, P9_EPROTO);
    }
#ifdef DEBUG_VIRTIO_P9FS
    std::ignore = fprintf(stderr, "p9fs readlink: tag=%d fid=%d\n", tag, fid);
#endif
    // Get the fid state
    const p9_fid_state *fidp = get_fid_state(fid);
    if (fidp == nullptr) {
        return send_error(msg, tag, P9_EPROTO);
    }
    // Read the link
    char target[P9_PATH_MAX]{};
    const ssize_t ret = readlink(fidp->path.c_str(), target, sizeof(target) - 1);
    if (ret < 0) {
        return send_error(msg, tag, host_errno_to_p9(errno));
    }
    target[ret] = 0;
    // Reply
    virtq_serializer out_msg(msg.a, msg.vq, msg.queue_idx, msg.desc_idx, P9_OUT_MSG_OFFSET);
    if (!out_msg.pack(target)) {
        return send_error(msg, tag, P9_EPROTO);
    }
    return send_reply(std::move(out_msg), tag, P9_RREADLINK);
}

bool virtio_p9fs_device::op_getattr(virtq_unserializer &&mmsg, uint16_t tag) {
    virtq_unserializer msg = std::move(mmsg);
    uint32_t fid{};
    uint64_t mask{};
    if (!msg.unpack(&fid, &mask)) {
        return send_error(msg, tag, P9_EPROTO);
    }
#ifdef DEBUG_VIRTIO_P9FS
    std::ignore = fprintf(stderr, "p9fs getattr: tag=%d fid=%d mask=%lx\n", tag, fid, mask);
#endif
    // Get the fid state
    const p9_fid_state *fidp = get_fid_state(fid);
    if (fidp == nullptr) {
        return send_error(msg, tag, P9_EPROTO);
    }
    stat_t st{};
    // Use fd when available, because its path might have been removed while fd still open
    if (fidp->fd >= 0) {
        // Get the attributes
        if (fstat(fidp->fd, &st) != 0) {
            return send_error(msg, tag, host_errno_to_p9(errno));
        }
    } else {
        // Get the attributes
        if (lstat(fidp->path.c_str(), &st) != 0) {
            return send_error(msg, tag, host_errno_to_p9(errno));
        }
    }
    // Get the qid
    p9_qid qid = stat_to_qid(st);
    // Fill stat attributes
    p9_stat rstat{};
    if ((mask & P9_GETATTR_MODE) != 0) {
        rstat.mode = st.st_mode;
    }
    if ((mask & P9_GETATTR_UID) != 0) {
        rstat.uid = st.st_uid;
    }
    if ((mask & P9_GETATTR_GID) != 0) {
        rstat.gid = st.st_gid;
    }
    if ((mask & P9_GETATTR_NLINK) != 0) {
        rstat.nlink = st.st_nlink;
    }
    if ((mask & P9_GETATTR_RDEV) != 0) {
        rstat.rdev = st.st_rdev;
    }
    if ((mask & P9_GETATTR_SIZE) != 0) {
        rstat.size = st.st_size;
    }
    if ((mask & P9_GETATTR_BLOCKS) != 0) {
        rstat.blksize = st.st_blksize;
        rstat.blocks = st.st_blocks;
    }
#ifdef __APPLE__
    if (mask & P9_GETATTR_ATIME) {
        rstat.atime_sec = st.st_atimespec.tv_sec;
        rstat.atime_nsec = st.st_atimespec.tv_nsec;
    }
    if (mask & P9_GETATTR_MTIME) {
        rstat.mtime_sec = st.st_mtimespec.tv_sec;
        rstat.mtime_nsec = st.st_mtimespec.tv_nsec;
    }
    if (mask & P9_GETATTR_CTIME) {
        rstat.ctime_sec = st.st_ctimespec.tv_sec;
        rstat.ctime_nsec = st.st_ctimespec.tv_nsec;
    }
#else
    if ((mask & P9_GETATTR_ATIME) != 0) {
        rstat.atime_sec = st.st_atim.tv_sec;
        rstat.atime_nsec = st.st_atim.tv_nsec;
    }
    if ((mask & P9_GETATTR_MTIME) != 0) {
        rstat.mtime_sec = st.st_mtim.tv_sec;
        rstat.mtime_nsec = st.st_mtim.tv_nsec;
    }
    if ((mask & P9_GETATTR_CTIME) != 0) {
        rstat.ctime_sec = st.st_ctim.tv_sec;
        rstat.ctime_nsec = st.st_ctim.tv_nsec;
    }
#endif
    // P9_GETATTR_BTIME, P9_GETATTR_GEN, P9_GETATTR_DATA_VERSION are not supported, they are hardwired to zero.
    // P9_GETATTR_INO is contained in qid.
    // Reply
    virtq_serializer out_msg(msg.a, msg.vq, msg.queue_idx, msg.desc_idx, P9_OUT_MSG_OFFSET);
    if (!out_msg.pack(&mask, &qid, &rstat)) {
        return send_error(msg, tag, P9_EPROTO);
    }
    return send_reply(std::move(out_msg), tag, P9_RGETATTR);
}

bool virtio_p9fs_device::op_lock(virtq_unserializer &&mmsg, uint16_t tag) {
    virtq_unserializer msg = std::move(mmsg);
    uint32_t fid{};
    uint8_t type{};
    uint32_t flags{};
    uint64_t start{};
    uint64_t length{};
    uint32_t proc_id{};
    char client_id[P9_NAME_MAX]{};
    if (!msg.unpack(&fid, &type, &flags, &start, &length, &proc_id, &client_id)) {
        return send_error(msg, tag, P9_EPROTO);
    }
#ifdef DEBUG_VIRTIO_P9FS
    std::ignore =
        fprintf(stderr, "p9fs lock: tag=%d fid=%d type=%d flags=%d start=%ld length=%ld proc_id=%d client_id=%s\n", tag,
            fid, type, flags, start, length, proc_id, client_id);
#endif
    // Only block flag is supported
    if (flags > P9_LOCK_FLAGS_BLOCK) {
        return send_error(msg, tag, P9_EINVAL);
    }
    // Get the fid state
    p9_fid_state *fidp = get_fid_state(fid);
    if ((fidp == nullptr) || fidp->fd < 0) {
        return send_error(msg, tag, P9_EPROTO);
    }
    // Lock the file
    flock_t fl{};
    fl.l_type = p9_lock_type_to_host(type);
    fl.l_whence = SEEK_SET;
    fl.l_start = static_cast<off_t>(start);
    fl.l_len = static_cast<off_t>(length);
    uint8_t status = P9_LOCK_SUCCESS;
    if ((flags & P9_LOCK_FLAGS_BLOCK) != 0) {
        // Blocking lock
        if (fcntl(fidp->fd, F_SETLKW, &fl) == -1) {
            status = P9_LOCK_ERROR;
        }
    } else {
        // Non-blocking lock
        if (fcntl(fidp->fd, F_SETLK, &fl) == -1) {
            status = P9_LOCK_SUCCESS;
        } else if (errno == EAGAIN || errno == EACCES) {
            status = P9_LOCK_BLOCKED;
        }
    }
    // Reply
    virtq_serializer out_msg(msg.a, msg.vq, msg.queue_idx, msg.desc_idx, P9_OUT_MSG_OFFSET);
    if (!out_msg.pack(&status)) {
        return send_error(msg, tag, P9_EPROTO);
    }
    return send_reply(std::move(out_msg), tag, P9_RLOCK);
}

bool virtio_p9fs_device::op_getlock(virtq_unserializer &&mmsg, uint16_t tag) {
    virtq_unserializer msg = std::move(mmsg);
    uint32_t fid{};
    uint8_t type{};
    uint64_t start{};
    uint64_t length{};
    uint32_t proc_id{};
    char client_id[P9_NAME_MAX]{};
    if (!msg.unpack(&fid, &type, &start, &length, &proc_id, &client_id)) {
        return send_error(msg, tag, P9_EPROTO);
    }
#ifdef DEBUG_VIRTIO_P9FS
    std::ignore = fprintf(stderr, "p9fs getlock: tag=%d fid=%d type=%d start=%ld length=%ld proc_id=%d client_id=%s\n",
        tag, fid, type, start, length, proc_id, client_id);
#endif
    // Get the fid state
    p9_fid_state *fidp = get_fid_state(fid);
    if ((fidp == nullptr) || fidp->fd < 0) {
        return send_error(msg, tag, P9_EPROTO);
    }
    // Lock the file
    flock_t fl{};
    fl.l_type = p9_lock_type_to_host(type);
    fl.l_whence = SEEK_SET;
    fl.l_start = static_cast<off_t>(start);
    fl.l_len = static_cast<off_t>(length);
    if (fcntl(fidp->fd, F_GETLK, &fl) == -1) {
        return send_error(msg, tag, host_errno_to_p9(errno));
    }
    uint8_t lock_type = host_lock_type_to_p9(fl.l_type);
    auto lock_start = static_cast<uint64_t>(fl.l_start);
    auto lock_length = static_cast<uint64_t>(fl.l_len);
    // Reply
    virtq_serializer out_msg(msg.a, msg.vq, msg.queue_idx, msg.desc_idx, P9_OUT_MSG_OFFSET);
    if (!out_msg.pack(&lock_type, &lock_start, &lock_length, &proc_id, &client_id)) {
        return send_error(msg, tag, P9_EPROTO);
    }
    return send_reply(std::move(out_msg), tag, P9_RGETLOCK);
}

bool virtio_p9fs_device::op_readdir(virtq_unserializer &&mmsg, uint16_t tag) {
    virtq_unserializer msg = std::move(mmsg);
    uint32_t fid{};
    uint64_t offset{};
    uint32_t count{};
    if (!msg.unpack(&fid, &offset, &count)) {
        return send_error(msg, tag, P9_EPROTO);
    }
#ifdef DEBUG_VIRTIO_P9FS
    std::ignore = fprintf(stderr, "p9fs readdir: tag=%d fid=%d offset=%ld count=%d\n", tag, fid, offset, count);
#endif
    // Get the fid state
    p9_fid_state *fidp = get_fid_state(fid);
    if (fidp == nullptr) {
        return send_error(msg, tag, P9_EPROTO);
    }
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    DIR *dirp = reinterpret_cast<DIR *>(fidp->dirp);
    // Open directory in case it's not yet
    if (dirp == nullptr) {
        dirp = opendir(fidp->path.c_str());
        if (dirp == nullptr) {
            return send_error(msg, tag, host_errno_to_p9(errno));
        }
        fidp->dirp = dirp;
    }
    constexpr uint32_t start_offset = P9_OUT_MSG_OFFSET + sizeof(uint32_t);
    virtq_serializer out_msg(msg.a, msg.vq, msg.queue_idx, msg.desc_idx, start_offset);
    // Seek directory
    if (offset == 0) {
        rewinddir(dirp);
    } else {
        seekdir(dirp, static_cast<int64_t>(offset));
    }
    // Traverse directory entries
    while (true) {
        const bool first_entry = (msg.offset == start_offset);
        // Get the next directory entry
        errno = 0;
        dirent *dir_entry = readdir(dirp);
        if (dir_entry == nullptr) {
            if (errno != 0 && first_entry) {
                return send_error(msg, tag, host_errno_to_p9(errno));
            }
            break;
        }
        const char *name = dir_entry->d_name;
        // Check if there is enough space to add this entry
        const uint32_t data_len = out_msg.offset - start_offset;
        const uint32_t entry_len =
            sizeof(p9_qid) + sizeof(uint64_t) + sizeof(uint8_t) + +sizeof(uint16_t) + strlen(name);
        if (data_len + entry_len > count) {
            break;
        }
        // Get entry offset
        const int64_t entry_off = telldir(dirp);
        if (entry_off < 0) {
            if (first_entry) {
                return send_error(msg, tag, host_errno_to_p9(errno));
            }
            break;
        }
        // Get entry qid and type
        p9_qid qid{};
        uint8_t type = dir_entry->d_type;
        // In some filesystems dtype may be DT_UNKNOWN as an optimization to save lstat() calls
        if (type == DT_UNKNOWN) {
            stat_t st{};
            const std::string path = join_path_name(fidp->path, dir_entry->d_name);
            if (lstat(path.c_str(), &st) < 0) {
                if (errno != 0 && first_entry) {
                    return send_error(msg, tag, host_errno_to_p9(errno));
                }
                break;
            }
            type = st.st_mode >> 12;
            qid = stat_to_qid(st);
        } else {
            if (type == DT_DIR) {
                qid.type = P9_QID_DIR;
            } else if (type == DT_LNK) {
                qid.type = P9_QID_SYMLINK;
            } else {
                qid.type = P9_QID_FILE;
            }
            qid.path = dir_entry->d_ino;
        }
        // Add the entry to our reply
        auto off = static_cast<uint64_t>(entry_off);
        if (!out_msg.pack(&qid, &off, &type, name)) {
            return send_error(msg, tag, P9_EPROTO);
        }
    }
    // Reply
    uint32_t data_len = out_msg.length - start_offset;
    out_msg.offset = P9_OUT_MSG_OFFSET;
    if (!out_msg.pack(&data_len)) {
        return send_error(msg, tag, P9_EPROTO);
    }
    return send_reply(std::move(out_msg), tag, P9_RREADDIR);
}

bool virtio_p9fs_device::op_fsync(virtq_unserializer &&mmsg, uint16_t tag) {
    virtq_unserializer msg = std::move(mmsg);
    uint32_t fid{};
    if (!msg.unpack(&fid)) {
        return send_error(msg, tag, P9_EPROTO);
    }
#ifdef DEBUG_VIRTIO_P9FS
    std::ignore = fprintf(stderr, "p9fs fsync: tag=%d fid=%d\n", tag, fid);
#endif
    // Get the fid state
    p9_fid_state *fidp = get_fid_state(fid);
    if ((fidp == nullptr) || fidp->fd < 0) {
        return send_error(msg, tag, P9_EPROTO);
    }
    // Sync the file
    if (fsync(fidp->fd) != 0) {
        return send_error(msg, tag, host_errno_to_p9(errno));
    }
    // Reply
    return send_ok(msg, tag, P9_RFSYNC);
}

bool virtio_p9fs_device::op_link(virtq_unserializer &&mmsg, uint16_t tag) {
    virtq_unserializer msg = std::move(mmsg);
    uint32_t dfid{};
    uint32_t fid{};
    char name[P9_NAME_MAX]{};
    if (!msg.unpack(&dfid, &fid, &name)) {
        return send_error(msg, tag, P9_EPROTO);
    }
#ifdef DEBUG_VIRTIO_P9FS
    std::ignore = fprintf(stderr, "p9fs link: tag=%d dfid=%d fid=%d name=%s\n", tag, dfid, fid, name);
#endif
    // Check if name is valid
    if (!is_name_legal(name)) {
        return send_error(msg, tag, P9_ENOENT);
    }
    // Get the fid state
    p9_fid_state *dfidp = get_fid_state(dfid);
    p9_fid_state *fidp = get_fid_state(fid);
    if ((dfidp == nullptr) || (fidp == nullptr)) {
        return send_error(msg, tag, P9_EPROTO);
    }
    // Create the hard link
    const std::string path = join_path_name(dfidp->path, name);
    if (link(fidp->path.c_str(), path.c_str()) != 0) {
        return send_error(msg, tag, host_errno_to_p9(errno));
    }
    // Reply
    if (!send_ok(msg, tag, P9_RLINK)) {
        std::ignore = unlink(path.c_str());
        return false;
    }
    return true;
}

bool virtio_p9fs_device::op_mkdir(virtq_unserializer &&mmsg, uint16_t tag) {
    virtq_unserializer msg = std::move(mmsg);
    uint32_t dfid{};
    uint32_t mode{};
    uint32_t gid{};
    char name[P9_NAME_MAX]{};
    if (!msg.unpack(&dfid, &name, &mode, &gid)) {
        return send_error(msg, tag, P9_EPROTO);
    }
#ifdef DEBUG_VIRTIO_P9FS
    std::ignore = fprintf(stderr, "p9fs mkdir: tag=%d dfid=%d name=%s mode=%d gid=%d\n", tag, dfid, name, mode, gid);
#endif
    // Check if name is valid
    if (!is_name_legal(name)) {
        return send_error(msg, tag, P9_ENOENT);
    }
    // Get the fid state
    p9_fid_state *dfidp = get_fid_state(dfid);
    if (dfidp == nullptr) {
        return send_error(msg, tag, P9_EPROTO);
    }
    // Create the directory
    const std::string path = join_path_name(dfidp->path, name);
    if (mkdir(path.c_str(), static_cast<mode_t>(mode)) != 0) {
        return send_error(msg, tag, host_errno_to_p9(errno));
    }
    // If we fail to change ownership, we silent ignore the error
    if (lchown(path.c_str(), static_cast<uid_t>(dfidp->uid), static_cast<gid_t>(gid)) != 0) {
        errno = 0;
    }
    // Get the path qid
    stat_t st{};
    if (lstat(path.c_str(), &st) != 0) {
        std::ignore = rmdir(path.c_str());
        return send_error(msg, tag, host_errno_to_p9(errno));
    }
    p9_qid qid = stat_to_qid(st);
    // Reply
    virtq_serializer out_msg(msg.a, msg.vq, msg.queue_idx, msg.desc_idx, P9_OUT_MSG_OFFSET);
    if (!out_msg.pack(&qid)) {
        std::ignore = rmdir(path.c_str());
        return send_error(msg, tag, P9_EPROTO);
    }
    if (!send_reply(std::move(out_msg), tag, P9_RMKDIR)) {
        std::ignore = rmdir(path.c_str());
        return false;
    }
    return true;
}

bool virtio_p9fs_device::op_renameat(virtq_unserializer &&mmsg, uint16_t tag) {
    virtq_unserializer msg = std::move(mmsg);
    uint32_t oldfid{};
    uint32_t newfid{};
    char oldname[P9_NAME_MAX]{};
    char newname[P9_NAME_MAX]{};
    if (!msg.unpack(&oldfid, &oldname, &newfid, &newname)) {
        return send_error(msg, tag, P9_EPROTO);
    }
#ifdef DEBUG_VIRTIO_P9FS
    std::ignore = fprintf(stderr, "p9fs renameat: tag=%d oldfid=%d oldname=%s newfid=%d newname=%s\n", tag, oldfid,
        oldname, newfid, newname);
#endif
    // Check if names are valid
    if (!is_name_legal(oldname) || !is_name_legal(newname)) {
        return send_error(msg, tag, P9_ENOENT);
    }
    // Get the fid state
    const p9_fid_state *oldfidp = get_fid_state(oldfid);
    const p9_fid_state *newfidp = get_fid_state(newfid);
    if ((newfidp == nullptr) || (oldfidp == nullptr)) {
        return send_error(msg, tag, P9_EPROTO);
    }
    // Rename the file
    const std::string oldpath = join_path_name(oldfidp->path, oldname);
    const std::string newpath = join_path_name(newfidp->path, newname);
    const int ret = rename(oldpath.c_str(), newpath.c_str());
    if (ret != 0) {
        return send_error(msg, tag, host_errno_to_p9(errno));
    }
    // Reply
    if (!send_ok(msg, tag, P9_RRENAMEAT)) {
        std::ignore = rename(newpath.c_str(), oldpath.c_str());
        return false;
    }
    // Fix path for all fids starting with the old path
    for (auto &pair : m_fids) {
        p9_fid_state *fidp = &pair.second;
        // Change fid path to the new path if it starts with old path
        if (fidp->path.rfind(oldpath) == 0) {
            fidp->path = newpath + fidp->path.substr(oldpath.length(), std::string::npos);
        }
    }
    return true;
}

bool virtio_p9fs_device::op_unlinkat(virtq_unserializer &&mmsg, uint16_t tag) {
    virtq_unserializer msg = std::move(mmsg);
    uint32_t dfid{};
    uint32_t flags{};
    char name[P9_NAME_MAX]{};
    if (!msg.unpack(&dfid, &name, &flags)) {
        return send_error(msg, tag, P9_EPROTO);
    }
#ifdef DEBUG_VIRTIO_P9FS
    std::ignore = fprintf(stderr, "p9fs unlinkat: tag=%d dfid=%d name=%s flags=%d\n", tag, dfid, name, flags);
#endif
    // Check if name is valid
    if (!is_name_legal(name)) {
        return send_error(msg, tag, P9_ENOENT);
    }
    // Get the fid state
    const p9_fid_state *dfidp = get_fid_state(dfid);
    if (dfidp == nullptr) {
        return send_error(msg, tag, P9_EPROTO);
    }
    // Remove the path
    const std::string path = join_path_name(dfidp->path, name);
    if ((flags & P9_AT_REMOVEDIR) != 0) {
        if (rmdir(path.c_str()) != 0) {
            return send_error(msg, tag, host_errno_to_p9(errno));
        }
    } else {
        if (unlink(path.c_str()) != 0) {
            return send_error(msg, tag, host_errno_to_p9(errno));
        }
    }
    return send_ok(msg, tag, P9_RUNLINKAT);
}

bool virtio_p9fs_device::op_version(virtq_unserializer &&mmsg, uint16_t tag) {
    virtq_unserializer msg = std::move(mmsg);
    char version[32]{};
    uint32_t msize{};
    if (!msg.unpack(&msize, &version)) {
        return send_error(msg, tag, P9_EPROTO);
    }
#ifdef DEBUG_VIRTIO_P9FS
    std::ignore = fprintf(stderr, "p9fs version: tag=%d msize=%d version=%s\n", tag, m_msize, version);
#endif
    // Set msize
    m_msize = std::min<uint32_t>(m_msize, P9_MAX_MSIZE);
    // Reply with the protocol version we support
    virtq_serializer out_msg(msg.a, msg.vq, msg.queue_idx, msg.desc_idx, P9_OUT_MSG_OFFSET);
    const char P9_PROTO_VERSION[] = "9P2000.L";
    if (!out_msg.pack(&m_msize, P9_PROTO_VERSION)) {
        return send_error(msg, tag, P9_EPROTO);
    }
    return send_reply(std::move(out_msg), tag, P9_RVERSION);
}

bool virtio_p9fs_device::op_attach(virtq_unserializer &&mmsg, uint16_t tag) {
    virtq_unserializer msg = std::move(mmsg);
    uint32_t fid{};
    uint32_t afid{};
    uint32_t uid{};
    char uname[128]{};
    char aname[128]{};
    if (!msg.unpack(&fid, &afid, &uname, &aname, &uid)) {
        return send_error(msg, tag, P9_EPROTO);
    }
#ifdef DEBUG_VIRTIO_P9FS
    std::ignore = fprintf(stderr, "p9fs attach: tag=%d fid=%d afid=%d uid=%d uname=%s aname=%s\n", tag, fid, afid, uid,
        uname, aname);
#endif
    // It's an error if the fid already exists
    if (get_fid_state(fid) != nullptr) {
        return send_error(msg, tag, P9_EPROTO);
    }
    // Check if root path exists
    stat_t st{};
    if (lstat(m_root_path.c_str(), &st) != 0) {
        return send_error(msg, tag, host_errno_to_p9(errno));
    }
    // Create the new fid state
    p9_fid_state *newfidp = &m_fids[fid];
    // Get the qid
    p9_qid qid = stat_to_qid(st);
    // Reply
    virtq_serializer out_msg(msg.a, msg.vq, msg.queue_idx, msg.desc_idx, P9_OUT_MSG_OFFSET);
    if (!out_msg.pack(&qid)) {
        std::ignore = m_fids.erase(fid);
        return send_error(msg, tag, host_errno_to_p9(errno));
    }
    if (!send_reply(std::move(out_msg), tag, P9_RATTACH)) {
        std::ignore = m_fids.erase(fid);
        return false;
    }
    // Update new fid state
    *newfidp = p9_fid_state{uid, m_root_path, -1};
    return true;
}

bool virtio_p9fs_device::op_walk(virtq_unserializer &&mmsg, uint16_t tag) {
    virtq_unserializer msg = std::move(mmsg);
    uint32_t fid{};
    uint32_t newfid{};
    uint16_t nwname{};
    if (!msg.unpack(&fid, &newfid, &nwname)) {
        return send_error(msg, tag, P9_EPROTO);
    }
#ifdef DEBUG_VIRTIO_P9FS
    std::ignore = fprintf(stderr, "p9fs walk: tag=%d fid=%d newfid=%d nwname=%d\n", tag, fid, newfid, nwname);
#endif
    // A maximum of sixteen name elements or qids may be packed in a single message
    if (nwname > P9_MAXWELEM) {
        return send_error(msg, tag, P9_EINVAL);
    }
    // Get the fid state, it must not have been opened for I/O by an open or create message
    p9_fid_state *fidp = get_fid_state(fid);
    if (fidp == nullptr) {
        return send_error(msg, tag, P9_EPROTO);
    }
    // The newfid must not be in use unless it is the same as fid
    if (newfid != fid && (get_fid_state(newfid) != nullptr)) {
        return send_error(msg, tag, P9_EPROTO);
    }
    // Get the start for the starting path and root path
    stat_t st{};
    stat_t root_st{};
    if (lstat(fidp->path.c_str(), &st) != 0 || lstat(m_root_path.c_str(), &root_st) != 0) {
        return send_error(msg, tag, host_errno_to_p9(errno));
    }
    // Walk path retrieving qid for each name
    virtq_serializer out_msg(msg.a, msg.vq, msg.queue_idx, msg.desc_idx, P9_OUT_MSG_OFFSET + sizeof(uint16_t));
    std::string path = fidp->path;
    uint16_t nwalked = 0;
    for (; nwalked < nwname; ++nwalked) {
        char namebuf[P9_NAME_MAX]{};
        if (!msg.unpack(&namebuf)) {
            return send_error(msg, tag, P9_EPROTO);
        }
        const std::string &name = namebuf;
        // Check if name is valid
        if (name.empty() || name.find('/') != std::string::npos) {
            return send_error(msg, tag, P9_ENOENT);
        }
        // A walk of the name ".." in the root directory is equivalent to a walk with no name elements
        if (!(name == ".." && is_same_stat_ino(&root_st, &st)) && name != ".") {
            std::string next_path;
            if (name == "..") {
                next_path = remove_path_name(path);
            } else {
                next_path = join_path_name(path, name);
            }
            // Get next path qid
            if (lstat(next_path.c_str(), &st) != 0) {
                // Return an error only for the first walk
                if (nwalked == 0) {
                    return send_error(msg, tag, host_errno_to_p9(errno));
                } // Otherwise, stop walk on error
                break;
            }
            path = std::move(next_path);
        }
        p9_qid wqid = stat_to_qid(st);
        // Store the composed path qid in the reply message
        if (!out_msg.pack(&wqid)) {
            return send_error(msg, tag, P9_EPROTO);
        }
    }
    // Create the new fid state
    const uint32_t uid = fidp->uid;
    p9_fid_state *newfidp = nullptr;
    if (fid != newfid) {
        fidp = nullptr;
        newfidp = &m_fids[newfid];
    } else {
        newfidp = fidp;
    }
    // Write amount of wqids in the reply message
    out_msg.offset = P9_OUT_MSG_OFFSET;
    if (!out_msg.pack(&nwalked)) {
        if (fid != newfid) {
            std::ignore = m_fids.erase(newfid);
        }
        return send_error(msg, tag, P9_EPROTO);
    }
    // Reply
    if (!send_reply(std::move(out_msg), tag, P9_RWALK)) {
        if (fid != newfid) {
            std::ignore = m_fids.erase(newfid);
        }
        return false;
    }
    // Update the new fid state
    *newfidp = p9_fid_state{uid, path, -1};
    return true;
}

bool virtio_p9fs_device::op_read(virtq_unserializer &&mmsg, uint16_t tag) {
    virtq_unserializer msg = std::move(mmsg);
    uint32_t fid{};
    uint64_t offset{};
    uint32_t count{};
    if (!msg.unpack(&fid, &offset, &count)) {
        return send_error(msg, tag, P9_EPROTO);
    }
#ifdef DEBUG_VIRTIO_P9FS
    std::ignore = fprintf(stderr, "p9fs read: tag=%d fid=%d offset=%ld count=%d\n", tag, fid, offset, count);
#endif
    // Get the fid state, only file fids are accepted
    const p9_fid_state *fidp = get_fid_state(fid);
    if ((fidp == nullptr) || fidp->fd < 0) {
        return send_error(msg, tag, P9_EPROTO);
    }
    // Prepare temporary output buffer
    std::array<uint8_t, P9_IOUNIT_MAX> buf{};
    if (count > buf.size()) {
        return send_error(msg, tag, P9_EPROTO);
    }
    // Read from fd
    const ssize_t ret = pread(fidp->fd, buf.data(), static_cast<size_t>(count), static_cast<off_t>(offset));
    if (ret < 0) {
        return send_error(msg, tag, host_errno_to_p9(errno));
    }
    auto ret_count = static_cast<uint32_t>(ret);
    // Reply
    virtq_serializer out_msg(msg.a, msg.vq, msg.queue_idx, msg.desc_idx, P9_OUT_MSG_OFFSET);
    if (!out_msg.pack(&ret_count) || !out_msg.write_bytes(buf.data(), count)) {
        return send_error(msg, tag, P9_EPROTO);
    }
    return send_reply(std::move(out_msg), tag, P9_RREAD);
}

bool virtio_p9fs_device::op_write(virtq_unserializer &&mmsg, uint16_t tag) {
    virtq_unserializer msg = std::move(mmsg);
    uint32_t fid{};
    uint64_t offset{};
    uint32_t count{};
    if (!msg.unpack(&fid, &offset, &count)) {
        return send_error(msg, tag, P9_EPROTO);
    }
#ifdef DEBUG_VIRTIO_P9FS
    std::ignore = fprintf(stderr, "p9fs write: tag=%d fid=%d offset=%ld count=%d\n", tag, fid, offset, count);
#endif
    // Get the fid state, only file fids are accepted
    const p9_fid_state *fidp = get_fid_state(fid);
    if ((fidp == nullptr) || fidp->fd < 0) {
        return send_error(msg, tag, P9_EPROTO);
    }
    // Read from input buffer
    std::array<uint8_t, P9_IOUNIT_MAX> buf{};
    if (count > buf.size() || !msg.read_bytes(buf.data(), count)) {
        return send_error(msg, tag, P9_EPROTO);
    }
    // Write to fd
    const ssize_t ret = pwrite(fidp->fd, buf.data(), static_cast<size_t>(count), static_cast<off_t>(offset));
    if (ret < 0) {
        return send_error(msg, tag, host_errno_to_p9(errno));
    }
    auto ret_count = static_cast<uint32_t>(ret);
    // Reply
    virtq_serializer out_msg(msg.a, msg.vq, msg.queue_idx, msg.desc_idx, P9_OUT_MSG_OFFSET);
    if (!out_msg.pack(&ret_count)) {
        return send_error(msg, tag, P9_EPROTO);
    }
    return send_reply(std::move(out_msg), tag, P9_RREAD);
}

bool virtio_p9fs_device::op_clunk(virtq_unserializer &&mmsg, uint16_t tag) {
    virtq_unserializer msg = std::move(mmsg);
    uint32_t fid{};
    if (!msg.unpack(&fid)) {
        return send_error(msg, tag, P9_EPROTO);
    }
#ifdef DEBUG_VIRTIO_P9FS
    std::ignore = fprintf(stderr, "p9fs clunk: tag=%d fid=%d\n", tag, fid);
#endif
    p9_fid_state *fidp = get_fid_state(fid);
    if (fidp == nullptr) {
        return send_error(msg, tag, P9_EPROTO);
    }
    // Close file descriptors
    const int close_errno = close_fid_state(fidp);
    // Remove from fid state list even on error
    fidp = nullptr;
    std::ignore = m_fids.erase(fid);
    // Propagate close error if any
    if (close_errno != 0) {
        return send_error(msg, tag, host_errno_to_p9(close_errno));
    }
    // Reply
    return send_ok(msg, tag, P9_RCLUNK);
}

bool virtio_p9fs_device::send_reply(virtq_serializer &&mout_msg, uint16_t tag, p9_opcode opcode) {
    virtq_serializer out_msg = std::move(mout_msg);
#ifdef DEBUG_VIRTIO_P9FS
    if (opcode != P9_RLERROR) {
        std::ignore = fprintf(stderr, "p9fs send_reply: tag=%d opcode=%d\n", tag, opcode);
    }
#endif
    // Rewind message write offset to its start
    out_msg.offset = 0;
    // Write message header
    uint32_t size = out_msg.length;
    if (!out_msg.pack(&size, &opcode, &tag)) {
        notify_device_needs_reset(out_msg.a);
        return false;
    }
    // Consume the queue and notify the driver
    if (!consume_and_notify_queue(out_msg.a, out_msg.queue_idx, out_msg.desc_idx, out_msg.length, 0)) {
        notify_device_needs_reset(out_msg.a);
        return false;
    }
    return true;
}

bool virtio_p9fs_device::send_ok(const virtq_unserializer &in_msg, uint16_t tag, p9_opcode opcode) {
    virtq_serializer out_msg(in_msg.a, in_msg.vq, in_msg.queue_idx, in_msg.desc_idx, P9_OUT_MSG_OFFSET);
    return send_reply(std::move(out_msg), tag, opcode);
}

bool virtio_p9fs_device::send_error(const virtq_unserializer &in_msg, uint16_t tag, p9_error error) {
#ifdef DEBUG_VIRTIO_P9FS
    if (error == P9_EPROTO) {
        std::ignore = fprintf(stderr, "p9fs PROTOCOL ERROR: tag=%d\n", tag);
    } else {
        std::ignore = fprintf(stderr, "p9fs send_error: tag=%d error=%d\n", tag, error);
    }
#endif
    virtq_serializer out_msg(in_msg.a, in_msg.vq, in_msg.queue_idx, in_msg.desc_idx, P9_OUT_MSG_OFFSET);
    if (!out_msg.pack(&error)) {
        notify_device_needs_reset(in_msg.a);
        return false;
    }
    return send_reply(std::move(out_msg), tag, P9_RLERROR);
}

} // namespace cartesi

#endif // HAVE_POSIX_FS
