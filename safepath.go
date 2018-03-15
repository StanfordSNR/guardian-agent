package guardianagent

import (
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

const SYS_RENAMEAT2 = 316

func split(path string) (base string, last string) {
	for ; strings.HasSuffix(path, "//"); path = path[0 : len(path)-1] {
	}
	last = path[strings.LastIndex(path[0:len(path)-1], "/")+1:]
	base = path[0 : len(path)-len(last)]
	return
}

func OpenNoFollow(dirFD int, path string, flags int, mode uint32) (int, error) {
	base, last := split(path)
	dirFD, err := OpenDirNoFollow(dirFD, base)
	if err != nil {
		return -1, err
	}
	defer unix.Close(dirFD)

	fd, err := unix.Openat(dirFD, last, flags|unix.O_NOFOLLOW, mode)
	if err != nil {
		return fd, err
	}

	// If user request O_PATH but not O_NOFOLLOW, and path points to a symbolic link
	// then the syscall may succeed even though it should fail. We check this and force failure.
	if flags&unix.O_PATH == 0 || flags&unix.O_NOFOLLOW != 0 {
		return fd, err
	}

	stat := unix.Stat_t{}
	err = unix.Fstat(fd, &stat)
	if err != nil {
		unix.Close(fd)
		return -1, err
	}
	if stat.Mode&syscall.S_IFMT == syscall.S_IFLNK {
		unix.Close(fd)
		return -1, syscall.ELOOP
	}
	return fd, nil
}

func UnlinkNoFollow(dirFD int, path string, flags int) error {
	base, last := split(path)
	dirFD, err := OpenDirNoFollow(dirFD, base)
	if err != nil {
		return err
	}
	defer unix.Close(dirFD)

	return unix.Unlinkat(dirFD, last, flags)
}

func MkdirNoFollow(dirFD int, path string, mode uint32) error {
	base, last := split(path)
	dirFD, err := OpenDirNoFollow(dirFD, base)
	if err != nil {
		return err
	}
	defer unix.Close(dirFD)

	return unix.Mkdirat(dirFD, last, mode)
}

func SymlinkNoFollow(target string, dirFD int, path string) error {
	base, last := split(path)
	dirFD, err := OpenDirNoFollow(dirFD, base)
	if err != nil {
		return err
	}
	defer unix.Close(dirFD)

	return unix.Symlinkat(target, dirFD, last)
}

func AccessNoFollow(dirFD int, path string, mode uint32) error {
	base, last := split(path)
	dirFD, err := OpenDirNoFollow(dirFD, base)
	if err != nil {
		return err
	}
	defer unix.Close(dirFD)

	// TODO: we cannot use faccessat for two reasons:
	//  * faccessat does not have a NOFOLLOW variant (the flags arugment is
	//    processed by the libc wrapper and not by the syscall)
	//  * faccessat checks using the real userid, but we want to check using the
	//    effective userid in case the guardo dameon runs as a setuid binary

	stats := unix.Stat_t{}
	err = unix.Fstatat(dirFD, last, &stats, unix.AT_SYMLINK_NOFOLLOW)
	if err != nil {
		return err
	}
	if stats.Mode&syscall.S_IFMT == syscall.S_IFLNK {
		return syscall.ELOOP
	}

	// clear irrelevant bits
	mode &= (unix.X_OK | unix.R_OK | unix.W_OK)

	if mode == unix.F_OK {
		return nil
	}

	uid := uint32(syscall.Geteuid())
	gid := uint32(syscall.Getegid())
	groups, err := syscall.Getgroups()
	if err != nil {
		groups = []int{}
	}
	groupmap := map[uint32]bool{}
	for _, g := range groups {
		groupmap[uint32(g)] = true
	}

	if uid == 0 && ((mode&unix.X_OK) == 0 || (stats.Mode&(unix.S_IXUSR|unix.S_IXGRP|unix.S_IXOTH)) != 0) {
		return nil
	}

	granted := uint32(0)
	if uid == stats.Uid {
		granted = (stats.Mode & (mode << 6)) >> 6
	} else if gid == stats.Gid || groupmap[stats.Gid] {
		granted = (stats.Mode & (mode << 3)) >> 3
	} else {
		granted = (stats.Mode & mode)
	}

	if granted == mode {
		return nil
	}
	return unix.EACCES

}

func StatNoFollow(dirFD int, path string, stat *unix.Stat_t, flags int) error {
	base, last := split(path)
	dirFD, err := OpenDirNoFollow(dirFD, base)
	if err != nil {
		return err
	}
	defer unix.Close(dirFD)

	err = unix.Fstatat(dirFD, last, stat, flags|unix.AT_SYMLINK_NOFOLLOW)
	if err != nil {
		return err
	}

	// If user did not specify O_NOFOLLOW, but the path points to a symbolic link
	// we force-fail the syscall.
	if flags&unix.AT_SYMLINK_NOFOLLOW != 0 {
		return nil
	}

	if stat.Mode&syscall.S_IFMT == syscall.S_IFLNK {
		return syscall.ELOOP
	}

	return nil
}

func ReadlinkNoFollow(dirFD int, path string, buf []byte, bufSize int) (int, error) {
	base, last := split(path)
	dirFD, err := OpenDirNoFollow(dirFD, base)
	if err != nil {
		return 0, err
	}
	defer unix.Close(dirFD)

	return unix.Readlinkat(dirFD, last, buf)
}

func RenameNoFollow(oldDirFd int, oldPath string, newDirFd int, newPath string, flags int) error {
	oldBase, oldLast := split(oldPath)
	oldDirFd, err := OpenDirNoFollow(oldDirFd, oldBase)
	if err != nil {
		return err
	}
	defer unix.Close(oldDirFd)

	newBase, newLast := split(newPath)
	newDirFd, err = OpenDirNoFollow(newDirFd, newBase)
	if err != nil {
		return err
	}
	defer unix.Close(newDirFd)

	oldPtr, err := unix.BytePtrFromString(oldLast)
	if err != nil {
		return err
	}
	newPtr, err := unix.BytePtrFromString(newLast)
	if err != nil {
		return err
	}

	_, _, errno := syscall.Syscall6(
		SYS_RENAMEAT2,
		uintptr(oldDirFd),
		uintptr(unsafe.Pointer(oldPtr)),
		uintptr(newDirFd),
		uintptr(unsafe.Pointer(newPtr)),
		uintptr(flags),
		0,
	)

	if errno != 0 {
		// In the syscall module the authors box a couple of common errors
		// (i.e EAGAIN, EINVAL, and ENOENT). Is that worth doing here?
		return syscall.Errno(errno)
	}

	return nil
}

func OpenDirNoFollow(dirFD int, path string) (int, error) {
	parts := strings.Split(path, "/")
	if filepath.IsAbs(path) {
		parts = append([]string{"/"}, parts...)
	} else if path == "" {
		parts = append([]string{"."}, parts...)
	}
	first := true
	for len(parts) > 0 {
		part := parts[0]
		parts = parts[1:]

		if part == "" {
			continue
		}

		childFD, err := unix.Openat(dirFD, part, unix.O_NOFOLLOW|unix.O_DIRECTORY|unix.O_PATH, 0)
		if !first {
			unix.Close(dirFD)
			first = false
		}
		if err != nil {
			return -1, errors.Wrapf(err, "Failed to openat base dir component: %s", part)
		}
		dirFD = childFD
	}
	return dirFD, nil
}

/**
Try handling symlinks


// Implementing along the lines of http://research.cs.wisc.edu/mist/safefile/
const (
	Untrusted     = iota
	Trusted       = iota
	StickyTrusted = iota
)

func NewSafePath(path string) (*SafePath, error) {
	if !filepath.IsAbs(origPath) {
		return nil, fmt.Erorrf("Path %s is not absolute", path)
	}
	sp := SafePath{OrigPath: path}
	curPath := "/"
	parts := strings.Split(path, "/")
	trust := Trusted

	dirFD, err := syscall.Open(curPath, syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		return nil, errors.Wrapf(err, "Cannot open %s", curPath)
	}
	defer func() { if dirFD != -1 { syscall.Close(dirFD) } }()

 	for len(parts) > 0 {
		part := parts[len(parts)-1]
		parts = parts[:len(parts)-1]

		if part == "/" {
			trust = Trusted
			curPath = "/"
		}

		if part == "" || part == "." {
			continue
		}

		var stat unix.Stat_t
		err := unix.Fstatat(dirFD, part, &stat, syscall.AT_SYMLINK_NOFOLLOW)
		if err != nil {
			return errors.Wrapf(err, "Cannot stat %s/%s: %s", path, part)
		}

		trust = getEntryTrust(trust, stat)
		if trust == Untrusted {
			return false
		}
		if stat.Mode & syscall.S_IFMT == syscall.S_IFLNK {
			linkTarget := make([]byte, stat.st_size + 1)
			n, err := syscall.Readlinkat(dirFD, part, linkTarget)
			if err != nil {
				log.Printf("Failed to readlink %s/%s: %s", path, part, err)
				return false
			}
			if n > stat.st_size + 1 {
				log.Printf("Unexpected readlink size of %s/%s: %s", path, part, n)
				return false
			}
			linkTarget[n] = 0
			if filepath.IsAbs(string(linkTarget)) {
				parts = append("/", strings.Split(filepath, "/"), parts)
			}
		} else if len(parts) > 0 {
			subdirFD, err = syscall.Openat(dirFD, part, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_DIRECTORY, 0)
			if err != nil {
				log.Printf("Failed to Openat %s/%s: %s", path, part, err)
				return false
			}
			syscall.Close(dirFD)
			dirFD = subdirFD
		}
	}
	// Open the final component with the flags and permissions requested by
	// the user plus forced NOFOLLOW.
	return syscall.Openat(dirFD, final, flags|syscall.O_NOFOLLOW, mode)
}


func getEntryTrust(int parentTrust, stat syscall.Stat_t) int {
	if parentTrust == Untrusted {
		return Untrusted
	}
	isWriteProtected :=
		(stat.Uid == 0) &&
		((stat.Gid == 0) || (stat.Mode & syscall.S_IWGRP == 0)) &&
		(stat.Mode & syscall.S_IWOTH == 0)

	if parentTrust == StickyTrusted {
		// Anything but a directory is untrused, because of the risk of hard links
		if stat.Mode & syscall.S_IFMT != syscall.S_IFDIR {
			return Untrusted
		if isWriteProtected {
			return Trusted
		}
		if (stat.Uid == 0) && (stat.Mode & syscall.S_ISVTX != 0) {
			return StickyTrusted
		}
		return Untrusted
	}

	// Parent is trusted

	// Symlinks are immutable and therefore trusted
	if stat.Mode & syscall.S_IFMT == syscall.S_IFLNK {
		return Trusted
	}
	if isWriteProtected {
		return Trusted
	}
	if stat.Uid == 0 && stat.Mode & syscall.S_IFMT == syscall.S_IFDIR && stat.Mode & syscall.S_ISVTX != 0 {
		return StickyTrusted
	}
	return Untrusted
}

*/
