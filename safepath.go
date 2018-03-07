package guardianagent

import (
	"fmt"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

func OpenNoLinks(path string, flags int, mode uint32) (int32, error) {
	if !filepath.IsAbs(path) {
		return -int32(syscall.EINVAL), fmt.Errorf("Path %s is not absolute", path)
	}
	dirFD := unix.AT_FDCWD
	defer func() {
		if dirFD != unix.AT_FDCWD {
			syscall.Close(dirFD)
		}
	}()

	var stat unix.Stat_t
	parts := append([]string{"/"}, strings.Split(path, "/")...)
	for len(parts) > 0 {
		part := parts[0]
		parts = parts[1:]

		if part == "" {
			part = "."
		}

		openFlags := flags | syscall.O_NOFOLLOW
		if len(parts) != 0 {
			//  not last path component
			openFlags = openFlags | unix.O_DIRECTORY | unix.O_PATH
		}

		childFD, err := unix.Openat(dirFD, part, openFlags, mode)
		if err != nil {
			return -int32(err.(syscall.Errno)), errors.Wrapf(err, "Failed to openat %s", part)
		}
		if dirFD != unix.AT_FDCWD {
			syscall.Close(dirFD)
		}
		dirFD = childFD

		err = unix.Fstat(dirFD, &stat)
		if err != nil {
			return -int32(err.(syscall.Errno)), errors.Wrapf(err, "Cannot stat %s", part)
		}

		if flags&syscall.O_NOFOLLOW == 0 && stat.Mode&syscall.S_IFMT == syscall.S_IFLNK {
			return -int32(syscall.ELOOP), fmt.Errorf("Path contains disallowed symlink %s: %s", path, part)
		}
	}

	result := int32(dirFD)
	dirFD = -1
	return result, nil
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
