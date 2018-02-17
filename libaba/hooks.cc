#include "guardo.pb.h"
#include "socket.hh"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <errno.h>
#include <experimental/filesystem>
#include <fcntl.h>
#include <libsyscall_intercept_hook_point.h>
#include <syscall.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

namespace fs = std::experimental::filesystem;

static const char* AGENT_SOCK_NAME = "guardo_sock";

std::string relative_to_absolute_path(int parent_fd, const fs::path& path)
{
    if (!path.is_relative())
    {
        return path;
    }
    fs::path base_dir;
    if (parent_fd == AT_FDCWD) 
    {
        base_dir = fs::current_path();
    } else 
    {
        base_dir = fs::read_symlink(fs::path("/proc/self/fd") / std::to_string(parent_fd));
    } 
    return base_dir / path;
}

void create_open_request(int parent_fd, 
                         const char* path, 
                         int flags,
                         int mode,
                         guardo::OpenRequest* open_req) 
{
    open_req->set_path(relative_to_absolute_path(parent_fd, path));        
    open_req->set_flags(flags);
    open_req->set_mode(mode);
}

void create_unlink_request(int parent_fd, 
                           const char* path, 
                           int flags,
                           guardo::UnlinkRequest* unlink_req) 
{
    unlink_req->set_path(relative_to_absolute_path(parent_fd, path));
    unlink_req->set_flags(flags);
}

static int hook(long syscall_number,
                long arg0, 
                long arg1,
                long arg2, 
                long arg3, 
                long arg4, 
                long arg5,
                long *result)
{
    long real_result = syscall_no_intercept(syscall_number, arg0, arg1, arg2, arg3, arg4, arg5);
    *result = real_result;
    if (real_result != -EACCES) 
    {
        return 0;
    }

    UnixSocket socket;
    socket.connect(Address::NewUnixAddress(fs::path(std::getenv("HOME")) / AGENT_SOCK_NAME));

    std::string payload;
    guardo::ElevationRequest request;
    switch (syscall_number) 
    {
        case SYS_open: 
            create_open_request(AT_FDCWD, (char*)arg0, arg1, arg2, request.mutable_open());
            break;
        case SYS_openat:
            create_open_request((int)arg0, (char*)arg1, arg2, arg3, request.mutable_open());
            break;
        case SYS_unlink:
            create_unlink_request(AT_FDCWD, (char*)arg0, 0, request.mutable_unlink());
            break;
        case SYS_unlinkat:
            create_unlink_request((int)arg0, (char*)arg1, arg2, request.mutable_unlink());
            break;
        case SYS_access:
            request.mutable_access()->set_path(relative_to_absolute_path(AT_FDCWD, (char*)arg0));
            request.mutable_access()->set_mode(arg1);
            break;
        default:
            printf("Error: unexpected intercepted syscall: %ld\n", syscall_number);
            return 0;
    }

    request.SerializeToString(&payload);
    auto msg = std::string(4, '\0');
    *(int*)msg.data() = payload.size();
    msg += payload;
    std::vector<int> fds;
    socket.sendmsg(msg, fds);

    fds.clear();
    std::string response_data = socket.recvmsg(&fds);
    size_t payload_size = *(int*)response_data.data();
    if (response_data.size() != (sizeof(int) + payload_size)) 
    {
        printf("Got unexpected data size: %lu, payload size: %lu\n", 
               response_data.size(), payload_size);
    }

    guardo::ElevationResponse response;
    if (!response.ParseFromString(response_data.data() + sizeof(int))) 
    {
        printf("Failed to parse ElevationResponse\n");
        return 0;
    }
    if (response.is_result_fd())
    {
        if (fds.size() == 0) 
        {
            printf("Error: no file descriptor with approval\n");
            *result = -1;
            return 0;
        }
        *result = fds[0];
    } else 
    {
        *result = response.result();
    }
    return 0;
}

static __attribute__((constructor)) void
init(void)
{
	// Set up the callback function
	intercept_hook_point = hook;
}