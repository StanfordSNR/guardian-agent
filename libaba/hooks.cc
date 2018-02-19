#include "guardo.pb.h"
#include "guardian_agent.pb.h"
#include "socket.hh"
#include "util.hh"

#include <arpa/inet.h>
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

static const char* AGENT_GUARD_SOCK_NAME = ".agent-guard-sock";
static const char* GUARDO_SOCK_NAME = ".guardo-sock";

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

void create_open_op(int parent_fd, 
                    const char* path, 
                    int flags,
                    int mode,
                    guardo::OpenOp* open_op) 
{
    open_op->set_path(relative_to_absolute_path(parent_fd, path));        
    open_op->set_flags(flags);
    open_op->set_mode(mode);
}

void create_unlink_op(int parent_fd, 
                      const char* path, 
                      int flags,
                      guardo::UnlinkOp* unlink_op) 
{
    unlink_op->set_path(relative_to_absolute_path(parent_fd, path));
    unlink_op->set_flags(flags);
}

fs::path user_runtime_dir()
{
    const char* dir = std::getenv("XDG_RUNTIME_DIR");
    if (dir == NULL) 
    {
        dir = std::getenv("HOME");
    }
    return fs::path(std::string(dir));
}

std::string create_raw_msg(unsigned char msg_num, const google::protobuf::MessageLite& msg)
{
    std::string raw_msg(5, '\0');
    *(unsigned char*)(raw_msg.data() + 4) = msg_num;
    msg.AppendToString(&raw_msg);
    *(int*)raw_msg.data() = htonl(raw_msg.size() - 4);
    return raw_msg;    
}

bool get_credential(const guardo::Operation& op, guardo::Credential* credential) 
{
    UnixSocket socket;
    socket.connect(Address::NewUnixAddress(user_runtime_dir() / AGENT_GUARD_SOCK_NAME));

    guardo::CredentialRequest request;
    *request.mutable_op() = op;
    socket.write(create_raw_msg(guardian_agent::CREDENTIAL_REQUEST, request), true);

    std::string packet_len_buf = socket.read_full(sizeof(int));
    int packet_len = ntohl(*(int*)packet_len_buf.data());
    std::string packet = socket.read_full(packet_len);
    guardo::CredentiallResponse response;
    if (!response.ParseFromString(packet.substr(1))) 
    {
        std::cerr << "Failed to parse CredentialResponse from string" << std::endl;
        return false;
    }
    if (response.status() != guardo::CredentiallResponse_Status_APPROVED) 
    {
        std::cerr << "Credential request not approved: " << guardo::CredentiallResponse_Status_Name(response.status()) << std::endl;
        return false;
    }

    *credential = response.credential();
    return true;
}

static void hook(long syscall_number,
                 long arg0, 
                 long arg1,
                 long arg2, 
                 long arg3, 
                 __attribute__((unused)) long arg4, 
                 __attribute__((unused)) long arg5,
                long int* result)
{
    guardo::Operation op;
    switch (syscall_number) 
    {
        case SYS_open: 
            create_open_op(AT_FDCWD, (char*)arg0, arg1, arg2, op.mutable_open());
            break;
        case SYS_openat:
            create_open_op((int)arg0, (char*)arg1, arg2, arg3, op.mutable_open());
            break;
        case SYS_unlink:
            create_unlink_op(AT_FDCWD, (char*)arg0, 0, op.mutable_unlink());
            break;
        case SYS_unlinkat:
            create_unlink_op((int)arg0, (char*)arg1, arg2, op.mutable_unlink());
            break;
        case SYS_access:
            op.mutable_access()->set_path(relative_to_absolute_path(AT_FDCWD, (char*)arg0));
            op.mutable_access()->set_mode(arg1);
            break;
        default:
            std::cerr << "Error: unexpected intercepted syscall: " << syscall_number << std::endl;
            return;
    }

    guardo::ElevationRequest elevation_request;
    *elevation_request.mutable_op() = op;

    if (!get_credential(op, elevation_request.mutable_credential()))
    {
        return;
    }

    UnixSocket socket;
    socket.connect(Address::NewUnixAddress(fs::path("/tmp") / GUARDO_SOCK_NAME));    

    socket.write(create_raw_msg(guardian_agent::ELEVATION_REQUEST, elevation_request), true);

    std::vector<int> fds;
    std::string response_data = socket.recvmsg(&fds);
    size_t payload_size = ntohl(*(int*)response_data.data());
    if (response_data.size() != (sizeof(int) + payload_size)) 
    {
        std::cerr << "Error: enexpected data size: " << response_data.size()  
            << " payload size: " << payload_size << std::endl;
    }
    unsigned char msg_num = *(response_data.data() + 4);
    if (msg_num != guardian_agent::ELEVATION_RESPONSE) 
    {
        std::cerr << "Error: got unexpected message num: " << msg_num << std::endl;
    }
    guardo::ElevationResponse response;
    if (!response.ParseFromString(response_data.data() + sizeof(int) + 1)) 
    {
        std::cerr << "Error: failed to parse ElevationResponse" << std::endl;
        return;
    }
    if (response.is_result_fd())
    {
        if (fds.size() == 0) 
        {
            std::cerr << "Error: no file descriptor with approval" << std::endl;
            return;
        }
        *result = fds[0];
    } else 
    {
        *result = response.result();
    }
    return;
}


static int safe_hook(long syscall_number,
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

    try 
    {
        hook(syscall_number, arg0, arg1, arg2, arg3, arg4, arg5, result);
    } catch ( const std::exception & e ) { /* don't throw from hook */
        print_exception( e );
    } catch (...) {
        std::cerr << "Unknown exeception caught in hook" << std::endl;
    }
    return 0;
}

static __attribute__((constructor)) void
init(void)
{
	// Set up the callback function
	intercept_hook_point = safe_hook;
}