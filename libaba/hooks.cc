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

namespace guardian_agent {

namespace fs = std::experimental::filesystem;

static const char* AGENT_GUARD_SOCK_NAME = ".agent-guard-sock";
static const char* GUARDO_SOCK_NAME = ".guardo-sock";

std::string relative_to_absolute_path(int parent_fd, const fs::path& path)
{
    if (!path.is_relative()){
        return path;
    }
    fs::path base_dir;
    if (parent_fd == AT_FDCWD) {
        base_dir = fs::current_path();
    } else {
        base_dir = fs::read_symlink(fs::path("/proc/self/fd") / std::to_string(parent_fd));
    } 
    return base_dir / path;
}

void create_open_op(int parent_fd, 
                    const char* path, 
                    int flags,
                    int mode,
                    OpenOp* open_op) 
{
    open_op->set_path(relative_to_absolute_path(parent_fd, path));        
    open_op->set_flags(flags);
    open_op->set_mode(mode);
}

void create_unlink_op(int parent_fd, 
                      const char* path, 
                      int flags,
                      UnlinkOp* unlink_op) 
{
    unlink_op->set_path(relative_to_absolute_path(parent_fd, path));
    unlink_op->set_flags(flags);
}

bool create_access_op(const char* path, 
                      int flags,
                      AccessOp* access_op) 
{
    // Don't try to elevate executable access checks for files that
    // are not executable at all. 
    if (flags == X_OK) {
        auto p = fs::status(path).permissions();
        if (((p & fs::perms::owner_exec) == fs::perms::none) &&
            ((p & fs::perms::group_exec) == fs::perms::none) &&
            ((p & fs::perms::others_exec) == fs::perms::none)) {
            return false;
        }
    }
    access_op->set_path(relative_to_absolute_path(AT_FDCWD, path));
    access_op->set_mode(flags);
    return true;
}

void create_socket_op(int domain, int type, int protocol, SocketOp* socket_op)
{
    socket_op->set_domain(domain);
    socket_op->set_type(type);
    socket_op->set_protocol(protocol);
}

fs::path user_runtime_dir()
{
    const char* dir = std::getenv("XDG_RUNTIME_DIR");
    if (dir == NULL) {
        dir = std::getenv("HOME");
    }
    return fs::path(std::string(dir));
}

std::string create_raw_msg(unsigned char msg_num, const google::protobuf::MessageLite& msg)
{
    std::string raw_msg(5, '\0');
    *(unsigned char*)(raw_msg.data() + sizeof(int)) = msg_num;
    msg.AppendToString(&raw_msg);
    *(int*)raw_msg.data() = htonl(raw_msg.size() - sizeof(int));
    return raw_msg;    
}

bool read_expected_msg(FileDescriptor* fd, const unsigned char expected_msg_num, google::protobuf::MessageLite* msg) 
{
    std::string packet_len_buf = fd->read_full(sizeof(int));
    int packet_len = ntohl(*(int*)packet_len_buf.data());
    std::string packet = fd->read_full(packet_len);
    if (packet[0] != expected_msg_num) {
        std::cerr << "Invalid msg_num, expected: " << expected_msg_num << ", got: " << packet[0] << std::endl;
        return false;
    }
    if (!msg->ParseFromString(packet.substr(1))) {
        std::cerr << "Failed to parse msg " << expected_msg_num << " from string" << std::endl;
        return false;
    }
    return true;
}

bool read_expected_msg_with_fd(UnixSocket* socket, const unsigned char expected_msg_num, google::protobuf::MessageLite* msg, std::vector<int>* fds) 
{
    std::string response_data = socket->recvmsg(fds);
    int payload_size = ntohl(*(int*)response_data.data());
    if (response_data.size() != (sizeof(int) + payload_size)) {
        std::cerr << "Error: enexpected data size: " << response_data.size()  
            << " payload size: " << payload_size << std::endl;
        return false;
    }
    unsigned char msg_num = *(response_data.data() + sizeof(payload_size));
    if (msg_num != expected_msg_num) {
        std::cerr << "Invalid msg_num, expected: " << expected_msg_num << ", got: " << msg_num << std::endl;
        return false;
    }
    if (!msg->ParseFromString(response_data.data() + sizeof(payload_size) + sizeof(msg_num))) {
        std::cerr << "Error: failed to parse msg:" << msg_num << std::endl;
        return false;
    }
    return true;
}

bool get_credential(const Operation& op, const Challenge& challenge, Credential* credential) 
{
    UnixSocket socket;
    socket.connect(Address::NewUnixAddress(user_runtime_dir() / AGENT_GUARD_SOCK_NAME));

    CredentialRequest request;
    *request.mutable_op() = op;
    *request.mutable_challenge() = challenge;
    socket.write(create_raw_msg(CREDENTIAL_REQUEST, request), true);

    CredentialResponse response;
    if (!read_expected_msg(&socket, CREDENTIAL_RESPONSE, &response)) {
        std::cerr << "Failed to read CredentialResponse" << std::endl;
        return false;
    }
    if (response.status() != CredentialResponse_Status_APPROVED) {
        std::cerr << "Credential request not approved: " << CredentialResponse_Status_Name(response.status()) << std::endl;
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
    Operation op;
    bool should_hook = true;
    switch (syscall_number) {
	// Must be in sync with switch statement in 'safe_hook' below.
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
            should_hook = create_access_op((char*)arg0, (int)arg1, op.mutable_access());
            break;
        case SYS_socket:
            create_socket_op((int)arg0, (int)arg1, (int)arg2, op.mutable_socket());
            break;
        default:
            std::cerr << "Error: unexpected intercepted syscall: " << syscall_number << std::endl;
            return;
    }

    if (!should_hook) {
        return;
    }

    UnixSocket socket;
    socket.connect(Address::NewUnixAddress(fs::path("/tmp") / GUARDO_SOCK_NAME));    

    ChallengeRequest challenge_req;
    socket.write(create_raw_msg(CHALLENGE_REQUEST, challenge_req), true);
    Challenge challenge;
    if (!read_expected_msg(&socket, CHALLENGE_RESPONSE, &challenge)) {
        std::cerr << "Failed to get challenge" << std::endl;
        return;
    }

    Credential credential;
    if (!get_credential(op, challenge, &credential)) {
        return;
    }

    ElevationRequest elevation_request;
    *elevation_request.mutable_op() = op;
    *elevation_request.mutable_credential() = credential;
    socket.write(create_raw_msg(ELEVATION_REQUEST, elevation_request), true);

    std::vector<int> fds;
    ElevationResponse elevation_response;
    if (!read_expected_msg_with_fd(&socket, ELEVATION_RESPONSE, &elevation_response, &fds)) {
        return;
    }

    if (elevation_response.is_result_fd()) {
        if (fds.size() == 0) 
        {
            std::cerr << "Error: no file descriptor with approval" << std::endl;
            return;
        }
        *result = fds[0];
    } else {
        *result = elevation_response.result();
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
    switch (syscall_number) {
    case SYS_open: 
    case SYS_openat:
    case SYS_unlink:
    case SYS_unlinkat:
    case SYS_access:
    case SYS_socket:
        break;
    default:
        return 1;
    }

    long real_result = syscall_no_intercept(syscall_number, arg0, arg1, arg2, arg3, arg4, arg5);
    *result = real_result;
    if ((real_result != -EACCES) && (real_result != -EPERM)) {
        return 0;
    }

    try {
        hook(syscall_number, arg0, arg1, arg2, arg3, arg4, arg5, result);
    } catch ( const std::exception & e ) { /* don't throw from hook */
        print_exception( e );
    } catch (...) {
        std::cerr << "Unknown exeception caught in hook" << std::endl;
    }
    return 0;
}

} // namespace guardian_agent

static __attribute__((constructor)) void
init(void)
{
	// Set up the callback function
	intercept_hook_point = guardian_agent::safe_hook;
}
