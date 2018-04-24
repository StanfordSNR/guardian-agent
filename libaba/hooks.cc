#include "guardo.pb.h"
#include "guardian_agent.pb.h"
#include "marshalls.hh"
#include "socket.hh"
#include "util.hh"
#include "proto/syscalls.hh"

#include <arpa/inet.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <errno.h>
#include <experimental/filesystem>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <libsyscall_intercept_hook_point.h>
#include <syscall.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

namespace guardian_agent {

namespace fs = std::experimental::filesystem;
namespace proto = google::protobuf;

static const char* AGENT_GUARD_SOCK_NAME = ".agent-guard-sock";
static const char* GUARDO_SOCK_NAME = ".guardo-sock";


std::unique_ptr<FileDescriptor> marshal_fds(Operation* op, std::vector<int>* fds) {
    std::unique_ptr<FileDescriptor> fd_cwd;
    for (auto& arg : *op->mutable_args()) {
        if (arg.has_fd_arg()) {
            Fd* fd = arg.mutable_fd_arg();
            if (fd->form_case() != Fd::kFd) {
                continue;
            }
            if (fd->fd() == AT_FDCWD) {
                if (!fd_cwd) {
                    fd_cwd = std::make_unique<FileDescriptor>(openat(AT_FDCWD, ".", O_RDONLY, 0));
                    if (fd_cwd->fd_num() < 0) {
                        throw unix_error("Failed to duplicate AT_FDCWD");
                    }
                }
                fds->push_back(fd_cwd->fd_num());
                fd->set_path(fs::current_path());
            } else {
                fds->push_back(fd->fd());
                fd->set_path(fs::read_symlink(fs::path("/proc/self/fd") / std::to_string(fd->fd())));
            }
        }   
    }

    return fd_cwd;
}

bool unmarshal_fds(ElevationResponse* response, const std::vector<int> fds) 
{
    unsigned int pos = 0;
    for (auto& result : *response->mutable_results()) {
        if (result.has_fd_arg()) {
            if (pos >= fds.size()) {
                return false;
            }
            result.mutable_fd_arg()->set_fd(fds[pos]);
            ++pos;
        }   
    }
    return true;
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
        std::cerr << "Failed to parse msg " << int(expected_msg_num) << " from string" << std::endl;
        return false;
    }
    return true;
}

bool read_expected_msg_with_fd(UnixSocket* socket, const unsigned char expected_msg_num, google::protobuf::MessageLite* msg, std::vector<int>* fds) 
{
    std::string packet = socket->recvmsg(fds);
    if (packet.size() < sizeof(int)) {
        std::cerr << "Error: got empty packet" << std::endl;
        return false;
    }
    int payload_size = ntohl(*(int*)packet.data());
    if (packet.size() != (sizeof(int) + payload_size)) {
        std::cerr << "Error: enexpected packet size: " << packet.size()  
            << " payload size: " << payload_size << std::endl;
        return false;
    }
    unsigned char msg_num = *(packet.data() + sizeof(payload_size));
    if (msg_num != expected_msg_num) {
        std::cerr << "Invalid msg_num, expected: " << expected_msg_num << ", got: " << msg_num << std::endl;
        return false;
    }
    if (!msg->ParseFromString(
            packet.substr(sizeof(payload_size) + sizeof(msg_num)))) {
        std::cerr << "Error: failed to parse msg:" << int(msg_num) << std::endl;
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

bool get_myself(Process* myself)
{
    std::ifstream in("/proc/self/cmdline");
 
	if(!in)	{
        std::cerr << "Failed to read /proc/self/cmdline" << std::endl;
		return false;
	}
 
	std::string cmdline;
    for (std::string arg; std::getline(in, arg, '\0');)
	{       
        cmdline += (arg + " ");
	}
	in.close();

    cmdline = cmdline.substr(0, cmdline.size()-1);

    myself->set_pid(getpid());
    myself->set_cmdline(cmdline);
    myself->set_ppid(getppid());
    return true;
}

bool skip_hook(long syscall_number, long raw_args[6]) 
{
    // Don't try to elevate executable access checks for files that
    // are not executable at all. 
    if ((syscall_number != SYS_access) && (syscall_number != SYS_faccessat)) {
        return false;
    }
    struct stat statbuf;
    memset(&statbuf, 0, sizeof(statbuf));
    if (syscall_number == SYS_access) {
        if (raw_args[1] != X_OK) {
            return false;
        }
        if (stat((char*)raw_args[0], &statbuf) != 0) {
            return false;
        }
    } else { // faccessat
        if (raw_args[2] != X_OK) {
            return false;
        }
        if (fstatat(raw_args[0], (char*)raw_args[1], &statbuf, 0) != 0) {
            return false;
        }
    }
    auto p = statbuf.st_mode;
    return (!(p & S_IXUSR) && !(p & S_IXGRP) && !(p & S_IXOTH));
}

static void hook(long syscall_number, long raw_args[6], long int* result)
{
    if (skip_hook(syscall_number, raw_args)) {
        return;
    }

    Operation op;
    std::vector<int> fds;
    op.set_syscall_num(syscall_number);
    std::unique_ptr<SyscallMarshall> marshall(SyscallMarshallRegistry::New(syscall_number, raw_args));
    if (marshall == nullptr) {
            std::cerr << "Error: unexpected intercepted syscall: " << syscall_number << std::endl;
            return;
    }

    *op.mutable_args() = marshall->GetArgs();
    if (!get_myself(op.mutable_caller())) {
        return;
    }

    auto fd_cwd = marshal_fds(&op, &fds);

    UnixSocket socket;
    socket.connect(Address::NewUnixAddress(fs::path("/tmp") / GUARDO_SOCK_NAME));    

    ChallengeRequest challenge_req;
    socket.sendmsg(create_raw_msg(CHALLENGE_REQUEST, challenge_req), std::vector<int>());
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
    socket.sendmsg(create_raw_msg(ELEVATION_REQUEST, elevation_request), fds);

    fds.clear();
    
    ElevationResponse elevation_response;
    if (!read_expected_msg_with_fd(&socket, ELEVATION_RESPONSE, &elevation_response, &fds)) {
        return;
    }

    if (!unmarshal_fds(&elevation_response, fds)) {
        for (auto& fd : fds) {
            close(fd);
        }
        return;
    }

    *result = marshall->ProcessResponse(elevation_response);
}

thread_local bool in_hook = false; 

static int safe_hook(long syscall_number,
                     long arg0, 
                     long arg1,
                     long arg2, 
                     long arg3, 
                     long arg4, 
                     long arg5,
                     long *result)
{
    if (!SyscallMarshallRegistry::IsRegistered(syscall_number)) {
        return 1;
    }

    long real_result = syscall_no_intercept(syscall_number, arg0, arg1, arg2, arg3, arg4, arg5);
    *result = real_result;
    if ((real_result != -EACCES) && (real_result != -EPERM)) {
        return 0;
    }
    // avoid hook loops
    if (in_hook) {
        return 0;
    }

    in_hook = true;
    try {
        long raw_args[6] = {arg0, arg1, arg2, arg3, arg4, arg5};
        hook(syscall_number, raw_args, result);
    } catch ( const std::exception & e ) { /* don't throw from hook */
        print_exception( e );
    } catch (...) {
        std::cerr << "Unknown exeception caught in hook" << std::endl;
    }
    in_hook = false;
    return 0;
}

} // namespace guardian_agent

static __attribute__((constructor)) void
init(void)
{
	// Set up the callback function
	intercept_hook_point = guardian_agent::safe_hook;

    guardian_agent::Syscalls syscalls;
    if (!syscalls.ParseFromString(std::string(&_binary_syscalls_binproto_start, &_binary_syscalls_binproto_end - &_binary_syscalls_binproto_start))) {
        std::cerr << "Failed to parse syscalls proto" << std::endl;
    } 
 
    for (const auto& spec : syscalls.syscall()) {
        guardian_agent::SyscallMarshallRegistry::Register(spec);
    }
}
