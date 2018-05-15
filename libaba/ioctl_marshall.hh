#ifndef IOCTL_MARSHALL_HH
#define IOCTL_MARSHALL_HH

#include "marshalls.hh"

#include <net/if.h>

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <string>

namespace guardian_agent {

using namespace std;

class IoctlMarshll : public SyscallMarshall {
public:
    IoctlMarshll(long raw_args[6]) {
        args.Add()->mutable_fd_arg()->set_fd(raw_args[0]);
        args.Add()->set_int_arg(raw_args[1]);
        long request = raw_args[1];

        if (request == SIOCGIFFLAGS) {
            args.Add()->set_in_out_buffer_arg(std::string((const char*)raw_args[2], sizeof(ifreq)));
            result_processors.push_back(
                std::unique_ptr<ResultProcessor>(new OutBufferProcessor((void*)raw_args[2], sizeof(ifreq))));   
            return;
        } else if (request == SIOCSIFFLAGS) {
            args.Add()->set_bytes_arg(std::string((const char*)raw_args[2], sizeof(ifreq)));
            return;
        }
        short buf_length = (request >> 16) & 0x3fff;
        char read_write = request >> 30;
        if ((read_write & 2) != 0) {
            args.Add()->set_bytes_arg(std::string((const char*)raw_args[2], buf_length));
        }
        if ((read_write & 1) != 0) {
            args.Add()->mutable_out_buffer_arg()->set_len(buf_length);
            result_processors.push_back(
                std::unique_ptr<ResultProcessor>(new OutBufferProcessor((void*)raw_args[2], buf_length)));   
        }
    }
};

}

#endif // IOCTL_MARSHALL_HH
