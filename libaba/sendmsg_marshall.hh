#ifndef SENDMSG_MARSHALL_HH
#define SENDMSG_MARSHALL_HH

#include "marshalls.hh"

#include <sys/types.h>
#include <sys/socket.h>

#include <string>

namespace guardian_agent {

using namespace std;

class SendmsgMarshll : public SyscallMarshall {
public:
    SendmsgMarshll(long raw_args[6]) {
        // ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags);
        args.Add()->mutable_fd_arg()->set_fd(raw_args[0]);

        // Currently support only one IOV
        const msghdr* message_hdr = (const msghdr*)raw_args[1];
        if (message_hdr->msg_iovlen > 1) {
            std::cerr << "Got sendmsg with more than 1 iov....using only first one!" << std::endl;
        }

        if (message_hdr->msg_iovlen == 0) {
            args.Add()->set_bytes_arg("");            
        } else {
            args.Add()->set_bytes_arg(
                std::string((const char*)message_hdr->msg_iov->iov_base, 
                            message_hdr->msg_iov->iov_len));
        }

        if (message_hdr->msg_controllen == 0) {
            args.Add()->set_bytes_arg("");            
        } else {
            args.Add()->set_bytes_arg(
                std::string((const char*)message_hdr->msg_control, 
                            message_hdr->msg_controllen));
        }

        args.Add()->set_int_arg(raw_args[2]);

        result_processors.push_back(std::unique_ptr<ResultProcessor>(new IntProcessor));
    }
};

}

#endif // SENDMSG_MARSHALL_HH
