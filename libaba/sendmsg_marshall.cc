#include "sendmsg_marshall.hh"

#include <syscall.h>

namespace guardian_agent {

REGISTER_SYSCALL_MARSHAL(SYS_sendmsg, SendmsgMarshll)

}