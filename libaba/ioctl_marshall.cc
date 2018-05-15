#include "ioctl_marshall.hh"

#include <syscall.h>

namespace guardian_agent {

REGISTER_SYSCALL_MARSHAL(SYS_ioctl, IoctlMarshll)

}