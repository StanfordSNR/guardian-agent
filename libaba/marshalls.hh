#ifndef MARSHALLS_HH
#define MARSHALLS_HH

#include "guardo.pb.h"

#include <map>
#include <memory>
#include <functional>

namespace guardian_agent {

class ResultProcessor 
{
public:
    virtual bool Process(const Argument& result) = 0;
    virtual ~ResultProcessor() {}
};

class SyscallMarshall {
public:
    static SyscallMarshall* New(long syscall_number, long arg0, long arg1, long arg2, long arg3, long arg4, long arg5, long int* result); 

    virtual bool ShouldHook() { return true; }
    virtual google::protobuf::RepeatedPtrField<Argument> GetArgs() { return args; };
    virtual void ProcessResponse(const ElevationResponse& response);

    virtual ~SyscallMarshall() {}

    typedef std::map<int, std::function<SyscallMarshall*()>> Registry;
    static Registry registry;

protected: 
    virtual void Prepare() = 0;
    long arg0, arg1, arg2, arg3, arg4, arg5;
    long int* result;
    google::protobuf::RepeatedPtrField<Argument> args;
    std::vector<std::unique_ptr<ResultProcessor>> result_processors;
};



}  // namespace guardian_agent

#endif /* MARSHALLS_HH */