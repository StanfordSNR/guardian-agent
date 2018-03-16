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
    virtual google::protobuf::RepeatedPtrField<Argument> GetArgs() { return args; };
    virtual void ProcessResponse(const ElevationResponse& response);

    virtual ~SyscallMarshall() {}

protected: 
    friend class SyscallMarshallRegistry;
    
    virtual void Prepare() = 0;
    long arg0, arg1, arg2, arg3, arg4, arg5;
    long int* result;
    google::protobuf::RepeatedPtrField<Argument> args;
    std::vector<std::unique_ptr<ResultProcessor>> result_processors;
};

class SyscallMarshallRegistry 
{
public:
    static void Register(long syscall_number, std::function<SyscallMarshall*()> factory_func);
    static void Register(const SyscallSpec& spec);
    static bool IsRegistered(long syscall_number);

    static SyscallMarshall* New(long syscall_number, long arg0, long arg1, long arg2, long arg3, long arg4, long arg5, long int* result); 

private:
    typedef std::map<int, std::function<SyscallMarshall*()>> Registry;

    static Registry* Get();
};

}  // namespace guardian_agent

#endif /* MARSHALLS_HH */