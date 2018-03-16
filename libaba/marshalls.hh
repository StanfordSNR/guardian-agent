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
    virtual bool Process(const Argument& result, long int* raw_result) = 0;
    virtual ~ResultProcessor() {}
};

class SyscallMarshall {
public:
    virtual google::protobuf::RepeatedPtrField<Argument> GetArgs() { return args; };
    virtual long ProcessResponse(const ElevationResponse& response);

    virtual ~SyscallMarshall() {}

protected: 
    google::protobuf::RepeatedPtrField<Argument> args;
    std::vector<std::unique_ptr<ResultProcessor>> result_processors;
};

class SyscallMarshallRegistry 
{
public:
    typedef std::function<SyscallMarshall*(long raw_args[6])> FactoryFunc;

    static void Register(long syscall_number, FactoryFunc factory_func);
    static void Register(const SyscallSpec& spec);
    static bool IsRegistered(long syscall_number);

    static SyscallMarshall* New(long syscall_number, long raw_args[6]); 

private:
    typedef std::map<int, FactoryFunc> Registry;

    static Registry* Get();
};

}  // namespace guardian_agent

#endif /* MARSHALLS_HH */