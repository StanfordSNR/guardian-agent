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

class IntProcessor : public ResultProcessor 
{
public:
    bool Process(const Argument& arg, long* raw_result);
};

class OutBufferProcessor : public ResultProcessor 
{
public:
    OutBufferProcessor(void* buffer, size_t buffer_size);

    bool Process(const Argument& arg, long*);

private:
    void* buf;
    size_t count;
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
    typedef std::unordered_map<int, FactoryFunc> Registry;

    static Registry* Get();
};

template<class T>
class Registrar
{
public:
    Registrar(int syscall_number) 
    { 
        SyscallMarshallRegistry::Register(syscall_number, [](long raw_args[6]){ return new T(raw_args); });
    }
};

#define REGISTER_SYSCALL_MARSHAL(sycall_number, class_name) \
static Registrar<class_name> register_##sycall_number(sycall_number);


}  // namespace guardian_agent

#endif /* MARSHALLS_HH */