#include "marshalls.hh"

#include <cassert>
#include <fcntl.h>
#include <syscall.h>

namespace guardian_agent {

using google::protobuf::RepeatedPtrField;    

class FdProcessor : public ResultProcessor 
{
public:
    FdProcessor(long int* result)
    : result(result)
    {}

    bool Process(const Argument& arg) 
    {
        if (arg.arg_case() != Argument::kFdArg) {
            return false;
        }
        *result = arg.fd_arg().fd();
        return true;
    }

private:
    long int* result;
};

class IntProcessor : public ResultProcessor 
{
public:
    IntProcessor(long int* result)
    : result(result)
    {}

    bool Process(const Argument& arg) 
    {
        if (arg.arg_case() != Argument::kIntArg) {
            return false;
        }
        *result = arg.int_arg();
        return true;
    }

private:
    long int* result;
};

class OutBufferProcessor : public ResultProcessor 
{
public:
    OutBufferProcessor(void* buffer, size_t buffer_size)
    : buf(buffer), count(buffer_size) {}

    bool Process(const Argument& arg)
    {
        if (arg.arg_case() != Argument::kBytesArg) {
            return false;
        }
        if (arg.bytes_arg().size() > count) {
            return false;
        }
        memcpy(buf, arg.bytes_arg().data(), arg.bytes_arg().size());
        return true;
    }

private:
    void* buf;
    size_t count;
};

class DynamicMarshall : public SyscallMarshall 
{
public:
    DynamicMarshall(const SyscallSpec& spec, long raw_args[6], long int* result) 
    : SyscallMarshall(result)
    {
        switch (spec.retval()) {
            case Param::INT32:
                result_processors.push_back(std::unique_ptr<ResultProcessor>(new IntProcessor(result)));
                break;
            case Param::FD:
                result_processors.push_back(std::unique_ptr<ResultProcessor>(new FdProcessor(result)));
                break;
            case Param::UNKNOWN:
                break;
            default:
                std::cerr << "Unexpected retval type: " << spec.retval() << std::endl;
        }
        if (spec.add_fd_cwd()) {
            args.Add()->mutable_dir_fd_arg()->set_fd(AT_FDCWD);            
        }

        for (int i = 0; i < spec.params_size(); ++i) {
            const auto& param = spec.params(i);
            switch (param.type()) {
                case Param::INT32:
                    args.Add()->set_int_arg(raw_args[i]);
                    break;
                case Param::STRING:
                    args.Add()->set_string_arg((const char*)raw_args[i]);
                    break;
                case Param::FD:
                    args.Add()->mutable_fd_arg()->set_fd(raw_args[i]);
                    break;
                case Param::DIR_FD:
                    args.Add()->mutable_dir_fd_arg()->set_fd(raw_args[i]);
                    break;
                case Param::IN_BUFFER: {
                    size_t len = param.const_len();
                    if (param.len_param_name() != "") {
                        int len_param = find_param(spec, param.len_param_name());
                        if (len_param >= 0) {
                            len = raw_args[len_param];
                        }
                    }
                    args.Add()->set_bytes_arg(std::string((const char*)raw_args[i], len));
                    break;
                }
                case Param::OUT_BUFFER: {
                    size_t len = param.const_len();
                    if (param.len_param_name() != "") {
                        int len_param = find_param(spec, param.len_param_name());
                        if (len_param >= 0) {
                            len = raw_args[len_param];
                        }
                    }
                    args.Add()->mutable_out_buffer_arg()->set_len(len);
                    result_processors.push_back(
                        std::unique_ptr<ResultProcessor>(new OutBufferProcessor((void*)raw_args[i], len)));
                    break;
                }
                default:
                    std::cerr << "Unknown param type: %d" << param.type() << std::endl;
            }
        }
    }

private:
    static int find_param(const SyscallSpec& spec, const std::string& name) 
    {
        for (int i = 0; i < spec.params_size(); ++i) {
            if (spec.params(i).name() == name) {
                return i;
            }
        }
        return -1;
    }
};


SyscallMarshallRegistry::Registry* SyscallMarshallRegistry::Get() 
{
    static Registry registry;
    return &registry;
}

bool SyscallMarshallRegistry::IsRegistered(long syscall_number)
{
    auto& registry = *Get();
    return (registry.find(syscall_number) != registry.end());
}

template<class T>
class Registrar
{
public:
    Registrar(int syscall_number) 
    { 
        std::cerr << "Register " <<  "(" << syscall_number << ")" << std::endl;
        SyscallMarshallRegistry::Register(syscall_number, [](long raw_args[6], long int* result){ return new T(raw_args, result); });
    }
};

#define REGISTER_SYSCALL_MARSHAL(sycall_number, class_name) \
static Registrar<class_name> register_##sycall_number(sycall_number);

void SyscallMarshallRegistry::Register(long syscall_number, FactoryFunc factory_func) 
{
    auto& registry = *Get();
    assert(registry.find(syscall_number) == registry.end());
    registry[syscall_number] = factory_func;
}

void SyscallMarshallRegistry::Register(const SyscallSpec& spec)
{
    std::cerr << "Register " << spec.name() << "(" << spec.num() << ")" << std::endl;
    Register(spec.num(), [spec](long raw_args[6], long int* result){ return new DynamicMarshall(spec, raw_args, result); });
}

SyscallMarshall* SyscallMarshallRegistry::New(long syscall_number, long raw_args[6], long int* result)
{
    auto& registry = *Get();
    auto factory_func = registry.find((int)syscall_number);
    if (factory_func == registry.end()) {
        return nullptr;
    } else {
        return (factory_func->second)(raw_args, result);
    }
}

void SyscallMarshall::ProcessResponse(const ElevationResponse& response) 
{ 
    *result = -response.errno_code();
    if (response.results_size() > (int)result_processors.size()) {
        *result = -1;
        return;
    }
    for (int i = 0; i < response.results_size(); ++i) {
        if (!result_processors[i]->Process(response.results(i))) {
            *result = -1;
        }
    }
}

}  // namespace guardian_agent