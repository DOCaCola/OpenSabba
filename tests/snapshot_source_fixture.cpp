// Native service fixture: redirect only declared device aliases into specimen
// files. Production ReadyMachineCapture/SnapshotReader/ImageSource stay intact.
#include "../src/synosnap_abi.hpp"
#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <fcntl.h>
#include <fstream>
#include <map>
#include <mutex>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <linux/fs.h>
#include <unistd.h>
#include <vector>
namespace {
struct Device {
    std::string kind,path,file,uuid,origin,cow;
    unsigned major{},minor{};
    std::uint64_t offset{},length{},sequence{};
};
template<class T> T real(const char* name) { return reinterpret_cast<T>(dlsym(RTLD_NEXT,name)); }
std::vector<Device>& devices() {
    static auto* result = new std::vector<Device>;
    static const bool loaded = [] {
        const auto* path = std::getenv("OPENSABBA_SOURCE_FIXTURE");
        if (!path) std::abort();
        auto* input = real<FILE*(*)(const char*,const char*)>("fopen")(path,"r");
        if (!input) std::abort();
        char* line=nullptr; std::size_t capacity=0;
        while (getline(&line,&capacity,input)>0) {
            Device entry;
            std::istringstream text(line);
            text >> entry.kind >> entry.path >> entry.file >> entry.offset >> entry.length
                 >> entry.major >> entry.minor >> entry.sequence >> entry.uuid >> entry.origin >> entry.cow;
            if (!text) std::abort();
            result->push_back(std::move(entry));
        }
        std::free(line); std::fclose(input);
        return true;
    }();
    (void)loaded;
    return *result;
}
struct ReadFault {
    std::string path;
    std::uint64_t offset = 0, length = 0;
    int error = 0, snapshot_error = 0, cancelled = 0;
    bool triggered = false;
};
ReadFault& read_fault() {
    static ReadFault fault = [] {
        ReadFault value;
        if (const auto* spec = std::getenv("OPENSABBA_SOURCE_READ_FAULT")) {
            std::istringstream in(spec);
            in >> value.path >> value.offset >> value.length >> value.error >> value.snapshot_error >> value.cancelled;
            if (!in) std::abort();
        }
        return value;
    }();
    return fault;
}
std::map<int,Device>& descriptors() { static auto* value=new std::map<int,Device>; return *value; }
std::mutex& mutex() { static auto* value=new std::mutex; return *value; }
const Device* match(const char* path) {
    const auto& rows=devices();
    const auto found=std::find_if(rows.begin(),rows.end(),[&](const auto& row){return row.path==path;});
    return found==rows.end()?nullptr:&*found;
}
bool reserved(const char* path) {
    return std::string(path).starts_with("/dev/synosnap") ||
           std::string(path).starts_with("/sys/class/block/synosnap");
}
void descriptor_record(const char* event,const Device& device,int fd,int flags,
                       std::uint64_t offset = 0,std::size_t length = 0,std::size_t alignment = 0) {
    const auto* path = std::getenv("OPENSABBA_SOURCE_DESCRIPTOR_TRACE");
    if (!path) return;
    const auto output = real<int(*)(const char*,int,...)>("open")(path,O_WRONLY|O_CREAT|O_APPEND,0600);
    const auto line = std::string(event)+" "+device.kind+" "+device.path+" "+std::to_string(fd)+" "+
        std::to_string(flags)+" "+std::to_string(offset)+" "+std::to_string(length)+" "+
        std::to_string(alignment)+"\n";
    if (output < 0 || write(output,line.data(),line.size()) != static_cast<ssize_t>(line.size())) std::abort();
    real<int(*)(int)>("close")(output);
}
void record(const Device& device, std::uint64_t offset, std::size_t length) {
    const auto* path=std::getenv("OPENSABBA_SOURCE_TRACE");
    if (!path) std::abort();
    const auto fd=real<int(*)(const char*,int,...)>("open")(path,O_WRONLY|O_CREAT|O_APPEND,0600);
    const auto line=device.kind+" "+device.path+" "+std::to_string(offset)+" "+std::to_string(length)+"\n";
    if (fd<0 || write(fd,line.data(),line.size())!=static_cast<ssize_t>(line.size())) std::abort();
    real<int(*)(int)>("close")(fd);
}
int open_source(const char* path,int flags,mode_t mode,const char* symbol) {
    const auto* device=match(path);
    if (!device && reserved(path)) { errno=ENOENT; return -1; }
    const auto fd=real<int(*)(const char*,int,...)>(symbol)(device?device->file.c_str():path,flags,mode);
    if (device && fd>=0) {
        std::lock_guard guard(mutex()); descriptors()[fd]=*device;
        descriptor_record("open",*device,fd,flags);
    }
    return fd;
}
template<class T> void describe(int fd,T* value) {
    std::lock_guard guard(mutex());
    const auto found=descriptors().find(fd);
    if (found==descriptors().end())return;
    const auto& device=found->second;
    if (device.kind=="control")value->st_mode=(value->st_mode&0777)|S_IFCHR;
    if (device.kind=="snap" || device.kind=="raw") {
        value->st_mode=(value->st_mode&0777)|S_IFBLK;
        value->st_rdev=makedev(device.major,device.minor);
    }
}
}
extern "C" int open(const char* path,int flags,...) {
    va_list args;va_start(args,flags);const auto mode=flags&O_CREAT?va_arg(args,mode_t):0;va_end(args);
    return open_source(path,flags,mode,"open");
}
extern "C" int open64(const char* path,int flags,...) {
    va_list args;va_start(args,flags);const auto mode=flags&O_CREAT?va_arg(args,mode_t):0;va_end(args);
    return open_source(path,flags,mode,"open64");
}
extern "C" FILE* fopen(const char* path,const char* mode) {
    const auto* device=match(path);
    if (!device && reserved(path)) { errno=ENOENT; return nullptr; }
    return real<FILE*(*)(const char*,const char*)>("fopen")(device?device->file.c_str():path,mode);
}
extern "C" FILE* fopen64(const char* path,const char* mode) {
    const auto* device=match(path);
    if (!device && reserved(path)) { errno=ENOENT; return nullptr; }
    return real<FILE*(*)(const char*,const char*)>("fopen64")(device?device->file.c_str():path,mode);
}
extern "C" int close(int fd) {
    { std::lock_guard guard(mutex()); descriptors().erase(fd); }
    return real<int(*)(int)>("close")(fd);
}
extern "C" int fstat(int fd,struct stat* value) {
    const auto result=real<int(*)(int,struct stat*)>("fstat")(fd,value);
    if (!result)describe(fd,value);
    return result;
}
extern "C" int fstat64(int fd,struct stat64* value) {
    const auto result=real<int(*)(int,struct stat64*)>("fstat64")(fd,value);
    if (!result)describe(fd,value);
    return result;
}
extern "C" ssize_t pread(int fd,void* bytes,size_t length,off_t offset) {
    std::lock_guard guard(mutex());
    const auto found=descriptors().find(fd);
    if (found!=descriptors().end()) {
        const auto& device=found->second;
        if (offset<0 || static_cast<std::uint64_t>(offset)>device.length ||
            length>device.length-static_cast<std::uint64_t>(offset)) { errno=EIO;return -1; }
        record(device,offset,length);
        descriptor_record("read",device,fd,real<int(*)(int,int,...)>("fcntl")(fd,F_GETFL),
            static_cast<std::uint64_t>(offset),length,reinterpret_cast<std::uintptr_t>(bytes)%4096);
        // the official agent's reader can return a positive short read followed by EOF.
        // Keep geometry unchanged and limit this specimen to one raw interval.
        if (std::getenv("OPENSABBA_RAW_EOF") && device.kind == "raw" && device.path == "/dev/sda" &&
            offset < 1024*1024) {
            if (offset >= 512) return 0;
            length = std::min(length,static_cast<std::size_t>(512-offset));
        }
        auto& fault = read_fault();
        if (device.path == fault.path && static_cast<std::uint64_t>(offset) < fault.offset+fault.length &&
            fault.offset < static_cast<std::uint64_t>(offset)+length) {
            fault.triggered = true; errno = fault.error; return -1;
        }
        offset+=device.offset;
    }
    return real<ssize_t(*)(int,void*,size_t,off_t)>("pread")(fd,bytes,length,offset);
}
extern "C" ssize_t pread64(int fd,void* bytes,size_t length,off64_t offset) {return pread(fd,bytes,length,offset);}
extern "C" int ioctl(int fd,unsigned long request,...) {
    va_list args;va_start(args,request);auto* value=va_arg(args,void*);va_end(args);
    std::lock_guard guard(mutex());
    const auto found=descriptors().find(fd);
    if (found==descriptors().end())return real<int(*)(int,unsigned long,void*)>("ioctl")(fd,request,value);
    const auto& device=found->second;
    if (request==BLKGETSIZE64) {*static_cast<std::uint64_t*>(value)=device.length;return 0;}
    if (request==BLKSSZGET) {*static_cast<int*>(value)=512;return 0;}
    if (request==BLKGETDISKSEQ) {*static_cast<std::uint64_t*>(value)=device.sequence;return 0;}
    if (device.kind=="control") {
        using namespace opensabba::synosnap_abi;
        if (request==info) {
            if (device.sequence) {errno=EIO;return -1;}
            auto& output=*static_cast<Info*>(value);
            const auto selected=std::find_if(devices().begin(),devices().end(),[&](const auto& row){
                return row.kind=="snap" && row.minor==output.minor;
            });
            if(selected==devices().end()){errno=ENOENT;return -1;}
            output={};output.minor=selected->minor;output.state=3;output.sequence=selected->sequence;
            for(unsigned i=0;i<16;++i)output.uuid[i]=std::stoul(selected->uuid.substr(2*i,2),nullptr,16);
            std::strcpy(output.origin,selected->origin.c_str());std::strcpy(output.cow,selected->cow.c_str());
            output.version=1;
            const auto& fault = read_fault();
            if (fault.triggered && selected->path == fault.path) {
                output.error = fault.snapshot_error;
                output.cancelled = static_cast<std::uint8_t>(fault.cancelled);
            }
            return 0;
        }
        if (request==free_minor) {*static_cast<std::int32_t*>(value)=16;return 0;}
        // No fixture command may mutate the real driver or install reload hooks.
        errno=EIO;return -1;
    }
    errno=EINVAL;return -1;
}

// Hold only this fixture's source-publication syscall, letting independent
// event handling continue without relying on repeated NAS task polling.
extern "C" int renameat(int olddir,const char* oldname,int newdir,const char* newname) {
    const auto result = real<int(*)(int,const char*,int,const char*)>("renameat")(
        olddir,oldname,newdir,newname);
    const auto* gate = std::getenv("OPENSABBA_SOURCE_PUBLICATION_GATE");
    static std::atomic_bool held{false};
    if (!result && gate && std::strcmp(newname,"service-source.pstream") == 0 && !held.exchange(true)) {
        if (fsync(newdir)) std::abort();
        const auto descriptor = real<int(*)(const char*,int,...)>("open")(gate,O_WRONLY|O_CREAT|O_EXCL,0600);
        if (descriptor < 0 || close(descriptor)) std::abort();
        const auto release = std::string(gate)+".release";
        unsigned attempts = 0;
        while (access(release.c_str(),F_OK)) {
            if (++attempts > 6000) std::abort();
            usleep(5000);
        }
    }
    return result;
}
