#include "opensabba/volume_nodes.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#ifdef __linux__
#include <cerrno>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#endif
using opensabba::pstream::Value;
void check(bool condition) {
    if (!condition) throw std::runtime_error("directory node test failed");
}
const Value::Object& fields(const Value& value) { return std::get<Value::Object>(value.data); }
int main() {
    const std::vector<opensabba::DirectoryNode> entries{
        {".",true,false},{"..",true,false},{"folder",true,false},
        {"file",false,false},{"link",false,true},{"hidden .name",true,false}};
    const auto all = opensabba::directory_node_values("/",false,entries);
    check(all.size() == 4 && fields(all[0]).size() == 3);
    check(fields(all[0]).at("name") == Value{std::string("folder")});
    check(fields(all[0]).at("path") == Value{std::string("/folder")});
    check(fields(all[1]).at("is_dir") == Value{std::uint64_t{0}});
    check(fields(all[2]).at("is_dir") == Value{std::uint64_t{1}});
    const auto dirs = opensabba::directory_node_values("/parent/",true,entries);
    check(dirs.size() == 3 && fields(dirs[0]).at("path") ==
          Value{std::string("/parent//folder")}); // Official agent preserves caller spelling.
    check(opensabba::directory_node_values("/empty",true,{}).empty());
#ifdef __linux__
    namespace fs = std::filesystem;
    char temporary[] = "/tmp/opensabba-directory-nodes-XXXXXX";
    const auto* created = mkdtemp(temporary);
    check(created != nullptr);
    const fs::path root(created);
    struct Cleanup { fs::path path; ~Cleanup() {
        for (const auto* name : {"blocked","readable-without-search"}) {
            if (fs::exists(path/name)) fs::permissions(path/name,fs::perms::owner_all,fs::perm_options::add);
        }
        fs::remove_all(path);
    } } cleanup{root};
    fs::create_directory(root/"folder");
    fs::create_directory(root/"folder"/"grandchild");
    fs::create_directory(root/"empty");
    fs::create_directory(root/"blocked");
    std::ofstream(root/"file") << "content";
    std::ofstream(root/".hidden") << "hidden";
    fs::create_directory_symlink("folder",root/"directory-link");
    fs::create_symlink("file",root/"file-link");
    fs::create_symlink("missing",root/"dangling-link");
    check(mkfifo((root/"fifo").c_str(),0600) == 0);
    const auto listing = opensabba::directory_nodes(root.string(),false);
    check(listing.error_code == 0 && listing.nodes.size() == 9);
    for (const auto& node : listing.nodes) {
        const auto& item = fields(node);
        const auto name = std::get<std::string>(item.at("name").data);
        check(item.size() == 3 && item.at("path") == Value{root.string()+"/"+name});
        const auto expected = name == "folder" || name == "empty" || name == "blocked" ||
                              name.ends_with("-link");
        check(item.at("is_dir") == Value{std::uint64_t{expected}});
    }
    check(opensabba::directory_nodes(root.string(),true).nodes.size() == 6);
    check(opensabba::directory_nodes((root/"empty").string(),false).nodes.empty());
    const auto followed = opensabba::directory_nodes((root/"directory-link").string(),true);
    check(followed.error_code == 0 && followed.nodes.size() == 1 &&
          fields(followed.nodes[0]).at("path") ==
              Value{(root/"directory-link"/"grandchild").string()});
    for (const auto& [name,error] : std::vector<std::pair<std::string,int>>{
             {"missing",ENOENT},{"file",ENOTDIR},{"file-link",ENOTDIR},{"dangling-link",ENOENT}}) {
        const auto result = opensabba::directory_nodes((root/name).string(),true);
        check(result.nodes.empty() && result.error_code ==
              static_cast<std::uint64_t>(-static_cast<std::int64_t>(error)));
    }
    const auto roots = opensabba::directory_nodes("/",true);
    check(roots.error_code == 0 && !roots.nodes.empty());
    for (const auto& node : roots.nodes)
        check(!std::get<std::string>(fields(node).at("path").data).starts_with("//"));
    check(chmod(root.c_str(),0755) == 0 && chmod((root/"blocked").c_str(),0000) == 0);
    fs::create_directory(root/"readable-without-search");
    std::ofstream(root/"readable-without-search"/"child") << "content";
    check(chmod((root/"readable-without-search").c_str(),0444) == 0);
    const auto child = fork();
    check(child >= 0);
    if (!child) {
        if (geteuid() == 0 && (setgid(65534) != 0 || setuid(65534) != 0)) _exit(2);
        const auto denied = opensabba::directory_nodes((root/"blocked").string(),true);
        const auto no_search = opensabba::directory_nodes((root/"readable-without-search").string(),false);
        _exit(denied.error_code == static_cast<std::uint64_t>(-std::int64_t{EACCES}) &&
              denied.nodes.empty() && no_search.error_code == 0 && no_search.nodes.empty() ? 0 : 3);
    }
    int status = 0;
    check(waitpid(child,&status,0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
#endif
    std::cout << "Official agent directory nodes and filesystem outcomes passed\n";
}
