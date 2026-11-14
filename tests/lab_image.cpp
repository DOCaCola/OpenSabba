#include "lab.hpp"
#include "opensabba/image.hpp"
#include <charconv>
#include <iostream>
#ifndef _WIN32
#include <cerrno>
#include <fcntl.h>
#include <unistd.h>
#endif
namespace opensabba {
using pstream::Value;
using pstream::Error;
int lab_image_command(int argc, char** argv) {
#ifdef _WIN32
    (void)argc; (void)argv;
    throw Error("image-stream currently requires Linux");
#else
    if (argc < 4) throw Error("usage: image-stream IMAGE OUTPUT [--image-name NAME] [--block-size BYTES] [--compression none|lz4]");
    std::string name = "opensabba-test.img";
    auto compression = TransferCompression::none;
    std::size_t block_size = 1024 * 1024;
    for (int i = 4; i < argc; i += 2) {
        if (i + 1 == argc) throw Error("missing image-stream option value");
        const std::string_view option(argv[i]), argument(argv[i + 1]);
        if (option == "--image-name") name = argument;
        else if (option == "--block-size") {
            const auto [end, error] = std::from_chars(argument.data(), argument.data() + argument.size(), block_size);
            if (error != std::errc{} || end != argument.data() + argument.size())
                throw Error("invalid image block size");
        } else if (option == "--compression") {
            if (argument == "none") compression = TransferCompression::none;
            else if (argument == "lz4") compression = TransferCompression::lz4;
            else throw Error("compression must be none or lz4");
        } else throw Error("unknown image-stream option");
    }
    validate_image_options(name, block_size);
    ImageSource source(argv[2]);
    const int output = open(argv[3], O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (output < 0) throw Error("cannot create stream output; choose a new file");
    bool complete = false;
    struct Cleanup {
        int fd; const char* path; bool& complete;
        ~Cleanup() { close(fd); if (!complete) unlink(path); }
    } cleanup{output, argv[3], complete};
    auto send = [&](const Value& value) {
        const auto bytes = pstream::encode(value);
        std::size_t sent = 0;
        while (sent < bytes.size()) {
            const auto count = write(output, bytes.data() + sent, bytes.size() - sent);
            if (count < 0 && errno == EINTR) continue;
            if (count <= 0) throw Error("cannot write image stream");
            sent += static_cast<std::size_t>(count);
        }
    };
    stream_image(source, name, block_size, send, {}, 0, compression);
    send(Value{Value::Object{{"close", Value{std::uint64_t{1}}}}});
    if (fsync(output) != 0) throw Error("cannot persist image stream");
    complete = true;
    std::cout << "Wrote offline upload data stream: " << source.size()
              << " image bytes. No NAS connection or backup was created.\n";
    return 0;
#endif
}
}
