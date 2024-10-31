#pragma once
#include <iostream>
#include <string>
#include <string_view>
#include <array>

#include <unistd.h>

#include "server_error.h"

class Variant {
public:
    static constexpr std::array<std::string_view, 1> Types = {
        "uint16_t",
    };

    static constexpr std::array<std::string_view, 1> Hashes = {
        "SHA224",
    };

    static constexpr std::array<std::string_view, 1> Sides = {
        "client",
    };
private:
    std::string type;
    std::string hash;
    std::string side;

public:
    Variant(int argc, char** argv);
    Variant() = delete;
    std::string_view getType() {
        return type;
    }
    std::string_view getHash() {
        return hash;
    }
    std::string_view getSide() {
        return side;
    }
    static void print_help_and_exit(int exit_code);
};
