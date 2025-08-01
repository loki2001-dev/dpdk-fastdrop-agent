#include <atomic>
#include <array>
#include <chrono>
#include <csignal>
#include <iostream>
#include <memory>
#include <thread>
#include <unistd.h>
#include <fstream>
#include <string>

#include "dpdk/dpdk_init.h"

std::atomic<bool> running{true};

void signal_handler(int) {
    running = false;
}

const std::array<int, 6> handled_signals = {
    SIGINT, SIGTERM, SIGTSTP, SIGHUP, SIGQUIT, SIGUSR1
};

void initialize() {
    // signal
    for (int sig : handled_signals) {
        std::signal(sig, signal_handler);
    }
}

int32_t main(int32_t argc, char *argv[]) {
    initialize();

    const auto dpdk_initializer = std::make_shared<dpdk_init>();

    while (running) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    return EXIT_SUCCESS;
}