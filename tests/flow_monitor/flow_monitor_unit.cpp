// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#define CATCH_CONFIG_MAIN
#include "catch_wrapper.hpp"
#include "cxplat_fault_injection.h"
#include "cxplat_passed_test_log.h"
#include "ebpf_flow_hooks.h"
#include "ebpf_flow_program_attach_type_guids.h"
#include "utils.h"
#include "watchdog.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <ebpf_api.h>
#include <iostream>
#include <string>
#include <thread>

struct _DEVICE_OBJECT* _ebpf_ext_driver_device_object;

CATCH_REGISTER_LISTENER(_watchdog)
CATCH_REGISTER_LISTENER(cxplat_passed_test_log)

#define MAX_FLOW_EVENTS 100
#define FLOW_EVENT_TEST_TIMEOUT_SEC 30

// Must match the structure in flow_monitor.c
typedef struct _flow_event_info
{
    uint32_t local_addr_v4;      ///< Local IPv4 address (network byte order)
    uint32_t remote_addr_v4;     ///< Remote IPv4 address (network byte order)
    uint16_t local_port;         ///< Local port (network byte order)
    uint16_t remote_port;        ///< Remote port (network byte order)
    uint8_t  protocol;           ///< IP protocol (TCP/UDP/etc)
    uint8_t  direction;          ///< 0 = inbound, 1 = outbound
    uint64_t flow_handle;        ///< WFP flow handle
    uint32_t data_length;        ///< Length of data in the flow
    uint64_t timestamp;          ///< Timestamp when the event occurred
    uint32_t action;             ///< Action taken on the flow (ALLOW/BLOCK/NEED_MORE_DATA)
    uint8_t  event_type;         ///< Type of flow event
} flow_event_info_t;

// Event types (must match flow_monitor.c)
#define FLOW_EVENT_TYPE_NEW_FLOW        1
#define FLOW_EVENT_TYPE_DATA_RECEIVED   2
#define FLOW_EVENT_TYPE_FLOW_CLOSED     3

static volatile uint32_t flow_event_count = 0;

int
flow_monitor_event_callback(void* ctx, void* data, size_t size)
{
    // Parameter checks.
    UNREFERENCED_PARAMETER(ctx);
    if (data == nullptr || size == 0) {
        return 0;
    }

    if (size != sizeof(flow_event_info_t)) {
        std::cerr << "Unexpected flow event size: " << size 
                  << " (expected: " << sizeof(flow_event_info_t) << ")" << std::endl;
        return 0;
    }

    flow_event_info_t* event = static_cast<flow_event_info_t*>(data);
    flow_event_count++;

    // Log the event for debugging
    std::cout << "Flow event [" << flow_event_count << "]: "
              << "Type=" << (int)event->event_type
              << ", Protocol=" << (int)event->protocol
              << ", Action=" << event->action
              << ", DataLen=" << event->data_length
              << std::endl;

    return 0;
}

TEST_CASE("flow_monitor_basic_test", "[flow_monitor]")
{
    // Allow some time for previous tests to clean up
    std::this_thread::sleep_for(std::chrono::seconds(2));

    struct bpf_object* object = nullptr;
    struct bpf_program* flow_program = nullptr;
    struct bpf_link* flow_link = nullptr;
    struct ring_buffer* ring = nullptr;

    // Load the flow monitor BPF program
    object = bpf_object__open("flow_monitor.sys");
    REQUIRE(object != nullptr);

    int res = bpf_object__load(object);
    REQUIRE(res == 0);

    // Find and attach to the flow monitor BPF program
    flow_program = bpf_object__find_program_by_name(object, "FlowMonitor");
    REQUIRE(flow_program != nullptr);

    // Attach the program to the flow classify hook
    ebpf_result_t result = ebpf_program_attach(
        flow_program, &EBPF_ATTACH_TYPE_FLOW_CLASSIFY, nullptr, 0, &flow_link);
    REQUIRE(result == EBPF_SUCCESS);
    REQUIRE(flow_link != nullptr);

    // Attach to the eBPF ring buffer event map
    bpf_map* flow_events_map = bpf_object__find_map_by_name(object, "flow_events_map");
    REQUIRE(flow_events_map != nullptr);
    
    ring = ring_buffer__new(bpf_map__fd(flow_events_map), flow_monitor_event_callback, nullptr, nullptr);
    REQUIRE(ring != nullptr);

    std::cout << "Flow monitor test setup complete. Monitoring for events..." << std::endl;

    // Monitor for flow events for a short time
    uint32_t initial_event_count = flow_event_count;
    auto start_time = std::chrono::high_resolution_clock::now();
    
    while (std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::high_resolution_clock::now() - start_time).count() < FLOW_EVENT_TEST_TIMEOUT_SEC) {
        
        // Poll the ring buffer for events
        int poll_result = ring_buffer__poll(ring, 100); // 100ms timeout
        if (poll_result < 0 && poll_result != -EINTR) {
            std::cerr << "ring_buffer__poll failed: " << poll_result << std::endl;
            break;
        }

        // Check if we received any events
        if (flow_event_count > initial_event_count) {
            std::cout << "Received " << (flow_event_count - initial_event_count) << " flow events" << std::endl;
            break;
        }

        // Short sleep to avoid busy-waiting
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    // Test passes if we successfully set up monitoring (events are optional since they depend on actual traffic)
    std::cout << "Flow monitor test completed. Total events: " << flow_event_count << std::endl;

    // Cleanup
    if (ring) {
        ring_buffer__free(ring);
    }
    if (flow_link) {
        int link_fd = bpf_link__fd(flow_link);
        bpf_link_detach(link_fd);
        bpf_link__destroy(flow_link);
    }
    if (object) {
        bpf_object__close(object);
    }
}

TEST_CASE("flow_monitor_program_test_run", "[flow_monitor]")
{
    // Test the flow monitor program using bpf_prog_test_run_opts
    struct bpf_object* object = nullptr;
    struct bpf_program* flow_program = nullptr;

    // Load the flow monitor BPF program
    object = bpf_object__open("flow_monitor.sys");
    REQUIRE(object != nullptr);

    int res = bpf_object__load(object);
    REQUIRE(res == 0);

    // Find the flow monitor program
    flow_program = bpf_object__find_program_by_name(object, "FlowMonitor");
    REQUIRE(flow_program != nullptr);

    // Create test flow data
    flow_classify_md_t test_flow_ctx = {0};
    test_flow_ctx.local_addr_v4 = 0x0100007F;  // 127.0.0.1 in network byte order
    test_flow_ctx.remote_addr_v4 = 0x08080808; // 8.8.8.8 in network byte order
    test_flow_ctx.local_port = htons(9993);    // FLOWEBPFEXT_PORT_HTTPS
    test_flow_ctx.remote_port = htons(12345);
    test_flow_ctx.protocol = 6; // TCP
    test_flow_ctx.direction = 1; // outbound
    test_flow_ctx.flow_handle = 0x123456789ABCDEF0;

    // Test with HTTP GET request
    uint8_t http_data[] = "GET /api/test HTTP/1.1\r\nHost: example.com\r\n\r\n";
    test_flow_ctx.data_start = http_data;
    test_flow_ctx.data_end = http_data + sizeof(http_data) - 1;

    bpf_test_run_opts opts = {0};
    opts.ctx_in = &test_flow_ctx;
    opts.ctx_size_in = sizeof(test_flow_ctx);
    opts.data_in = http_data;
    opts.data_size_in = sizeof(http_data) - 1;

    fd_t program_fd = bpf_program__fd(flow_program);
    REQUIRE(program_fd != ebpf_fd_invalid);

    // Execute the program
    int result = bpf_prog_test_run_opts(program_fd, &opts);
    REQUIRE(result == 0);

    // Test with suspicious data (path traversal)
    uint8_t suspicious_data[] = "GET /../../../etc/passwd HTTP/1.1\r\n";
    test_flow_ctx.data_start = suspicious_data;
    test_flow_ctx.data_end = suspicious_data + sizeof(suspicious_data) - 1;

    opts.data_in = suspicious_data;
    opts.data_size_in = sizeof(suspicious_data) - 1;

    result = bpf_prog_test_run_opts(program_fd, &opts);
    REQUIRE(result == 0);

    // Cleanup
    if (object) {
        bpf_object__close(object);
    }
}
