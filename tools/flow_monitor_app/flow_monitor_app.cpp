// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// This application monitors flow events from the flow_monitor BPF program

#include <iostream>
#include <chrono>
#include <thread>
#include <signal.h>
#include <iomanip>
#include <sstream>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

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

// Flow actions (must match flow extension)
#define ALLOW           0
#define BLOCK           1
#define NEED_MORE_DATA  2

static volatile bool g_shutdown = false;
static uint64_t g_event_count = 0;

// Signal handler for Ctrl+C
void signal_handler(int sig)
{
    if (sig == SIGINT) {
        g_shutdown = true;
        std::cout << "\nShutting down..." << std::endl;
    }
}

// Convert IPv4 address from network byte order to string
std::string ip_to_string(uint32_t ip)
{
    std::ostringstream oss;
    oss << ((ip >> 0) & 0xFF) << "."
        << ((ip >> 8) & 0xFF) << "."
        << ((ip >> 16) & 0xFF) << "."
        << ((ip >> 24) & 0xFF);
    return oss.str();
}

// Convert port from network byte order to host byte order
uint16_t ntohs_portable(uint16_t netshort)
{
    return ((netshort & 0xFF) << 8) | ((netshort >> 8) & 0xFF);
}

// Get protocol name string
const char* protocol_to_string(uint8_t protocol)
{
    switch (protocol) {
        case 1: return "ICMP";
        case 6: return "TCP";
        case 17: return "UDP";
        default: return "Unknown";
    }
}

// Get event type string
const char* event_type_to_string(uint8_t event_type)
{
    switch (event_type) {
        case FLOW_EVENT_TYPE_NEW_FLOW: return "NEW_FLOW";
        case FLOW_EVENT_TYPE_DATA_RECEIVED: return "DATA_RECEIVED";
        case FLOW_EVENT_TYPE_FLOW_CLOSED: return "FLOW_CLOSED";
        default: return "Unknown";
    }
}

// Get action string
const char* action_to_string(uint32_t action)
{
    switch (action) {
        case ALLOW: return "ALLOW";
        case BLOCK: return "BLOCK";
        case NEED_MORE_DATA: return "NEED_MORE_DATA";
        default: return "Unknown";
    }
}

// Format timestamp to readable string
std::string format_timestamp(uint64_t timestamp_ns)
{
    auto time_point = std::chrono::steady_clock::time_point{std::chrono::nanoseconds{timestamp_ns}};
    auto time_since_epoch = time_point.time_since_epoch();
    auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(time_since_epoch);
    
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    
    std::ostringstream oss;
    //oss << std::put_time(std::localtime(&time_t), "%H:%M:%S");
    oss << "." << std::setfill('0') << std::setw(3) << (milliseconds.count() % 1000);
    return oss.str();
}

// Ring buffer callback function
int flow_monitor_callback(void* ctx, void* data, size_t size)
{
    (void)ctx; // Unused parameter
    
    if (size != sizeof(flow_event_info_t)) {
        std::cerr << "Unexpected event size: " << size << " (expected: " << sizeof(flow_event_info_t) << ")" << std::endl;
        return 0;
    }
    
    flow_event_info_t* event = static_cast<flow_event_info_t*>(data);
    g_event_count++;
    
    // Format and display the flow event
    std::cout << "[" << g_event_count << "] " 
              << format_timestamp(event->timestamp) << " "
              << event_type_to_string(event->event_type) << " "
              << protocol_to_string(event->protocol) << " "
              << ip_to_string(event->local_addr_v4) << ":" << ntohs_portable(event->local_port)
              << " " << (event->direction ? "-> " : "<- ")
              << ip_to_string(event->remote_addr_v4) << ":" << ntohs_portable(event->remote_port)
              << " [" << action_to_string(event->action) << "]"
              << " (Data: " << event->data_length << " bytes, Flow: 0x" 
              << std::hex << event->flow_handle << std::dec << ")"
              << std::endl;
    
    return 0;
}

int main()
{
    std::cout << "Flow Monitor Application" << std::endl;
    std::cout << "Monitoring flow events from flowebpfext..." << std::endl;
    std::cout << "Press Ctrl+C to exit" << std::endl;
    std::cout << std::endl;
    
    // Set up signal handler
    signal(SIGINT, signal_handler);
    
    struct bpf_object* obj = nullptr;
    struct bpf_program* prog = nullptr;
    struct bpf_link* link = nullptr;
    struct ring_buffer* rb = nullptr;
    int err = 0;
    
    // Load and verify the BPF program
    obj = bpf_object__open("flow_monitor.sys");
    if (!obj) {
        std::cerr << "ERROR: Failed to open BPF object file 'flow_monitor.sys'" << std::endl;
        return 1;
    }
    
    err = bpf_object__load(obj);
    if (err) {
        std::cerr << "ERROR: Failed to load BPF object: " << err << std::endl;
        goto cleanup;
    }
    
    // Find the flow monitor program
    prog = bpf_object__find_program_by_name(obj, "FlowMonitor");
    if (!prog) {
        std::cerr << "ERROR: Failed to find 'FlowMonitor' program in BPF object" << std::endl;
        err = -1;
        goto cleanup;
    }
    
    // Attach the program to the flow classify hook
    link = bpf_program__attach(prog);
    if (!link) {
        err = -1;
        std::cerr << "ERROR: Failed to attach BPF program" << std::endl;
        goto cleanup;
    }
    
    // Set up ring buffer to receive events
    struct bpf_map* map = bpf_object__find_map_by_name(obj, "flow_events_map");
    if (!map) {
        std::cerr << "ERROR: Failed to find 'flow_events_map' map" << std::endl;
        err = -1;
        goto cleanup;
    }
    
    rb = ring_buffer__new(bpf_map__fd(map), flow_monitor_callback, nullptr, nullptr);
    if (!rb) {
        std::cerr << "ERROR: Failed to create ring buffer" << std::endl;
        err = -1;
        goto cleanup;
    }
    
    std::cout << "Flow monitor started successfully!" << std::endl;
    std::cout << "Waiting for flow events..." << std::endl;
    std::cout << std::endl;
    
    // Main event loop
    while (!g_shutdown) {
        err = ring_buffer__poll(rb, 100); // Poll with 100ms timeout
        if (err == -EINTR) {
            // Interrupted by signal
            break;
        }
        if (err < 0) {
            std::cerr << "ERROR: ring_buffer__poll failed: " << err << std::endl;
            break;
        }
    }
    
    std::cout << "\nTotal events processed: " << g_event_count << std::endl;
    
cleanup:
    if (map) {
        bpf_object__close((bpf_object*)map);
    }
    if (rb) {
        ring_buffer__free(rb);
    }
    if (link) {
        bpf_link__destroy(link);
    }
    if (obj) {
        bpf_object__close(obj);
    }
    return err;
}
