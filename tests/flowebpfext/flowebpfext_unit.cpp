// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#define CATCH_CONFIG_MAIN
#include "catch_wrapper.hpp"
#include "cxplat_fault_injection.h"
#include "cxplat_passed_test_log.h"
#include "ebpf_ext.h"
#include "ebpf_ext_tracelog.h"
#include "ebpf_extension_uuids.h"
#include "ebpf_flow_hooks.h"
#include "flow_ebpf_ext_classify.h"
#include "flow_ebpf_ext_helper.h"
#include "flow_ebpf_ext_program_info.h"
#include "watchdog.h"

#include <errno.h>
#include <map>
#include <stop_token>
#include <thread>

struct _DEVICE_OBJECT* _ebpf_ext_driver_device_object;

CATCH_REGISTER_LISTENER(_watchdog)
CATCH_REGISTER_LISTENER(cxplat_passed_test_log)

// FIXME (before merge): These tests are currently placeholders and have not been fully reviewed/implemented.
//                       They are intended to be used as a starting point for flow extension testing.

// External function declarations
extern "C"
{
    NTSTATUS
    ebpf_ext_register_flow();
    void
    ebpf_ext_unregister_flow();
    _Success_(return >= 0) int32_t _ebpf_flow_test_helper(
        _In_ flow_classify_md_t* flow_md, _Out_writes_bytes_(tuple_length) uint8_t* tuple, uint32_t tuple_length);
}

#pragma region flow_classify

typedef struct test_flow_client_context_t
{
    flowebpfext_helper_base_client_context_t base;
    flow_classify_md_t flow_context;
    uint32_t program_result;
    bool program_invoked;
} test_flow_client_context_t;

_Must_inspect_result_ ebpf_result_t
flowebpfext_unit_invoke_flow_program(
    _In_ const void* client_flow_context, _In_ const void* context, _Out_ uint32_t* result)
{
    UNREFERENCED_PARAMETER(client_flow_context);

    auto client_context = (test_flow_client_context_t*)client_flow_context;
    auto flow_context = (flow_classify_md_t*)context;

    if (!client_context || !flow_context || !result) {
        return EBPF_INVALID_ARGUMENT;
    }

    // Copy flow data to client context for verification
    client_context->flow_context = *flow_context;
    client_context->program_invoked = true;

    // Return the preset result
    *result = client_context->program_result;

    return EBPF_SUCCESS;
}

TEST_CASE("flowebpfext_port_match", "[flowebpfext]")
{
    ebpf_extension_data_t npi_specific_characteristics = {};
    test_flow_client_context_t client_context = {};
    client_context.program_result = ALLOW;

    flow_ebpf_ext_helper_t helper(
        &npi_specific_characteristics,
        (_ebpf_extension_dispatch_function)flowebpfext_unit_invoke_flow_program,
        (flowebpfext_helper_base_client_context_t*)&client_context);

    // Test flow classification for HTTPS port (9993)
    flow_classify_md_t flow_md = {};
    flow_md.local_addr_v4 = 0x0100007F;  // 127.0.0.1 in network byte order
    flow_md.remote_addr_v4 = 0x08080808; // 8.8.8.8 in network byte order
    flow_md.local_port = htons(9993);    // FLOWEBPFEXT_PORT_HTTPS
    flow_md.remote_port = htons(12345);
    flow_md.protocol = IPPROTO_TCP;
    flow_md.direction = 1; // outbound
    flow_md.flow_handle = 0x123456789ABCDEF0;

    uint8_t test_data[] = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    flow_md.data_start = test_data;
    flow_md.data_end = test_data + sizeof(test_data) - 1;

    // Simulate flow classification
    uint32_t classify_result = 0;
    ebpf_result_t result = flowebpfext_unit_invoke_flow_program(&client_context, &flow_md, &classify_result);

    REQUIRE(result == EBPF_SUCCESS);
    REQUIRE(client_context.program_invoked == true);
    REQUIRE(classify_result == ALLOW);

    // Verify flow context was properly passed
    REQUIRE(client_context.flow_context.local_port == htons(9993));
    REQUIRE(client_context.flow_context.remote_port == htons(12345));
    REQUIRE(client_context.flow_context.protocol == IPPROTO_TCP);
    REQUIRE(client_context.flow_context.direction == 1);
    REQUIRE(client_context.flow_context.flow_handle == 0x123456789ABCDEF0);
}

TEST_CASE("flowebpfext_bpf_attach_invoke", "[flowebpfext]")
{
    ebpf_extension_data_t npi_specific_characteristics = {};
    test_flow_client_context_t client_context = {};
    client_context.program_result = ALLOW;

    flow_ebpf_ext_helper_t helper(
        &npi_specific_characteristics,
        (_ebpf_extension_dispatch_function)flowebpfext_unit_invoke_flow_program,
        (flowebpfext_helper_base_client_context_t*)&client_context);

    // Test successful program attachment and invocation
    REQUIRE(client_context.base.helper != nullptr);
    REQUIRE(client_context.base.desired_attach_type == BPF_ATTACH_TYPE_FLOW_CLASSIFY);

    // Test flow classification with different protocols
    flow_classify_md_t tcp_flow = {};
    tcp_flow.protocol = IPPROTO_TCP;
    tcp_flow.local_port = htons(443);
    tcp_flow.remote_port = htons(54321);
    tcp_flow.direction = 0; // inbound

    uint32_t result = 0;
    ebpf_result_t invoke_result = flowebpfext_unit_invoke_flow_program(&client_context, &tcp_flow, &result);

    REQUIRE(invoke_result == EBPF_SUCCESS);
    REQUIRE(result == ALLOW);
    REQUIRE(client_context.flow_context.protocol == IPPROTO_TCP);

    // Test UDP flow (should also work)
    client_context.program_invoked = false;
    flow_classify_md_t udp_flow = {};
    udp_flow.protocol = IPPROTO_UDP;
    udp_flow.local_port = htons(9993);
    udp_flow.remote_port = htons(12345);

    invoke_result = flowebpfext_unit_invoke_flow_program(&client_context, &udp_flow, &result);

    REQUIRE(invoke_result == EBPF_SUCCESS);
    REQUIRE(client_context.program_invoked == true);
    REQUIRE(client_context.flow_context.protocol == IPPROTO_UDP);
}

TEST_CASE("flowebpfext_return_codes", "[flowebpfext]")
{
    ebpf_extension_data_t npi_specific_characteristics = {};
    test_flow_client_context_t client_context = {};

    flow_ebpf_ext_helper_t helper(
        &npi_specific_characteristics,
        (_ebpf_extension_dispatch_function)flowebpfext_unit_invoke_flow_program,
        (flowebpfext_helper_base_client_context_t*)&client_context);

    flow_classify_md_t flow_md = {};
    flow_md.protocol = IPPROTO_TCP;
    flow_md.local_port = htons(9993);
    flow_md.remote_port = htons(12345);
    uint8_t test_data[] = "HTTP packet data";
    flow_md.data_start = test_data;
    flow_md.data_end = test_data + sizeof(test_data) - 1;

    // Test ALLOW return code
    client_context.program_result = ALLOW;
    client_context.program_invoked = false;
    uint32_t result = 0;
    ebpf_result_t invoke_result = flowebpfext_unit_invoke_flow_program(&client_context, &flow_md, &result);

    REQUIRE(invoke_result == EBPF_SUCCESS);
    REQUIRE(result == ALLOW);
    REQUIRE(client_context.program_invoked == true);

    // Test BLOCK return code
    client_context.program_result = BLOCK;
    client_context.program_invoked = false;
    invoke_result = flowebpfext_unit_invoke_flow_program(&client_context, &flow_md, &result);

    REQUIRE(invoke_result == EBPF_SUCCESS);
    REQUIRE(result == BLOCK);
    REQUIRE(client_context.program_invoked == true);

    // Test NEED_MORE_DATA return code
    client_context.program_result = NEED_MORE_DATA;
    client_context.program_invoked = false;
    invoke_result = flowebpfext_unit_invoke_flow_program(&client_context, &flow_md, &result);

    REQUIRE(invoke_result == EBPF_SUCCESS);
    REQUIRE(result == NEED_MORE_DATA);
    REQUIRE(client_context.program_invoked == true);

    // Test invalid return code (should still succeed but with invalid value)
    client_context.program_result = 999; // Invalid return code
    client_context.program_invoked = false;
    invoke_result = flowebpfext_unit_invoke_flow_program(&client_context, &flow_md, &result);

    REQUIRE(invoke_result == EBPF_SUCCESS);
    REQUIRE(result == 999);
    REQUIRE(client_context.program_invoked == true);
}

TEST_CASE("flowebpfext_error_handling", "[flowebpfext]")
{
    ebpf_extension_data_t npi_specific_characteristics = {};
    test_flow_client_context_t client_context = {};
    client_context.program_result = ALLOW;

    flow_ebpf_ext_helper_t helper(
        &npi_specific_characteristics,
        (_ebpf_extension_dispatch_function)flowebpfext_unit_invoke_flow_program,
        (flowebpfext_helper_base_client_context_t*)&client_context);

    // Test invalid parameters
    uint32_t result = 0;

    // Test null context
    ebpf_result_t invoke_result = flowebpfext_unit_invoke_flow_program(nullptr, nullptr, &result);
    REQUIRE(invoke_result == EBPF_INVALID_ARGUMENT);

    // Test null result pointer
    flow_classify_md_t flow_md = {};
    invoke_result = flowebpfext_unit_invoke_flow_program(&client_context, &flow_md, nullptr);
    REQUIRE(invoke_result == EBPF_INVALID_ARGUMENT);

    // Test null flow context
    invoke_result = flowebpfext_unit_invoke_flow_program(&client_context, nullptr, &result);
    REQUIRE(invoke_result == EBPF_INVALID_ARGUMENT);
}

TEST_CASE("flowebpfext_flow_helper_function", "[flowebpfext]")
{
    // Test the bpf_flow_test_helper function
    flow_classify_md_t flow_md = {};
    flow_md.local_addr_v4 = 0x0100007F;  // 127.0.0.1
    flow_md.remote_addr_v4 = 0x08080808; // 8.8.8.8
    flow_md.local_port = htons(9993);
    flow_md.remote_port = htons(12345);
    flow_md.protocol = IPPROTO_TCP;
    flow_md.direction = 1;
    flow_md.flow_handle = 0x123456789ABCDEF0;

    uint8_t tuple_buffer[sizeof(flow_classify_md_t) + 10];
    memset(tuple_buffer, 0, sizeof(tuple_buffer));

    // Test successful call
    int32_t result = _ebpf_flow_test_helper(&flow_md, tuple_buffer, sizeof(tuple_buffer));
    REQUIRE(result == sizeof(flow_classify_md_t));

    // Verify the data was copied correctly
    auto copied_flow = (flow_classify_md_t*)tuple_buffer;
    REQUIRE(copied_flow->local_addr_v4 == flow_md.local_addr_v4);
    REQUIRE(copied_flow->remote_addr_v4 == flow_md.remote_addr_v4);
    REQUIRE(copied_flow->local_port == flow_md.local_port);
    REQUIRE(copied_flow->remote_port == flow_md.remote_port);
    REQUIRE(copied_flow->protocol == flow_md.protocol);
    REQUIRE(copied_flow->direction == flow_md.direction);
    REQUIRE(copied_flow->flow_handle == flow_md.flow_handle);

    // Test buffer too small
    uint8_t small_buffer[sizeof(flow_classify_md_t) - 1];
    result = _ebpf_flow_test_helper(&flow_md, small_buffer, sizeof(small_buffer));
    REQUIRE(result == -EINVAL);
}

TEST_CASE("flowebpfext_ipv6_flows", "[flowebpfext]")
{
    ebpf_extension_data_t npi_specific_characteristics = {};
    test_flow_client_context_t client_context = {};
    client_context.program_result = ALLOW;

    flow_ebpf_ext_helper_t helper(
        &npi_specific_characteristics,
        (_ebpf_extension_dispatch_function)flowebpfext_unit_invoke_flow_program,
        (flowebpfext_helper_base_client_context_t*)&client_context);

    // Test IPv6 flow (using protocol field to simulate IPv6)
    flow_classify_md_t ipv6_flow = {};
    ipv6_flow.local_addr_v4 = 0; // IPv6 would use different addressing
    ipv6_flow.remote_addr_v4 = 0;
    ipv6_flow.local_port = htons(9993);
    ipv6_flow.remote_port = htons(443);
    ipv6_flow.protocol = IPPROTO_TCP;
    ipv6_flow.direction = 0; // inbound
    ipv6_flow.flow_handle = 0xFEDCBA9876543210;

    uint8_t ipv6_data[] = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n";
    ipv6_flow.data_start = ipv6_data;
    ipv6_flow.data_end = ipv6_data + sizeof(ipv6_data) - 1;

    uint32_t result = 0;
    ebpf_result_t invoke_result = flowebpfext_unit_invoke_flow_program(&client_context, &ipv6_flow, &result);

    REQUIRE(invoke_result == EBPF_SUCCESS);
    REQUIRE(result == ALLOW);
    REQUIRE(client_context.flow_context.flow_handle == 0xFEDCBA9876543210);
    REQUIRE(client_context.flow_context.direction == 0);
}

TEST_CASE("flowebpfext_stream_data_inspection", "[flowebpfext]")
{
    ebpf_extension_data_t npi_specific_characteristics = {};
    test_flow_client_context_t client_context = {};
    client_context.program_result = NEED_MORE_DATA;

    flow_ebpf_ext_helper_t helper(
        &npi_specific_characteristics,
        (_ebpf_extension_dispatch_function)flowebpfext_unit_invoke_flow_program,
        (flowebpfext_helper_base_client_context_t*)&client_context);

    // Test stream data inspection
    flow_classify_md_t flow_md = {};
    flow_md.protocol = IPPROTO_TCP;
    flow_md.local_port = htons(9993);
    flow_md.remote_port = htons(12345);
    flow_md.direction = 1;

    // Test with partial HTTP request
    uint8_t partial_http[] = "GET /api/v1/";
    flow_md.data_start = partial_http;
    flow_md.data_end = partial_http + sizeof(partial_http) - 1;

    uint32_t result = 0;
    ebpf_result_t invoke_result = flowebpfext_unit_invoke_flow_program(&client_context, &flow_md, &result);

    REQUIRE(invoke_result == EBPF_SUCCESS);
    REQUIRE(result == NEED_MORE_DATA);

    // Test with complete HTTP request
    client_context.program_result = ALLOW;
    client_context.program_invoked = false;
    uint8_t complete_http[] =
        "GET /api/v1/users HTTP/1.1\r\nHost: example.com\r\nAuthorization: Bearer token123\r\n\r\n";
    flow_md.data_start = complete_http;
    flow_md.data_end = complete_http + sizeof(complete_http) - 1;

    invoke_result = flowebpfext_unit_invoke_flow_program(&client_context, &flow_md, &result);

    REQUIRE(invoke_result == EBPF_SUCCESS);
    REQUIRE(result == ALLOW);
    REQUIRE(client_context.program_invoked == true);

    // Test with suspicious content
    client_context.program_result = BLOCK;
    client_context.program_invoked = false;
    uint8_t suspicious_data[] = "GET /../../etc/passwd HTTP/1.1\r\n";
    flow_md.data_start = suspicious_data;
    flow_md.data_end = suspicious_data + sizeof(suspicious_data) - 1;

    invoke_result = flowebpfext_unit_invoke_flow_program(&client_context, &flow_md, &result);

    REQUIRE(invoke_result == EBPF_SUCCESS);
    REQUIRE(result == BLOCK);
    REQUIRE(client_context.program_invoked == true);
}

#pragma endregion
