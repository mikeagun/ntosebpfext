// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#define CATCH_CONFIG_MAIN
#include "catch_wrapper.hpp"
#include "watchdog.h"
#include "ebpf_ext.h"
#include "ebpf_ext_tracelog.h"
#include "ebpf_extension_uuids.h"
#include "flow_ebpf_ext_classify.h"
#include "flow_ebpf_ext_program_info.h"

struct _DEVICE_OBJECT* _ebpf_ext_driver_device_object;

CATCH_REGISTER_LISTENER(_watchdog)

// Skeleton for flowebpfext extension unit tests.
// Add test cases for:
// - Port matching (FLOWEBPFEXT_PORT_HTTPS)
// - BPF program attach/invoke
// - ALLOW/BLOCK/NEED_MORE_DATA/invalid return codes
// - Error logging

TEST_CASE("flowebpfext_port_match", "[flowebpfext]")
{
    // TODO: Implement test for port matching (9993)
}

TEST_CASE("flowebpfext_bpf_attach_invoke", "[flowebpfext]")
{
    // TODO: Implement test for BPF program attach and invocation
}

TEST_CASE("flowebpfext_return_codes", "[flowebpfext]")
{
    // TODO: Implement test for ALLOW/BLOCK/NEED_MORE_DATA/invalid return codes
}

TEST_CASE("flowebpfext_error_logging", "[flowebpfext]")
{
    // TODO: Implement test for error logging
}
