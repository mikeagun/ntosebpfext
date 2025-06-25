// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// This BPF program listens for flow events from the flowebpfext extension, and stores them into a ring buffer map.

#include "bpf_helpers.h"
#include "ebpf_flow_hooks.h"

#include <stddef.h>
#include <stdint.h>

// Ring-buffer for flow events.
#define FLOW_EVENTS_MAP_SIZE (512 * 1024)
struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, FLOW_EVENTS_MAP_SIZE);
} flow_events_map SEC(".maps");

// The following line is optional, but is used to verify
// that the FlowMonitor prototype is correct or the compiler
// would complain when the function is actually defined below.
flow_classify_hook_t FlowMonitor;

SEC("flow_classify")
int
FlowMonitor(flow_classify_md_t* ctx)
{
    return FLOW_CLASSIFY_ALLOW;
}
