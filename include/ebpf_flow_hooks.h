// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once
#include <stdint.h>

// This file contains APIs for hooks and helpers that are
// exposed by flowebpfext.sys for use by eBPF programs.

typedef enum _flow_classsify_result {
    ALLOW,
    BLOCK,
    NEED_MORE_DATA,
} flow_classsify_result_t;

typedef struct _flow_classify_md
{
    uint32_t local_addr_v4;      ///< Local IPv4 address (network byte order)
    uint32_t remote_addr_v4;     ///< Remote IPv4 address (network byte order)
    uint16_t local_port;         ///< Local port (network byte order)
    uint16_t remote_port;        ///< Remote port (network byte order)
    uint8_t  protocol;           ///< IP protocol (TCP/UDP/etc)
    uint8_t  direction;          ///< 0 = inbound, 1 = outbound
    uint64_t flow_handle;        ///< WFP flow handle
    uint8_t* data_start;         ///< Pointer to start of stream segment data
    uint8_t* data_end;           ///< Pointer to end of stream segment data
} flow_classify_md_t;

/*
 * @brief Handle flow classification (stream inspection).
 *
 * Program type: \ref EBPF_PROGRAM_TYPE_FLOW_CLASSIFY
 *
 * Attach type(s):
 * \ref EBPF_ATTACH_TYPE_FLOW_CLASSIFY
 *
 * @param[in] context \ref flow_classify_md_t
 * @return 0 to permit, nonzero to block or indicate terminal/other result.
 */
typedef int
flow_classify_hook_t(flow_classify_md_t* context);

// Flow classify helper functions.
#define FLOW_CLASSIFY_EXT_HELPER_FN_BASE 0xFFFF

#if !defined(__doxygen) && !defined(EBPF_HELPER)
#define EBPF_HELPER(return_type, name, args) typedef return_type(*name##_t) args
#endif

typedef enum
{
    BPF_FUNC_flow_test_helper = FLOW_CLASSIFY_EXT_HELPER_FN_BASE + 1,
} ebpf_flow_classify_helper_id_t;

/**
 * @brief Get the 5-tuple and flow info for the current flow.
 *
 * @param[in] context Flow metadata.
 * @param[out] tuple Buffer to store the 5-tuple and flow info.
 * @param[in] tuple_length Length of the buffer.
 *
 * @retval >=0 The length of the tuple data.
 * @retval <0 A failure occurred.
 */
EBPF_HELPER(int, bpf_flow_test_helper, (flow_classify_md_t * ctx, uint8_t* tuple, uint32_t tuple_length));
#ifndef __doxygen
#define bpf_flow_test_helper ((bpf_flow_test_helper_t)BPF_FUNC_flow_get_5tuple)
#endif
