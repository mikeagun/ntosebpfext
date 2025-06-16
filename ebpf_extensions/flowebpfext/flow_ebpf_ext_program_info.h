// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once

#include "ebpf_ext.h"
#include "ebpf_extension.h"
#include "ebpf_flow_hooks.h"
#include "ebpf_flow_program_attach_type_guids.h"
#include "ebpf_program_types.h"
#include "ebpf_structs.h"

enum flow_prog_type_t{
    BPF_PROG_TYPE_FLOW_CLASSIFY = 7
};

enum flow_attach_type_t
{
    BPF_ATTACH_TYPE_FLOW_CLASSIFY = 17, ///< Flow classifier FIXME: sort out id.
};

// Flow program information.
static const ebpf_helper_function_prototype_t _flow_ebpf_extension_helper_function_prototype[] = {
    {.header = {EBPF_HELPER_FUNCTION_PROTOTYPE_CURRENT_VERSION, EBPF_HELPER_FUNCTION_PROTOTYPE_CURRENT_VERSION_SIZE},
     .helper_id = EBPF_MAX_GENERAL_HELPER_FUNCTION + 1,
     .name = "bpf_flow_test_helper",
     .return_type = EBPF_RETURN_TYPE_INTEGER,
     .arguments =
         {EBPF_ARGUMENT_TYPE_PTR_TO_CTX, EBPF_ARGUMENT_TYPE_PTR_TO_WRITABLE_MEM, EBPF_ARGUMENT_TYPE_CONST_SIZE}},
};

static const ebpf_context_descriptor_t _ebpf_flow_context_descriptor = {
    sizeof(flow_classify_md_t),
    0, // No offset for data_start
    0, // No offset for data_end
    -1,
};

static const ebpf_program_type_descriptor_t _ebpf_flow_program_type_descriptor = {
    .header = {EBPF_PROGRAM_TYPE_DESCRIPTOR_CURRENT_VERSION, EBPF_PROGRAM_TYPE_DESCRIPTOR_CURRENT_VERSION_SIZE},
    .name = "flow_classify",
    .context_descriptor = &_ebpf_flow_context_descriptor,
    .program_type = EBPF_PROGRAM_TYPE_FLOW_CLASSIFY_GUID,
    .bpf_prog_type = BPF_PROG_TYPE_FLOW_CLASSIFY, // Set to appropriate BPF_PROG_TYPE if defined for flow classify
};

static const ebpf_program_info_t _ebpf_flow_program_info = {
    .header = {EBPF_PROGRAM_INFORMATION_CURRENT_VERSION, EBPF_PROGRAM_INFORMATION_CURRENT_VERSION_SIZE},
    .program_type_descriptor = &_ebpf_flow_program_type_descriptor,
    .count_of_program_type_specific_helpers = EBPF_COUNT_OF(_flow_ebpf_extension_helper_function_prototype),
    .program_type_specific_helper_prototype = _flow_ebpf_extension_helper_function_prototype,
};

static const ebpf_program_section_info_t _ebpf_flow_section_info[] = {
    {
        .header =
            {EBPF_PROGRAM_SECTION_INFORMATION_CURRENT_VERSION, EBPF_PROGRAM_SECTION_INFORMATION_CURRENT_VERSION_SIZE},
        .section_name = (wchar_t*)L"flow_classify",
        .program_type = &EBPF_PROGRAM_TYPE_FLOW_CLASSIFY,
        .attach_type = &EBPF_ATTACH_TYPE_FLOW_CLASSIFY,
        .bpf_program_type = BPF_PROG_TYPE_FLOW_CLASSIFY, // Set to appropriate BPF_PROG_TYPE if defined for flow classify
        .bpf_attach_type = BPF_ATTACH_TYPE_FLOW_CLASSIFY, // Set to appropriate BPF_ATTACH_TYPE if defined for flow classify
    },
};
