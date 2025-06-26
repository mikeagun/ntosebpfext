// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

/**
 * @file
 * @brief This file implements the flow classify program type hook on eBPF for Windows (stream inspection API).
 */
#include "flow_ebpf_ext_platform.h"
#include "flow_ebpf_ext_classify.h"
#include "flow_ebpf_ext_program_info.h"

#include <errno.h>

// GUIDs for callouts (define your own or use static const GUIDs)
// {A1B2C3D4-1111-2222-3333-444455556666}
static const GUID FLOWEBPFEXT_STREAM_CALLOUT_V4 = {
    0xa1b2c3d4, 0x1111, 0x2222, {0x33, 0x33, 0x44, 0x44, 0x55, 0x55, 0x66, 0x66}};
// {A1B2C3D4-1111-2222-3333-444455556667}
static const GUID FLOWEBPFEXT_STREAM_CALLOUT_V6 = {
    0xa1b2c3d4, 0x1111, 0x2222, {0x33, 0x33, 0x44, 0x44, 0x55, 0x55, 0x66, 0x67}};
// {A1B2C3D4-1111-2222-3333-444455556668}
static const GUID FLOWEBPFEXT_FLOW_ESTABLISHED_CALLOUT_V4 = {
    0xa1b2c3d4, 0x1111, 0x2222, {0x33, 0x33, 0x44, 0x44, 0x55, 0x55, 0x66, 0x68}};
// {A1B2C3D4-1111-2222-3333-444455556669}
static const GUID FLOWEBPFEXT_FLOW_ESTABLISHED_CALLOUT_V6 = {
    0xa1b2c3d4, 0x1111, 0x2222, {0x33, 0x33, 0x44, 0x44, 0x55, 0x55, 0x66, 0x69}};

#ifndef FLOWEBPFEXT_PORT_HTTPS
#define FLOWEBPFEXT_PORT_HTTPS 9993
#endif

// Static callout IDs for flow_established
static UINT32 g_flowebpfext_flow_established_callout_id_v4 = 0;
static UINT32 g_flowebpfext_flow_established_callout_id_v6 = 0;

typedef struct _flowebpfext_stream_context
{
    ebpf_extension_hook_client_t* attached_program;
} flowebpfext_stream_context_t;

static ebpf_result_t
_ebpf_flow_context_create(
    _In_reads_bytes_opt_(data_size_in) const uint8_t* data_in,
    size_t data_size_in,
    _In_reads_bytes_opt_(context_size_in) const uint8_t* context_in,
    size_t context_size_in,
    _Outptr_ void** context);

static void
_ebpf_flow_context_destroy(
    _In_opt_ void* context,
    _Out_writes_bytes_to_(*data_size_out, *data_size_out) uint8_t* data_out,
    _Inout_ size_t* data_size_out,
    _Out_writes_bytes_to_(*context_size_out, *context_size_out) uint8_t* context_out,
    _Inout_ size_t* context_size_out);

void
flowebpfext_stream_classify(
    const FWPS_INCOMING_VALUES* inFixedValues,
    const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    void* layerData,
    const void* classifyContext,
    const FWPS_FILTER* filter,
    uint64_t flowContext,
    FWPS_CLASSIFY_OUT* classifyOut);

void
flowebpfext_register_flow_callouts();
void
flowebpfext_flow_unregister_callouts();

_Success_(return >= 0) static int32_t _ebpf_flow_test_helper(
    _In_ flow_classify_md_t* flow_md, _Out_writes_bytes_(tuple_length) uint8_t* tuple, uint32_t tuple_length)
{
    if (tuple_length < sizeof(flow_classify_md_t))
        return -EINVAL;
    memcpy(tuple, flow_md, sizeof(flow_classify_md_t));
    return sizeof(flow_classify_md_t);
}

static const void* _ebpf_flow_helper_functions[] = {(void*)&_ebpf_flow_test_helper};

static ebpf_helper_function_addresses_t _ebpf_flow_helper_function_address_table = {
    .header = {EBPF_HELPER_FUNCTION_ADDRESSES_CURRENT_VERSION, EBPF_HELPER_FUNCTION_ADDRESSES_CURRENT_VERSION_SIZE},
    .helper_function_count = EBPF_COUNT_OF(_ebpf_flow_helper_functions),
    .helper_function_address = (uint64_t*)_ebpf_flow_helper_functions,
};

//
// Flow Classify Program Information NPI Provider.
//
static ebpf_program_data_t _ebpf_flow_program_data = {
    .header = EBPF_PROGRAM_DATA_HEADER,
    .program_info = &_ebpf_flow_program_info,
    .program_type_specific_helper_function_addresses = &_ebpf_flow_helper_function_address_table,
    .context_create = _ebpf_flow_context_create,
    .context_destroy = _ebpf_flow_context_destroy,
    .required_irql = PASSIVE_LEVEL,
};

static ebpf_extension_data_t _ebpf_flow_program_info_provider_data = {
    .header = {EBPF_EXTENSION_NPI_PROVIDER_VERSION, sizeof(_ebpf_flow_program_data)}, .data = &_ebpf_flow_program_data};

NPI_MODULEID DECLSPEC_SELECTANY _ebpf_flow_program_info_provider_moduleid = {sizeof(NPI_MODULEID), MIT_GUID, {0}};

static ebpf_extension_program_info_provider_t* _ebpf_flow_program_info_provider_context = NULL;

//
// Flow Classify Hook NPI Provider.
//
ebpf_attach_provider_data_t _ebpf_flow_hook_provider_data = {
    .header = {EBPF_ATTACH_PROVIDER_DATA_CURRENT_VERSION, EBPF_ATTACH_PROVIDER_DATA_CURRENT_VERSION_SIZE},
    .supported_program_type = EBPF_PROGRAM_TYPE_FLOW_CLASSIFY_GUID,
    .bpf_attach_type = (bpf_attach_type_t)17, // BPF_ATTACH_TYPE_FLOW_CLASSIFY
};

NPI_MODULEID DECLSPEC_SELECTANY _ebpf_flow_hook_provider_moduleid = {sizeof(NPI_MODULEID), MIT_GUID, {0}};

static ebpf_extension_hook_provider_t* _ebpf_flow_hook_provider_context = NULL;

EX_PUSH_LOCK _ebpf_flow_hook_provider_lock;
bool _ebpf_flow_hook_provider_registered = FALSE;
uint64_t _ebpf_flow_hook_provider_registration_count = 0;

//
// Client attach/detach handler routines.
//

static ebpf_result_t
_flow_ebpf_extension_flow_on_client_attach(
    _In_ const ebpf_extension_hook_client_t* attaching_client,
    _In_ const ebpf_extension_hook_provider_t* provider_context)
{
    ebpf_result_t result = EBPF_SUCCESS;
    bool push_lock_acquired = false;

    EBPF_EXT_LOG_ENTRY();

    UNREFERENCED_PARAMETER(attaching_client);
    UNREFERENCED_PARAMETER(provider_context);

    ExAcquirePushLockExclusive(&_ebpf_flow_hook_provider_lock);

    push_lock_acquired = true;

    if (!_ebpf_flow_hook_provider_registered) {
        flowebpfext_register_flow_callouts();
        _ebpf_flow_hook_provider_registered = TRUE;
    }
    _ebpf_flow_hook_provider_registration_count++;
    // Exit:
    if (push_lock_acquired) {
        ExReleasePushLockExclusive(&_ebpf_flow_hook_provider_lock);
    }

    EBPF_EXT_RETURN_RESULT(result);
}

static void
_flow_ebpf_extension_flow_on_client_detach(_In_ const ebpf_extension_hook_client_t* detaching_client)
{
    // ebpf_result_t result = EBPF_SUCCESS;

    EBPF_EXT_LOG_ENTRY();

    UNREFERENCED_PARAMETER(detaching_client);
    ExAcquirePushLockExclusive(&_ebpf_flow_hook_provider_lock);

    _ebpf_flow_hook_provider_registration_count--;

    if (_ebpf_flow_hook_provider_registered && _ebpf_flow_hook_provider_registration_count == 0) {
        flowebpfext_flow_unregister_callouts();
        _ebpf_flow_hook_provider_registered = FALSE;
    }
    ExReleasePushLockExclusive(&_ebpf_flow_hook_provider_lock);

    EBPF_EXT_LOG_EXIT();
}

//
// NMR Registration Helper Routines.
//

void
ebpf_ext_unregister_flow()
{
    if (_ebpf_flow_hook_provider_context) {
        ebpf_extension_hook_provider_unregister(_ebpf_flow_hook_provider_context);
        _ebpf_flow_hook_provider_context = NULL;
    }
    if (_ebpf_flow_program_info_provider_context) {
        ebpf_extension_program_info_provider_unregister(_ebpf_flow_program_info_provider_context);
        _ebpf_flow_program_info_provider_context = NULL;
    }
}

NTSTATUS
ebpf_ext_register_flow()
{
    NTSTATUS status = STATUS_SUCCESS;
    EBPF_EXT_LOG_ENTRY();
    const ebpf_extension_program_info_provider_parameters_t program_info_provider_parameters = {
        &_ebpf_flow_program_info_provider_moduleid, &_ebpf_flow_program_data};
    const ebpf_extension_hook_provider_parameters_t hook_provider_parameters = {
        &_ebpf_flow_hook_provider_moduleid, &_ebpf_flow_hook_provider_data};
    // Set the program type as the provider module id.
    _ebpf_flow_program_info_provider_moduleid.Guid = EBPF_PROGRAM_TYPE_FLOW_CLASSIFY;
    _ebpf_flow_hook_provider_moduleid.Guid = EBPF_ATTACH_TYPE_FLOW_CLASSIFY;
    status = ebpf_extension_program_info_provider_register(
        &program_info_provider_parameters, &_ebpf_flow_program_info_provider_context);
    if (!NT_SUCCESS(status)) {
        EBPF_EXT_LOG_MESSAGE_NTSTATUS(
            EBPF_EXT_TRACELOG_LEVEL_ERROR,
            EBPF_EXT_TRACELOG_KEYWORD_FLOW,
            "ebpf_extension_program_info_provider_register",
            status);
        goto Exit;
    }
    status = ebpf_extension_hook_provider_register(
        &hook_provider_parameters,
        _flow_ebpf_extension_flow_on_client_attach,
        _flow_ebpf_extension_flow_on_client_detach,
        NULL,
        &_ebpf_flow_hook_provider_context);
    if (status != EBPF_SUCCESS) {
        EBPF_EXT_LOG_MESSAGE_NTSTATUS(
            EBPF_EXT_TRACELOG_LEVEL_ERROR,
            EBPF_EXT_TRACELOG_KEYWORD_FLOW,
            "ebpf_extension_hook_provider_register",
            status);
        goto Exit;
    }
Exit:
    if (!NT_SUCCESS(status)) {
        ebpf_ext_unregister_flow();
    }
    EBPF_EXT_RETURN_NTSTATUS(status);
}

typedef struct _flow_notify_context
{
    EBPF_CONTEXT_HEADER;
    flow_classify_md_t flow_md;
} flow_notify_context_t;

static ebpf_result_t
_ebpf_flow_context_create(
    _In_reads_bytes_opt_(data_size_in) const uint8_t* data_in,
    size_t data_size_in,
    _In_reads_bytes_opt_(context_size_in) const uint8_t* context_in,
    size_t context_size_in,
    _Outptr_ void** context)
{
    EBPF_EXT_LOG_ENTRY();
    ebpf_result_t result;
    flow_notify_context_t* flow_context = NULL;
    *context = NULL;
    if (context_in == NULL || context_size_in < sizeof(flow_classify_md_t)) {
        EBPF_EXT_LOG_MESSAGE(EBPF_EXT_TRACELOG_LEVEL_ERROR, EBPF_EXT_TRACELOG_KEYWORD_FLOW, "Context is required");
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }
    flow_context = (flow_notify_context_t*)ExAllocatePoolUninitialized(
        NonPagedPoolNx, sizeof(flow_notify_context_t), EBPF_EXTENSION_POOL_TAG);
    EBPF_EXT_BAIL_ON_ALLOC_FAILURE_RESULT(EBPF_EXT_TRACELOG_KEYWORD_FLOW, flow_context, "flow_context", result);
    memcpy(&flow_context->flow_md, context_in, sizeof(flow_classify_md_t));
    flow_context->flow_md.data_start = (uint8_t*)data_in;
    flow_context->flow_md.data_end = (uint8_t*)data_in + data_size_in;
    *context = flow_context;
    flow_context = NULL;
    result = EBPF_SUCCESS;
Exit:
    if (flow_context) {
        ExFreePool(flow_context);
        flow_context = NULL;
    }
    EBPF_EXT_RETURN_RESULT(result);
}

static void
_ebpf_flow_context_destroy(
    _In_opt_ void* context,
    _Out_writes_bytes_to_(*data_size_out, *data_size_out) uint8_t* data_out,
    _Inout_ size_t* data_size_out,
    _Out_writes_bytes_to_(*context_size_out, *context_size_out) uint8_t* context_out,
    _Inout_ size_t* context_size_out)
{
    EBPF_EXT_LOG_ENTRY();
    flow_notify_context_t* flow_context = (flow_notify_context_t*)context;
    flow_classify_md_t* flow_context_out = (flow_classify_md_t*)context_out;
    if (!flow_context) {
        EBPF_EXT_LOG_MESSAGE(EBPF_EXT_TRACELOG_LEVEL_ERROR, EBPF_EXT_TRACELOG_KEYWORD_FLOW, "Null context in destroy");
        goto Exit;
    }
    if (context_out != NULL && *context_size_out >= sizeof(flow_classify_md_t)) {
        memcpy(flow_context_out, &flow_context->flow_md, sizeof(flow_classify_md_t));
        *context_size_out = sizeof(flow_classify_md_t);
        // Zero out the data_start and data_end.
        flow_context_out->data_start = 0;
        flow_context_out->data_end = 0;
    } else {
        *context_size_out = 0;
    }

    // Copy the resulting data to the data_out.
    if (data_out != NULL &&
        *data_size_out >= (size_t)(flow_context->flow_md.data_end - flow_context->flow_md.data_start)) {
        memcpy(
            data_out,
            flow_context->flow_md.data_start,
            flow_context->flow_md.data_end - flow_context->flow_md.data_start);
        *data_size_out = flow_context->flow_md.data_end - flow_context->flow_md.data_start;
    } else {
        *data_size_out = 0;
    }
    ExFreePool(flow_context);
Exit:
    EBPF_EXT_LOG_EXIT();
}

// Add static variables to store callout IDs
static UINT32 g_flowebpfext_stream_callout_id_v4 = 0;
static UINT32 g_flowebpfext_stream_callout_id_v6 = 0;

void
flowebpfext_stream_classify(
    const FWPS_INCOMING_VALUES* inFixedValues,
    const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    void* layerData,
    const void* classifyContext,
    const FWPS_FILTER* filter,
    uint64_t flowContext,
    FWPS_CLASSIFY_OUT* classifyOut)
{
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(inFixedValues);
    UNREFERENCED_PARAMETER(inMetaValues);

    flowebpfext_stream_context_t* stream_ctx = (flowebpfext_stream_context_t*)(uintptr_t)flowContext;

    // Only operate if context is set (by flow established callout)
    if (stream_ctx == NULL) {
        EBPF_EXT_LOG_MESSAGE(EBPF_EXT_TRACELOG_LEVEL_ERROR, EBPF_EXT_TRACELOG_KEYWORD_FLOW, "No stream context");
        classifyOut->actionType = FWP_ACTION_CONTINUE;
        return;
    }

    if (stream_ctx->attached_program == NULL) {
        EBPF_EXT_LOG_MESSAGE(EBPF_EXT_TRACELOG_LEVEL_ERROR, EBPF_EXT_TRACELOG_KEYWORD_FLOW, "No attached program");
        classifyOut->actionType = FWP_ACTION_CONTINUE;
        return;
    }

    UINT16 layerId = 0;
    if (filter->action.calloutId == g_flowebpfext_flow_established_callout_id_v4) {
        layerId = FWPS_LAYER_ALE_FLOW_ESTABLISHED_V4;
    } else if (filter->action.calloutId == g_flowebpfext_flow_established_callout_id_v6) {
        layerId = FWPS_LAYER_ALE_FLOW_ESTABLISHED_V6;
    } else {
        classifyOut->actionType = FWP_ACTION_CONTINUE;
        ExFreePool(stream_ctx);
        return;
    }

    uint32_t result = 0;
    ebpf_result_t invoke_result = ebpf_extension_hook_invoke_program(stream_ctx->attached_program, layerData, &result);
    if (invoke_result != EBPF_SUCCESS || result != FLOW_CLASSIFY_NEED_MORE_DATA) {
        FwpsFlowRemoveContext0((UINT64)flowContext, layerId, filter->action.calloutId);
        ExFreePool(stream_ctx);
        stream_ctx = NULL;
    }
    if (invoke_result == EBPF_SUCCESS) {
        if (result == FLOW_CLASSIFY_ALLOW) {
            EBPF_EXT_LOG_MESSAGE(
                EBPF_EXT_TRACELOG_LEVEL_INFO, EBPF_EXT_TRACELOG_KEYWORD_FLOW, "eBPF program allowed the flow");
            classifyOut->actionType = FWP_ACTION_PERMIT;
        } else if (result == FLOW_CLASSIFY_BLOCK) {
            EBPF_EXT_LOG_MESSAGE(
                EBPF_EXT_TRACELOG_LEVEL_INFO, EBPF_EXT_TRACELOG_KEYWORD_FLOW, "eBPF program blocked the flow");
            classifyOut->actionType = FWP_ACTION_BLOCK;
        } else if (result == FLOW_CLASSIFY_NEED_MORE_DATA) {
            classifyOut->actionType = FWP_ACTION_CONTINUE;
        } else {
            EBPF_EXT_LOG_MESSAGE(
                EBPF_EXT_TRACELOG_LEVEL_ERROR, EBPF_EXT_TRACELOG_KEYWORD_FLOW, "Unexpected result from eBPF program");
            classifyOut->actionType = FWP_ACTION_CONTINUE;
        }
    } else {
        EBPF_EXT_LOG_MESSAGE(
            EBPF_EXT_TRACELOG_LEVEL_ERROR, EBPF_EXT_TRACELOG_KEYWORD_FLOW, "eBPF program invoke_result != SUCCESS");
        classifyOut->actionType = FWP_ACTION_CONTINUE;
    }
}

void
flowebpfext_flow_delete(UINT16 layerId, UINT32 calloutId, uint64_t flowContext)
{
    flowebpfext_stream_context_t* stream_ctx = (flowebpfext_stream_context_t*)(uintptr_t)flowContext;
    if (stream_ctx) {
        // Remove the context and free it.
        FwpsFlowRemoveContext0((UINT64)flowContext, layerId, calloutId);
        ExFreePool(stream_ctx);
    }
}

// Flow established callout function
void
flowebpfext_flow_established_classify(
    const FWPS_INCOMING_VALUES* inFixedValues,
    const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    void* layerData,
    const void* classifyContext,
    const FWPS_FILTER* filter,
    uint64_t flowContext,
    FWPS_CLASSIFY_OUT* classifyOut)
{
    UNREFERENCED_PARAMETER(inFixedValues);
    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    // Only initialize context if not already present
    if (flowContext == 0) {
        flowebpfext_stream_context_t* stream_ctx = (flowebpfext_stream_context_t*)ExAllocatePoolUninitialized(
            NonPagedPoolNx, sizeof(flowebpfext_stream_context_t), 'flwC');
        if (!stream_ctx) {
            EBPF_EXT_LOG_MESSAGE(
                EBPF_EXT_TRACELOG_LEVEL_ERROR, EBPF_EXT_TRACELOG_KEYWORD_FLOW, "stream_ctx alloc failed");
            classifyOut->actionType = FWP_ACTION_CONTINUE;
            return;
        }
        stream_ctx->attached_program =
            ebpf_extension_hook_get_next_attached_client(_ebpf_flow_hook_provider_context, NULL);
        UINT16 layerId = 0;
        if (filter->action.calloutId == g_flowebpfext_flow_established_callout_id_v4) {
            layerId = FWPS_LAYER_ALE_FLOW_ESTABLISHED_V4;
        } else if (filter->action.calloutId == g_flowebpfext_flow_established_callout_id_v6) {
            layerId = FWPS_LAYER_ALE_FLOW_ESTABLISHED_V6;
        } else {
            EBPF_EXT_LOG_MESSAGE(
                EBPF_EXT_TRACELOG_LEVEL_ERROR,
                EBPF_EXT_TRACELOG_KEYWORD_FLOW,
                "Invalid calloutId in flow_established_classify");
            classifyOut->actionType = FWP_ACTION_CONTINUE;
            ExFreePool(stream_ctx);
            return;
        }
        NTSTATUS status = FwpsFlowAssociateContext0(
            (UINT64)inMetaValues->flowHandle, (UINT16)layerId, (UINT32)filter->action.calloutId, (UINT64)stream_ctx);
        if (!NT_SUCCESS(status)) {
            EBPF_EXT_LOG_MESSAGE_NTSTATUS(
                EBPF_EXT_TRACELOG_LEVEL_ERROR,
                EBPF_EXT_TRACELOG_KEYWORD_FLOW,
                "FwpsFlowAssociateContext0 failed",
                status);
            ExFreePool(stream_ctx);
            classifyOut->actionType = FWP_ACTION_CONTINUE;
            return;
        }
    }
    classifyOut->actionType = FWP_ACTION_CONTINUE;
}

void
flowebpfext_register_flow_callouts()
{
    NTSTATUS status;
    FWPS_CALLOUT callout = {0};
    FWPM_CALLOUT mCallout = {0};
    FWPM_FILTER filter = {0};
    FWPM_FILTER_CONDITION cond[2] = {0};
    HANDLE engineHandle = NULL;
    UINT32 calloutId = 0;

    status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &engineHandle);
    if (!NT_SUCCESS(status))
        return;

    // Register callout for IPv4 (stream classify)
    callout.calloutKey = FLOWEBPFEXT_STREAM_CALLOUT_V4;
    callout.classifyFn = flowebpfext_stream_classify;
    callout.flowDeleteFn = flowebpfext_flow_delete;
    callout.flags = FWP_CALLOUT_FLAG_CONDITIONAL_ON_FLOW;
    //needs to be registered on  FWPM_LAYER_STREAM_V4 layer
    status = FwpsCalloutRegister(NULL, &callout, &calloutId);
    if (!NT_SUCCESS(status))
        goto Cleanup;
    g_flowebpfext_stream_callout_id_v4 = calloutId;

    // Register callout for IPv6 (stream classify)
    callout.calloutKey = FLOWEBPFEXT_STREAM_CALLOUT_V6;
    callout.classifyFn = flowebpfext_stream_classify;
    callout.flowDeleteFn = flowebpfext_flow_delete;
    callout.flags = FWP_CALLOUT_FLAG_CONDITIONAL_ON_FLOW;
    //needs to be registered on  FWPM_LAYER_STREAM_V6 layer
    status = FwpsCalloutRegister(NULL, &callout, &calloutId);
    if (!NT_SUCCESS(status))
        goto Cleanup;
    g_flowebpfext_stream_callout_id_v6 = calloutId;

    // Register callout for IPv4 (flow established)
    callout.calloutKey = FLOWEBPFEXT_FLOW_ESTABLISHED_CALLOUT_V4;
    callout.classifyFn = flowebpfext_flow_established_classify;
    // callout.flowDeleteFn = flowebpfext_flow_delete;
    callout.flags = 0;
    // needs to be registered on FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4 layer
    status = FwpsCalloutRegister(NULL, &callout, &calloutId);
    if (!NT_SUCCESS(status))
        goto Cleanup;
    g_flowebpfext_flow_established_callout_id_v4 = calloutId;

    // Register callout for IPv6 (flow established)
    callout.calloutKey = FLOWEBPFEXT_FLOW_ESTABLISHED_CALLOUT_V6;
    callout.classifyFn = flowebpfext_flow_established_classify;
    // callout.flowDeleteFn = flowebpfext_flow_delete;
    callout.flags = 0;
    // needs to be registered on FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6
    status = FwpsCalloutRegister(NULL, &callout, &calloutId);
    if (!NT_SUCCESS(status))
        goto Cleanup;
    g_flowebpfext_flow_established_callout_id_v6 = calloutId;

    // Add callout to filter engine for IPv4
    mCallout.calloutKey = FLOWEBPFEXT_FLOW_ESTABLISHED_CALLOUT_V4;
    mCallout.displayData.name = L"flowebpfext Flow Established Callout V4";
    mCallout.displayData.description = L"eBPF flow established callout for TCP/IPv4 port 443";
    mCallout.applicableLayer = FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4;
    status = FwpmCalloutAdd0(engineHandle, &mCallout, NULL, NULL);
    if (!NT_SUCCESS(status))
        goto Cleanup;

    // Add callout to filter engine for IPv6
    mCallout.calloutKey = FLOWEBPFEXT_FLOW_ESTABLISHED_CALLOUT_V6;
    mCallout.displayData.name = L"flowebpfext Flow Established Callout V6";
    mCallout.displayData.description = L"eBPF flow established callout for TCP/IPv6 port 443";
    mCallout.applicableLayer = FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6;
    status = FwpmCalloutAdd0(engineHandle, &mCallout, NULL, NULL);
    if (!NT_SUCCESS(status))
        goto Cleanup;

    // Add filter for IPv4
    filter.displayData.name = L"flowebpfext Flow Established Filter V4";
    filter.displayData.description = L"Filter for TCP/IPv4 port 443 (flow established)";
    filter.layerKey = FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4;
    filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
    filter.action.calloutKey = FLOWEBPFEXT_FLOW_ESTABLISHED_CALLOUT_V4;
    filter.filterCondition = cond;
    filter.numFilterConditions = 2;
    filter.subLayerKey = FLOWEBPFEXT_FLOW_ESTABLISHED_CALLOUT_V4;
    filter.weight.type = FWP_EMPTY;
    filter.flags = FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT | FWPM_FILTER_FLAG_PERMIT_IF_CALLOUT_UNREGISTERED;
    // Condition 0: Protocol == TCP
    cond[0].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
    cond[0].matchType = FWP_MATCH_EQUAL;
    cond[0].conditionValue.type = FWP_UINT8;
    cond[0].conditionValue.uint8 = IPPROTO_TCP;
    // Condition 1: Local port == 443
    cond[1].fieldKey = FWPM_CONDITION_IP_LOCAL_PORT;
    cond[1].matchType = FWP_MATCH_EQUAL;
    cond[1].conditionValue.type = FWP_UINT16;
    cond[1].conditionValue.uint16 = FLOWEBPFEXT_PORT_HTTPS;
    status = FwpmFilterAdd0(engineHandle, &filter, NULL, NULL);
    if (!NT_SUCCESS(status))
        goto Cleanup;

    // Add filter for IPv6
    filter.displayData.name = L"flowebpfext Flow Established Filter V6";
    filter.displayData.description = L"Filter for TCP/IPv6 port 443 (flow established)";
    filter.layerKey = FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6;
    filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
    filter.action.calloutKey = FLOWEBPFEXT_FLOW_ESTABLISHED_CALLOUT_V6;
    filter.filterCondition = cond;
    filter.numFilterConditions = 2;
    filter.subLayerKey = FLOWEBPFEXT_FLOW_ESTABLISHED_CALLOUT_V6;
    filter.weight.type = FWP_EMPTY;
    filter.flags = FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT | FWPM_FILTER_FLAG_PERMIT_IF_CALLOUT_UNREGISTERED;
    // Condition 0: Protocol == TCP
    cond[0].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
    cond[0].matchType = FWP_MATCH_EQUAL;
    cond[0].conditionValue.type = FWP_UINT8;
    cond[0].conditionValue.uint8 = IPPROTO_TCP;
    // Condition 1: Local port == 443
    cond[1].fieldKey = FWPM_CONDITION_IP_LOCAL_PORT;
    cond[1].matchType = FWP_MATCH_EQUAL;
    cond[1].conditionValue.type = FWP_UINT16;
    cond[1].conditionValue.uint16 = FLOWEBPFEXT_PORT_HTTPS;
    status = FwpmFilterAdd0(engineHandle, &filter, NULL, NULL);
    // Ignore status for last filter

Cleanup:
    if (engineHandle)
        FwpmEngineClose0(engineHandle);
}

void
flowebpfext_flow_unregister_callouts()
{
    // Unregister stream classify callouts
    if (g_flowebpfext_stream_callout_id_v4)
        FwpsCalloutUnregisterById(g_flowebpfext_stream_callout_id_v4);
    if (g_flowebpfext_stream_callout_id_v6)
        FwpsCalloutUnregisterById(g_flowebpfext_stream_callout_id_v6);
    // Unregister flow established callouts
    if (g_flowebpfext_flow_established_callout_id_v4)
        FwpsCalloutUnregisterById(g_flowebpfext_flow_established_callout_id_v4);
    if (g_flowebpfext_flow_established_callout_id_v6)
        FwpsCalloutUnregisterById(g_flowebpfext_flow_established_callout_id_v6);
    // Optionally reset IDs to 0
    g_flowebpfext_stream_callout_id_v4 = 0;
    g_flowebpfext_stream_callout_id_v6 = 0;
    g_flowebpfext_flow_established_callout_id_v4 = 0;
    g_flowebpfext_flow_established_callout_id_v6 = 0;
}