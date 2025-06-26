// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include <ntddk.h>
#pragma warning(push)
#pragma warning(disable : 4201) // unnamed struct/union
#include <fwpmk.h>
#include <fwpsk.h>
#pragma warning(pop)
#include <netiodef.h>
#pragma warning(push)
#pragma warning(disable : 4062) // enumerator 'identifier' in switch of enum 'enumeration' is not handled
#include <wdf.h>
#pragma warning(pop)


//#include <guiddef.h>
//#include <netioapi.h>
//#include <netiodef.h>

// Get definitions for ULONGLONG, etc.
#include <guiddef.h>
#include <netioapi.h>
#include <netiodef.h>

#ifdef _MSC_VER
#include <guiddef.h>
#else
typedef uint8_t GUID[16];
#endif

#if !defined(NO_CRT) && !defined(_NO_CRT_STDIO_INLINE)
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#else
typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned short wchar_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;
typedef unsigned long long size_t;
#define bool _Bool
#endif


#include "cxplat_fault_injection.h"
#include "shared_context.h"
#include "usersim\ex.h"
#include "usersim\fwp_test.h"
#include "usersim\ke.h"
#include "usersim\ps.h"
#include "usersim\rtl.h"
#include "usersim\se.h"
#include "usersim\wdf.h"
//#include "kernel_um.h"
#include "..\src\net_platform.h"
//netebpfext_platform.h

//#include "..\src\fwp_um.h"

//#include <winsock2.h>
//#include <windows.h>
//
//#include <guiddef.h>
//#include <netioapi.h>
//#include <netiodef.h>
//#include <netioddk.h>
//#include <netiodef.h>
//#include <guiddef.h>
//#include <initguid.h>

#define ebpf_fault_injection_is_enabled() cxplat_fault_injection_is_enabled()

#ifdef __cplusplus
extern "C"
{
#endif
    typedef LIST_ENTRY ebpf_list_entry_t;

    inline void
    ebpf_list_initialize(_Out_ ebpf_list_entry_t* list_head)
    {

        list_head->Flink = list_head->Blink = list_head;
        return;
    }

    inline bool
    ebpf_list_is_empty(_In_ const ebpf_list_entry_t* list_head)
    {

        return (list_head->Flink == list_head);
    }

    inline void
    ebpf_list_insert_tail(_Inout_ ebpf_list_entry_t* list_head, _Out_ ebpf_list_entry_t* entry)
    {
        ebpf_list_entry_t* previous_entry;
        previous_entry = list_head->Blink;

        entry->Flink = list_head;
        entry->Blink = previous_entry;
        previous_entry->Flink = entry;
        list_head->Blink = entry;
        ebpf_assert(list_head->Blink->Flink == list_head);
        ebpf_assert(list_head->Flink->Blink == list_head);
        return;
    }

    inline bool
    ebpf_list_remove_entry(_Inout_ ebpf_list_entry_t* entry)
    {
        ebpf_list_entry_t* previous_entry;
        ebpf_list_entry_t* next_entry;

        next_entry = entry->Flink;
        previous_entry = entry->Blink;

        previous_entry->Flink = next_entry;
        next_entry->Blink = previous_entry;
        return (previous_entry == next_entry);
    }

    inline ebpf_list_entry_t*
    ebpf_list_remove_head_entry(_Inout_ ebpf_list_entry_t* list_head)
    {
        if (list_head->Flink == list_head) {
            return list_head;
        }
        ebpf_list_entry_t* removed = list_head->Flink;
        list_head->Flink = removed->Flink;
        removed->Flink->Blink = list_head;

        return removed;
    }

    inline void
    ebpf_list_append_tail_list(_Inout_ ebpf_list_entry_t* list_head, _Inout_ ebpf_list_entry_t* list_to_append)
    {
        ebpf_list_entry_t* list_end = list_head->Blink;

        list_head->Blink->Flink = list_to_append;
        list_head->Blink = list_to_append->Blink;
        list_to_append->Blink->Flink = list_head;
        list_to_append->Blink = list_end;
    }

    inline void
    ebpf_probe_for_write(_Out_writes_bytes_(length) void* address, size_t length, unsigned long alignment)
    {
        if (((uintptr_t)address % alignment) != 0) {
            RaiseException(STATUS_DATATYPE_MISALIGNMENT, 0, 0, NULL);
        }
        UNREFERENCED_PARAMETER(length);
    }

#ifdef __cplusplus
}
#endif
