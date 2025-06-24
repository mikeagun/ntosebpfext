//// Copyright (c) Microsoft Corporation
//// SPDX-License-Identifier: MIT
// #pragma once
//
// #include "catch_wrapper.hpp"
//
// #ifdef FUZZER
// #undef REQUIRE
// #def ine  REQUIRE(X)                 \
//    {                              \
//        bool x = (X);              \
//        UNREFERENCED_PARAMETER(x); \
//    }
// #endif
//
// #include "ebpf_ext.h"
// #include "ebpf_ext_tracelog.h"
// #include "ebpf_extension_uuids.h"
// #include "ebpf_flow_hooks.h"
// #include "flow_ebpf_ext_program_info.h"
//
// #include <iostream>
// #include <vector>
//
// typedef struct _flowebpfext_helper_base_client_context
//{
//     class _flow_ebpf_ext_helper* helper;
//     void* provider_binding_context;
//     bpf_attach_type_t desired_attach_type; // BPF_ATTACH_TYPE_FLOW_CLASSIFY for flow extension
//     flow_classify_md_t flow_context;
// } flowebpfext_helper_base_client_context_t;
//
// typedef class _flow_ebpf_ext_helper
//{
//   public:
//     _flow_ebpf_ext_helper();
//     _flow_ebpf_ext_helper(
//         _In_opt_ const void* npi_specific_characteristics,
//         _In_opt_ _ebpf_extension_dispatch_function dispatch_function,
//         _In_opt_ flowebpfext_helper_base_client_context_t* client_context);
//     ~_flow_ebpf_ext_helper();
//
//     std::vector<GUID>
//     program_info_provider_guids();
//
//     ebpf_extension_data_t
//     get_program_info_provider_data(_In_ const GUID& program_info_provider);
//
//   private:
//     bool trace_initiated = false;
//     bool platform_initialized = false;
//     DRIVER_OBJECT* driver_object = reinterpret_cast<DRIVER_OBJECT*>(this);
//     DEVICE_OBJECT* device_object = reinterpret_cast<DEVICE_OBJECT*>(this);
//
//     struct NPI_MODULEID_LESS
//     {
//         bool
//         operator()(const GUID& lhs, const GUID& rhs) const
//         {
//             int result = memcmp(&lhs, &rhs, sizeof(lhs));
//             return result < 0;
//         }
//     };
//
//     typedef struct _program_info_provider
//     {
//         _flow_ebpf_ext_helper* parent;
//         NPI_MODULEID module_id;
//         void* context;
//         const void* dispatch;
//         const ebpf_extension_data_t* provider_data;
//     } program_info_provider_t;
//     std::map<GUID, std::unique_ptr<program_info_provider_t>, NPI_MODULEID_LESS> program_info_providers;
//
//     typedef struct _nmr_client_registration
//     {
//         // Wrapper for NmrRegisterClient
//         _flow_ebpf_ext_helper* parent;
//         HANDLE registration_handle;
//         NPI_CLIENT_CHARACTERISTICS characteristics;
//     } nmr_client_registration_t;
//     std::vector<std::unique_ptr<nmr_client_registration_t>> client_registrations;
//
//     _ebpf_extension_dispatch_function dispatch_function = nullptr;
//     flowebpfext_helper_base_client_context_t* client_context = nullptr;
//
//     static NTSTATUS
//     _nmr_client_attach_provider(
//         _In_ HANDLE nmr_binding_handle,
//         _In_ void* client_context,
//         _In_ const NPI_REGISTRATION_INSTANCE* provider_registration_instance);
//
//     static NTSTATUS
//     _nmr_client_detach_provider(_In_ void* client_binding_context);
//
//     static void
//     _nmr_client_cleanup_binding_context(_In_ void* client_binding_context);
//
// } flow_ebpf_ext_helper_t;
