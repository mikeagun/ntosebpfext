// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "ebpf_ext.h"
#include "flow_ebpf_ext_helper.h"
// #include "usersim\fwp_test.h"
// #include "usersim\km\platform.h"
#include "fwp_test.h"
#include "platform.h"

// FIXME (before merge): These helpers have not been fully reviewed/implemented.

// extern "C"
//{
//     NTSTATUS
//     ebpf_ext_register_flow();
//     void
//     ebpf_ext_unregister_flow();
// }
//
//_flow_ebpf_ext_helper::_flow_ebpf_ext_helper()
//{
//     platform_initialized = platform_initiate() == 0;
//     trace_initiated = platform_initialized;
//     _ebpf_ext_driver_device_object = device_object;
// }
//
//_flow_ebpf_ext_helper::_flow_ebpf_ext_helper(
//     _In_opt_ const void* npi_specific_characteristics,
//     _In_opt_ _ebpf_extension_dispatch_function dispatch_function,
//     _In_opt_ flowebpfext_helper_base_client_context_t* client_context)
//     : dispatch_function(dispatch_function), client_context(client_context)
//{
//     platform_initialized = platform_initiate() == 0;
//     trace_initiated = platform_initialized;
//     _ebpf_ext_driver_device_object = device_object;
//     NTSTATUS status = ebpf_ext_register_flow();
//     if (!NT_SUCCESS(status)) {
//         throw std::runtime_error("Failed to register flow providers");
//     }
//
//     if (client_context) {
//         client_context->helper = this;
//         client_context->desired_attach_type = BPF_ATTACH_TYPE_FLOW_CLASSIFY;
//     }
//
//     // Register as NMR client
//     auto client_registration = std::make_unique<nmr_client_registration_t>();
//     client_registration->parent = this;
//     client_registration->characteristics.Header.Revision = NPI_CLIENT_CHARACTERISTICS_REVISION_1;
//     client_registration->characteristics.Header.Size = sizeof(NPI_CLIENT_CHARACTERISTICS);
//     client_registration->characteristics.Flags = 0;
//     client_registration->characteristics.ClientContext = client_registration.get();
//     client_registration->characteristics.ClientAttachProvider = _nmr_client_attach_provider;
//     client_registration->characteristics.ClientDetachProvider = _nmr_client_detach_provider;
//     client_registration->characteristics.ClientCleanupBindingContext = _nmr_client_cleanup_binding_context;
//
//     // Set up the NPI ID for flow classify
//     static const GUID EBPF_ATTACH_TYPE_FLOW_CLASSIFY_GUID = {
//         0x12345678, 0x1234, 0x5678, {0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78}};
//
//     client_registration->characteristics.ClientRegistrationInstance.NpiId =
//         (PNPIID)&EBPF_ATTACH_TYPE_FLOW_CLASSIFY_GUID;
//     client_registration->characteristics.ClientRegistrationInstance.ModuleId =
//         (PNPI_MODULEID)&EBPF_ATTACH_TYPE_FLOW_CLASSIFY_GUID;
//     client_registration->characteristics.ClientRegistrationInstance.Number = 0;
//     client_registration->characteristics.ClientRegistrationInstance.NpiSpecificCharacteristics =
//         (void*)npi_specific_characteristics;
//
//     status = NmrRegisterClient(
//         &client_registration->characteristics, client_registration.get(), &client_registration->registration_handle);
//     if (NT_SUCCESS(status)) {
//         client_registrations.push_back(std::move(client_registration));
//     }
// }
//
//_flow_ebpf_ext_helper::~_flow_ebpf_ext_helper()
//{
//     // Unregister all client registrations
//     for (auto& registration : client_registrations) {
//         if (registration->registration_handle) {
//             NmrDeregisterClient(registration->registration_handle);
//         }
//     }
//     client_registrations.clear();
//
//     ebpf_ext_unregister_flow();
//
//     if (trace_initiated) {
//         platform_terminate();
//     }
// }
//
// std::vector<GUID>
//_flow_ebpf_ext_helper::program_info_provider_guids()
//{
//     std::vector<GUID> guids;
//     for (const auto& provider : program_info_providers) {
//         guids.push_back(provider.first);
//     }
//     return guids;
// }
//
// ebpf_extension_data_t
//_flow_ebpf_ext_helper::get_program_info_provider_data(_In_ const GUID& program_info_provider)
//{
//     auto it = program_info_providers.find(program_info_provider);
//     if (it != program_info_providers.end()) {
//         return *(it->second->provider_data);
//     }
//     return {};
// }
//
// NTSTATUS
//_flow_ebpf_ext_helper::_nmr_client_attach_provider(
//     _In_ HANDLE nmr_binding_handle,
//     _In_ void* client_context,
//     _In_ const NPI_REGISTRATION_INSTANCE* provider_registration_instance)
//{
//     UNREFERENCED_PARAMETER(nmr_binding_handle);
//
//     auto registration = reinterpret_cast<nmr_client_registration_t*>(client_context);
//     auto helper = registration->parent;
//
//     if (helper->client_context) {
//         helper->client_context->provider_binding_context = client_context;
//     }
//
//     return STATUS_SUCCESS;
// }
//
// NTSTATUS
//_flow_ebpf_ext_helper::_nmr_client_detach_provider(_In_ void* client_binding_context)
//{
//     UNREFERENCED_PARAMETER(client_binding_context);
//     return STATUS_SUCCESS;
// }
//
// void
//_flow_ebpf_ext_helper::_nmr_client_cleanup_binding_context(_In_ void* client_binding_context)
//{
//     UNREFERENCED_PARAMETER(client_binding_context);
// }
