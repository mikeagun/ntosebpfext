// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include "ebpf_ext.h"

/**
 * @brief Unregister FLOW NPI providers.
 *
 */
void
flowebpfext_unregister_providers();

/**
 * @brief Register FLOW NPI providers.
 *
 * @retval STATUS_SUCCESS Operation succeeded.
 * @retval STATUS_UNSUCCESSFUL Operation failed.
 */
NTSTATUS
flowebpfext_register_providers();
