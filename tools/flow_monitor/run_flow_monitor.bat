@echo off
REM Copyright (c) Microsoft Corporation
REM SPDX-License-Identifier: MIT

REM Flow Monitor Test Script
REM This script demonstrates how to set up and run the flow monitor

echo Flow Monitor Test Script
echo ========================
echo.

REM Check if running as administrator
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Error: This script must be run as Administrator
    echo Please right-click and select "Run as administrator"
    pause
    exit /b 1
)

echo Step 1: Exporting flow program information...
echo.

REM Export flow program information
flow_ebpf_ext_export_program_info.exe
if %errorLevel% neq 0 (
    echo Error: Failed to export flow program information
    echo Make sure flow_ebpf_ext_export_program_info.exe is available
    pause
    exit /b 1
)

echo.
echo Step 2: Checking flowebpfext service status...
echo.

REM Check if flowebpfext service exists
sc query flowebpfext >nul 2>&1
if %errorLevel% neq 0 (
    echo flowebpfext service not found, attempting to create it...
    echo Note: You may need to specify the correct path to flowebpfext.sys
    sc create flowebpfext type=kernel start=demand binPath=flowebpfext.sys
    if %errorLevel% neq 0 (
        echo Error: Failed to create flowebpfext service
        echo Please ensure flowebpfext.sys is available and accessible
        pause
        exit /b 1
    )
)

REM Start the service if it's not running
sc query flowebpfext | find "RUNNING" >nul
if %errorLevel% neq 0 (
    echo Starting flowebpfext service...
    sc start flowebpfext
    if %errorLevel% neq 0 (
        echo Warning: Failed to start flowebpfext service
        echo The service may already be running or there may be an issue
    )
) else (
    echo flowebpfext service is already running
)

echo.
echo Step 3: Starting flow monitor application...
echo.
echo Press Ctrl+C in the flow monitor application to stop monitoring
echo.

REM Run the flow monitor application
flow_monitor_app.exe
if %errorLevel% neq 0 (
    echo Error: Failed to run flow monitor application
    echo Make sure flow_monitor_app.exe and flow_monitor.sys are available
)

echo.
echo Flow monitoring session ended.
pause
