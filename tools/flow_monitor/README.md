# Flow Monitor

This project demonstrates how to monitor network flows using the flowebpfext eBPF extension. It consists of three main components:

## Components

### 1. flow_monitor.sys (BPF Program)
- An eBPF program that attaches to the flow classify hook
- Monitors TCP/UDP flows on port 9993 (configurable)
- Performs simple flow inspection (HTTP method detection, path traversal detection)
- Writes flow events to a ring buffer map
- Returns ALLOW, BLOCK, or NEED_MORE_DATA based on inspection results

### 2. flow_monitor_app.exe (User-mode Application)
- A C++ application that reads flow events from the ring buffer
- Displays flow information including:
  - Source and destination IP addresses and ports
  - Protocol type (TCP/UDP/etc.)
  - Flow direction (inbound/outbound)
  - Data length
  - Timestamp
  - Action taken (ALLOW/BLOCK/NEED_MORE_DATA)
  - Event type (NEW_FLOW/DATA_RECEIVED/FLOW_CLOSED)

### 3. flow_ebpf_ext_export_program_info.exe (Program Information Export)
- Exports flow program information to the eBPF store
- Required to register the flow_classify section with eBPF for Windows

## Prerequisites

- eBPF for Windows must be installed and running
- flowebpfext.sys extension must be loaded and running
- Visual Studio 2022 with C++ development tools
- Administrator privileges to load/run the programs

## Building

1. Build the solution in Visual Studio:
   ```
   MSBuild ntosebpfext.sln /p:Configuration=Release /p:Platform=x64
   ```

2. Or build individual projects:
   ```
   MSBuild tools\flow_monitor\flow_monitor.vcxproj /p:Configuration=Release /p:Platform=x64
   MSBuild tools\flow_monitor_app\flow_monitor_app.vcxproj /p:Configuration=Release /p:Platform=x64
   MSBuild tools\flow_ebpf_ext_export_program_info\flow_ebpf_ext_export_program_info.vcxproj /p:Configuration=Release /p:Platform=x64
   ```

## Usage

### Step 1: Export Program Information
First, export the flow program information to the eBPF store:
```cmd
# Clear any existing flow program information (optional)
flow_ebpf_ext_export_program_info.exe --clear

# Export the flow program information
flow_ebpf_ext_export_program_info.exe
```

### Step 2: Load the flowebpfext Extension
Make sure the flowebpfext extension is loaded:
```cmd
sc create flowebpfext type=kernel start=demand binPath=flowebpfext.sys
sc start flowebpfext
```

### Step 3: Run the Flow Monitor Application
Run the user-mode application to start monitoring flows:
```cmd
flow_monitor_app.exe
```

The application will:
1. Load the `flow_monitor.sys` BPF program
2. Attach it to the flow classify hook
3. Set up a ring buffer to receive flow events
4. Display flow events in real-time

### Example Output
```
Flow Monitor Application
Monitoring flow events from flowebpfext...
Press Ctrl+C to exit

Flow monitor started successfully!
Waiting for flow events...

[1] 14:30:15.123 NEW_FLOW TCP 192.168.1.100:12345 -> 93.184.216.34:9993 [NEED_MORE_DATA] (Data: 0 bytes, Flow: 0x123456789ABCDEF0)
[2] 14:30:15.125 DATA_RECEIVED TCP 192.168.1.100:12345 -> 93.184.216.34:9993 [NEED_MORE_DATA] (Data: 78 bytes, Flow: 0x123456789ABCDEF0)
[3] 14:30:15.127 DATA_RECEIVED TCP 192.168.1.100:12345 -> 93.184.216.34:9993 [ALLOW] (Data: 512 bytes, Flow: 0x123456789ABCDEF0)
```

## Configuration

### Port Configuration
The default monitored port is 9993 (defined as `FLOWEBPFEXT_PORT_HTTPS` in the flowebpfext extension). To monitor different ports, modify the port configuration in the flowebpfext extension and rebuild.

### Flow Inspection Logic
The BPF program includes simple flow inspection logic that can be modified in `flow_monitor.c`:
- HTTP method detection (GET, POST)
- Path traversal attack detection (../)
- Custom pattern matching can be added

### Event Types
The monitor tracks three types of flow events:
- `NEW_FLOW`: A new flow has been established
- `DATA_RECEIVED`: Data has been received on an existing flow
- `FLOW_CLOSED`: A flow has been closed (not currently implemented)

## Troubleshooting

### "Failed to open BPF object file"
- Ensure `flow_monitor.sys` is in the same directory as `flow_monitor_app.exe`
- Verify the BPF program compiled successfully

### "Failed to attach BPF program"
- Check that flowebpfext.sys is loaded and running
- Ensure the flow program information was exported successfully
- Verify administrator privileges

### "Failed to find 'flow_events_map' map"
- This indicates a compilation issue with the BPF program
- Check that the map definition in `flow_monitor.c` is correct

### No flow events appearing
- Verify that traffic is flowing on the monitored port (9993)
- Check that the flowebpfext extension is filtering the correct traffic
- Use network monitoring tools to confirm traffic is present

## Development

### Adding New Inspection Logic
To add custom flow inspection logic:

1. Modify the inspection code in `flow_monitor.c`
2. Add new event types or action types as needed
3. Update the user-mode application to handle new event types
4. Rebuild both components

### Modifying Flow Event Structure
If you need to add fields to the flow event structure:

1. Update `flow_event_info_t` in both `flow_monitor.c` and `flow_monitor_app.cpp`
2. Ensure both structures remain identical
3. Update the display logic in the user-mode application

### Performance Considerations
- The ring buffer size is set to 512KB by default
- High-frequency events may cause buffer overflow
- Consider implementing event filtering or sampling for high-traffic scenarios

## License

Copyright (c) Microsoft Corporation
SPDX-License-Identifier: MIT
