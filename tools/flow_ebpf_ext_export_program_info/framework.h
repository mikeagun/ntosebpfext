#pragma once


#include <winsock2.h>
#include <windows.h>
#include <netiodef.h>

// Define minimal kernel types for user-mode compilation
// These definitions are compatible with kernel definitions but suitable for user-mode
typedef struct _DEVICE_OBJECT {
    PVOID placeholder;  // Placeholder structure for user-mode compatibility
} DEVICE_OBJECT, *PDEVICE_OBJECT;
//#include <ntifs.h>
//#include <wdm.h>

//#define NDIS60
//#include <ntdef.h>
//#include <ntstatus.h>
//#pragma warning(push)
//#pragma warning(disable : 28253) // Inconsistent annotation for '_umul128'
//#include <ntintsafe.h>
//#pragma warning(pop)
//#include <ntifs.h>

//#include <ntdef.h>
//#include <ntstatus.h>
//#include <wdm.h>
//#include <winsock2.h>
//#include <windows.h>
////#include <winnt.h>
//#include <netiodef.h>

//typedef struct DECLSPEC_ALIGN(MEMORY_ALLOCATION_ALIGNMENT) _DEVICE_OBJECT {
//    CSHORT Type;
//    USHORT Size;
//    LONG ReferenceCount;
//    struct _DRIVER_OBJECT *DriverObject;
//    struct _DEVICE_OBJECT *NextDevice;
//    struct _DEVICE_OBJECT *AttachedDevice;
//    struct _IRP *CurrentIrp;
//    PIO_TIMER Timer;
//    ULONG Flags;                                // See above:  DO_...
//    ULONG Characteristics;                      // See ntioapi:  FILE_...
//    __volatile PVPB Vpb;
//    PVOID DeviceExtension;
//    DEVICE_TYPE DeviceType;
//    CCHAR StackSize;
//    union {
//        LIST_ENTRY ListEntry;
//        WAIT_CONTEXT_BLOCK Wcb;
//    } Queue;
//    ULONG AlignmentRequirement;
//    KDEVICE_QUEUE DeviceQueue;
//    KDPC Dpc;
//
//    //
//    //  The following field is for exclusive use by the filesystem to keep
//    //  track of the number of Fsp threads currently using the device
//    //
//
//    ULONG ActiveThreadCount;
//    PSECURITY_DESCRIPTOR SecurityDescriptor;
//    KEVENT DeviceLock;
//
//    USHORT SectorSize;
//    USHORT Spare1;
//
//    struct _DEVOBJ_EXTENSION  *DeviceObjectExtension;
//    PVOID  Reserved;
//
//} DEVICE_OBJECT;

//typedef struct _DEVICE_OBJECT *PDEVICE_OBJECT; 

// #include <assert.h>
// 
// // Get definitions for ULONGLONG, etc.
// // #include <winsock2.h>
// // #include <windows.h>
// // #include <ntstatus.h>
// #include <netioapi.h>
// #include <netiodef.h>
// 
// #ifdef _DEBUG
// #define ebpf_assert(x) assert(x)
// #else
// #define ebpf_assert(x) (void)(x)
// #endif //!_DEBUG


//#include <ntdef.h>
//#include <ntstatus.h>
//#pragma warning(push)
//#pragma warning(disable : 28253) // Inconsistent annotation for '_umul128'
//#include <ntintsafe.h>
//#pragma warning(pop)
//#include <ntifs.h>
//#include <netioddk.h>
//#include <ntddk.h>
//#pragma warning(push)
//#pragma warning(disable : 28196) // Inconsistent annotation for '_umul128'
//#include <ntstrsafe.h>
//#pragma warning(pop)
//#include <stdbool.h>
//#include <stdint.h>
//#include <wdm.h>
//#pragma warning(push)
//#pragma warning(disable : 4062) // unhandled switch case
//#include <wdf.h>
//#pragma warning(pop)
//// clang-format off
//#include <initguid.h>
//#include <fwpmk.h>
//#include <fwpsk.h>
//// clang-format on