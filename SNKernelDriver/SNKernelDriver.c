#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include "SNKernelDefinitions.h"

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")

// global variables
SNKERNEL_DATA SNKernelData;



NTSTATUS
SNKernelPortConnect(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID* ConnectionCookie
);


VOID
SNKernelPortDisconnect (
    _In_opt_ PVOID ConnectionCookie
    );


// alloc code sections for routines 
#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, SNKernelPortConnect)
#pragma alloc_text(PAGE, SNKernelPreCreate)
#pragma alloc_text(PAGE, SNKernelPostCreate)
#pragma alloc_text(PAGE, SNKernelPreCleanup)
#pragma alloc_text(PAGE, SNKernelPreFileSystemControl)
#pragma alloc_text(PAGE, SNKernelPortDisconnect)
#endif


const FLT_OPERATION_REGISTRATION Callbacks[] = {

    { IRP_MJ_CREATE,
      0,
      SNKernelPreCreate,
      SNKernelPostCreate},

    { IRP_MJ_CLEANUP,
      0,
      SNKernelPreCleanup,
      NULL},

#if (WINVER>=0x0602)

    { IRP_MJ_FILE_SYSTEM_CONTROL,
      0,
      SNKernelPreFileSystemControl,
      NULL
    },

#endif

    { IRP_MJ_OPERATION_END}
};


const FLT_CONTEXT_REGISTRATION ContextRegistration[] = {

    { FLT_STREAMHANDLE_CONTEXT,
      0,
      NULL,
      sizeof(BOOLEAN),
      'chBS' },

    { FLT_CONTEXT_END }
};


const FLT_REGISTRATION FilterRegistration = {

    sizeof(FLT_REGISTRATION),           //  Size
    FLT_REGISTRATION_VERSION,           //  Version
    0,                                  //  Flags
    ContextRegistration,                //  Context Registration.
    Callbacks,                          //  Operation callbacks
    SNKernelUnload,                      //  FilterUnload
    SNKernelInstanceSetup,               //  InstanceSetup
    SNKernelQueryTeardown,               //  InstanceQueryTeardown
    NULL,                               //  InstanceTeardownStart
    NULL,                               //  InstanceTeardownComplete
    NULL,                               //  GenerateFileName
    NULL,                               //  GenerateDestinationFileName
    NULL                                //  NormalizeNameComponent
};






NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT     DriverObject,
    _In_ PUNICODE_STRING    RegistryPath
)
{    
    UNREFERENCED_PARAMETER(RegistryPath);

    UNICODE_STRING uniString;
    NTSTATUS status;
    PSECURITY_DESCRIPTOR sd;
    OBJECT_ATTRIBUTES ObjectAttributes;


    ExInitializeDriverRuntime(DrvRtPoolNxOptIn);


    // this is where the attachments happen
    status = FltRegisterFilter(DriverObject,
        &FilterRegistration,
        &SNKernelData.Filter);



    RtlInitUnicodeString(&uniString, SNKernelPortName);

    status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);

    if (NT_SUCCESS(status)) {

        InitializeObjectAttributes(
            &ObjectAttributes,
            &uniString,
            OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
            NULL,
            sd);

        status = FltCreateCommunicationPort(
            SNKernelData.Filter,
            SNKernelData.ServerPort,
            &ObjectAttributes,
            NULL,
            SNKernelPortConnect,
            SNKernelPortDisconnect,
            NULL,
            1
        );

        FltFreeSecurityDescriptor(sd);
        
        
        if (NT_SUCCESS(status)) {

               //
               //  Start filtering I/O.
               //

            status = FltStartFiltering(SNKernelData.Filter);

            if (NT_SUCCESS(status)) {

                return STATUS_SUCCESS;
            }

            FltCloseCommunicationPort(SNKernelData.ServerPort);
        }

    
    }
    

    FltUnregisterFilter(SNKernelData.Filter);

    return status;
}

FLT_PREOP_CALLBACK_STATUS SNKernelPreCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, _Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
{
    return FLT_PREOP_CALLBACK_STATUS();
}

FLT_POSTOP_CALLBACK_STATUS SNKernelPostCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID CompletionContext, FLT_POST_OPERATION_FLAGS Flags)
{
    return FLT_POSTOP_CALLBACK_STATUS();
}

FLT_PREOP_CALLBACK_STATUS SNKernelPreCleanup(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, _Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
{
    return FLT_PREOP_CALLBACK_STATUS();
}

FLT_PREOP_CALLBACK_STATUS SNKernelPreFileSystemControl(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, _Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
{
    return FLT_PREOP_CALLBACK_STATUS();
}

NTSTATUS SNKernelUnload(FLT_FILTER_UNLOAD_FLAGS Flags)
{
    return NTSTATUS();
}

NTSTATUS SNKernelInstanceSetup(PCFLT_RELATED_OBJECTS FltObjects, FLT_INSTANCE_SETUP_FLAGS Flags, DEVICE_TYPE VolumeDeviceType, FLT_FILESYSTEM_TYPE VolumeFilesystemType)
{
    return NTSTATUS();
}

NTSTATUS SNKernelQueryTeardown(PCFLT_RELATED_OBJECTS FltObjects, FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags)
{
    return NTSTATUS();
}
