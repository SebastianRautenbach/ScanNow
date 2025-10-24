#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include "SNKernelDefinitions.h"

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")


PUNICODE_STRING ScannedExtensions;
ULONG ScannedExtentionsCount;

// this is incase no extension is loaded from the registry
UNICODE_STRING ScannedExtensionDefault = RTL_CONSTANT_STRING(L"exe");





//////////////////////////////////////////////////////////////////////////////
//
//      Global definitions
//
//////////////////////////////////////////////////////////////////////////////

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


VOID
SNKernelFreeExtensions(
);

BOOLEAN
SNKernelCheckExtension(
    _In_ PUNICODE_STRING Extension
);


NTSTATUS
SNKernelAntivirusScanUM(
    _In_ PFLT_FILE_NAME_INFORMATION FileInfo,
    _Inout_ PFLT_CALLBACK_DATA Data
);


//////////////////////////////////////////////////////////////////////////////
//
//      alloc code sections for routines
//
//////////////////////////////////////////////////////////////////////////////

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, SNKernelPortConnect)
#pragma alloc_text(PAGE, SNKernelFreeExtensions)
#pragma alloc_text(PAGE, SNKernelPreCreate)
#pragma alloc_text(PAGE, SNKernelPostCreate)
#pragma alloc_text(PAGE, SNKernelPreCleanup)
#pragma alloc_text(PAGE, SNKernelPreFileSystemControl)
#pragma alloc_text(PAGE, SNKernelPortDisconnect)
#pragma alloc_text(PAGE, SNKernelCheckExtension)
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



//////////////////////////////////////////////////////////////////////////////
//
//      DRIVER ENTRY POINT
//
//////////////////////////////////////////////////////////////////////////////


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




    status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);

    if (NT_SUCCESS(status)) {

        InitializeObjectAttributes(
            &ObjectAttributes,
            &uniString,
            OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
            NULL,
            sd);


        RtlInitUnicodeString(&uniString, SNKernelPortName);
        
        
        //
        //  Create port so only Admin and System can access it
        //

        status = FltCreateCommunicationPort(
            SNKernelData.Filter,
            &SNKernelData.ServerPort,
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

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "(*) SNKernelDriver -> SUCCESS DRIVER ENTRY\n"));

    return status;
}




FLT_PREOP_CALLBACK_STATUS SNKernelPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{    
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext = NULL);

    PAGED_CODE();

    // Is this connection done by our Antivirus

    if (IoThreadToProcess(Data->Thread) == SNKernelData.UserProcess) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "(*) SNKernelDriver -> SNKernelPreCreate -> Allowing for trusted process\n"));
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS SNKernelPostCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext = NULL);
    UNREFERENCED_PARAMETER(Flags);

    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION nameInfo;
    BOOLEAN matchedExtentionFile;

    // avoid scanning if it failed creating
    if (!NT_SUCCESS(Data->IoStatus.Status) ||
        (STATUS_REPARSE == Data->IoStatus.Status)
        ) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    status = FltGetFileNameInformation(Data,
        FLT_FILE_NAME_NORMALIZED, FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo
    );

    if (!NT_SUCCESS(status)) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    FltParseFileNameInformation(nameInfo);

    matchedExtentionFile = SNKernelCheckExtension(nameInfo);


    if (!matchedExtentionFile) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    
    SNKernelAntivirusScanUM(nameInfo, Data);
    FltReleaseFileNameInformation(nameInfo);
    
    



    // This calls the function to scan in the user mode antivirus

    // (VOID) 

    return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS SNKernelPreCleanup(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext = NULL);


    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS SNKernelPreFileSystemControl(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext = NULL);


    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

NTSTATUS SNKernelUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(Flags);


    return STATUS_SUCCESS;
}

NTSTATUS SNKernelInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
)
{    
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);
    UNREFERENCED_PARAMETER(VolumeFilesystemType);


    PAGED_CODE();


    FLT_ASSERT(FltObjects->Filter == SNKernelData.Filter);

    // avoid attaching to network file system
    if(VolumeDeviceType == FILE_DEVICE_NETWORK_FILE_SYSTEM) {
        return STATUS_FLT_DO_NOT_ATTACH;
    }

    return STATUS_SUCCESS;
}

NTSTATUS SNKernelQueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);


    return STATUS_SUCCESS;
}

NTSTATUS
SNKernelPortConnect(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID* ConnectionCookie
) {
    UNREFERENCED_PARAMETER(ClientPort);
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);
    UNREFERENCED_PARAMETER(ConnectionCookie = NULL);

    return STATUS_SUCCESS;
}


VOID
SNKernelPortDisconnect(
    _In_opt_ PVOID ConnectionCookie
) {
    UNREFERENCED_PARAMETER(ConnectionCookie = NULL);
}


VOID
SNKernelFreeExtensions(
) {
    PAGED_CODE();

    while(ScannedExtentionsCount > 0) {
        ScannedExtentionsCount--;

        if (ScannedExtensions != &ScannedExtensionDefault) {
            SNKernelFreeUnicodeString(ScannedExtensions + ScannedExtentionsCount);
        }
    }
    if (ScannedExtensions != &ScannedExtensionDefault && ScannedExtensions != NULL) {
        ExFreePoolWithTag(ScannedExtensions, SNK_STRING_TAG_DEF);
    }

    ScannedExtensions = NULL;
}

BOOLEAN
SNKernelCheckExtension(
    _In_ PUNICODE_STRING Extension
) {
    ULONG count;

    if (Extension->Length == 0) {
        return FALSE;
    }
    // check if the extention matches the array of known extentions
    for (count = 0; count < ScannedExtentionsCount; count++) {
        if (RtlCompareUnicodeString(Extension, ScannedExtensions + count, TRUE) == 0) {
            return TRUE;
        }
    }

    return FALSE;
}


NTSTATUS
SNKernelAntivirusScanUM(    
    _In_ PFLT_FILE_NAME_INFORMATION FileInfo,
    _Inout_ PFLT_CALLBACK_DATA Data
) {
    
    NTSTATUS status;
    PSN_NOTIFICATION notification;    

    if (SNKernelData.ClientPort == NULL) {
        return STATUS_SUCCESS;
    }


    try {
        
        notification = ExAllocatePoolZero(NonPagedPool, sizeof(SN_NOTIFICATION), SNK_POOL_TAG_DEF);

        
        if (notification == NULL) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            leave;
        }

        
        RtlStringCchCopyNW(
            notification->FilePath,
            SNK_MAX_PATH_CHARS,
            FileInfo->Name.Buffer,
            FileInfo->Name.Length / sizeof(WCHAR)
        );

        notification->Length = FileInfo->Name.Length;
        notification->TotalLength = sizeof(SN_NOTIFICATION);



        status = FltSendMessage(
            SNKernelData.Filter,
            &SNKernelData.ClientPort,
            notification,
            sizeof(SN_NOTIFICATION),
            notification,
            NULL,
            NULL);
    
    } finally {

        if (notification != NULL) {
            ExFreePoolWithTag(notification, SNK_POOL_TAG_DEF);
        }

    }

    return status;
   

}