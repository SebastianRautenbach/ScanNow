#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include <ntstrsafe.h>
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
    _In_ UNICODE_STRING FileInfo
);

NTSTATUS
SNKernelInitScannedExtentions(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
);


NTSTATUS
SNKernelOpenServiceParametersKey(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING ServiceRegistryPath,
    _Out_ PHANDLE ServiceParametersKey
);


typedef
NTSTATUS
(*PFN_IoOpenDriverRegistryKey) (
    PDRIVER_OBJECT     DriverObject,
    DRIVER_REGKEY_TYPE RegKeyType,
    ACCESS_MASK        DesiredAccess,
    ULONG              Flags,
    PHANDLE            DriverRegKey
    );


PFN_IoOpenDriverRegistryKey
SNKernelGetIoOpenDriverRegistryKey(
    VOID
);

VOID
SNKernelFreeExtensions(
);



VOID
SNKernelFreeUnicodeString(
    _Inout_ PUNICODE_STRING String
);



NTSTATUS
SNKernelAllocateUnicodeString(
    _Inout_ PUNICODE_STRING String
);


//////////////////////////////////////////////////////////////////////////////
//
//      alloc code sections for routines
//
//////////////////////////////////////////////////////////////////////////////

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(INIT, SNKernelGetIoOpenDriverRegistryKey)
#pragma alloc_text(INIT, SNKernelOpenServiceParametersKey)
#pragma alloc_text(INIT, SNKernelInitScannedExtentions)
#pragma alloc_text(PAGE, SNKernelPortConnect)
#pragma alloc_text(PAGE, SNKernelFreeExtensions)
#pragma alloc_text(PAGE, SNKernelPreCreate)
#pragma alloc_text(PAGE, SNKernelPostCreate)
#pragma alloc_text(PAGE, SNKernelPreCleanup)
#pragma alloc_text(PAGE, SNKernelPreFileSystemControl)
#pragma alloc_text(PAGE, SNKernelPortDisconnect)
#pragma alloc_text(PAGE, SNKernelCheckExtension)
#pragma alloc_text(PAGE, SNKernelFreeUnicodeString)
#pragma alloc_text(PAGE, SNKernelAllocateUnicodeString)
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
      SNK_POOL_TAG_DEF },

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
    UNICODE_STRING uniString;
    NTSTATUS status;
    PSECURITY_DESCRIPTOR sd;
    OBJECT_ATTRIBUTES ObjectAttributes;


    ExInitializeDriverRuntime(DrvRtPoolNxOptIn);

    
    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "(*) SNKernelDriver -> DriverEntry FLT_REGISTRATION_VERSION = %u\n", FLT_REGISTRATION_VERSION));

    
    // this is where the attachments happen
    status = FltRegisterFilter(
        DriverObject,
        &FilterRegistration,
        &SNKernelData.Filter);

    
    if (!NT_SUCCESS(status)) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "(*) SNKernelDriver -> DriverEntry -> FltRegisterFilter error status=%u", status));
        return status;
    }


    status = SNKernelInitScannedExtentions(DriverObject, RegistryPath);

    if (!NT_SUCCESS(status)) {

        status = STATUS_SUCCESS;

        ScannedExtensions = &ScannedExtensionDefault;
        ScannedExtentionsCount = 1;
    }


    status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);

    if (NT_SUCCESS(status)) {

        RtlInitUnicodeString(&uniString, SNKernelPortName);
        
        
        InitializeObjectAttributes(
            &ObjectAttributes,
            &uniString,
            OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
            NULL,
            sd);


        
        
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
    
    SNKernelFreeExtensions();

    FltUnregisterFilter(SNKernelData.Filter);

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "(*) SNKernelDriver -> SUCCESS DRIVER ENTRY\n"));

    return status;
}




/*
*       This function is called when a file is in the initial process of creation
*/

FLT_PREOP_CALLBACK_STATUS SNKernelPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{    
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext = NULL);

    PAGED_CODE();

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "(*) SNKernelDriver -> SNKernelPreCreate\n"));

    // Is this connection done by our Antivirus

    if (IoThreadToProcess(Data->Thread) == SNKernelData.UserProcess) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "(*) SNKernelDriver -> SNKernelPreCreate -> Allowing for trusted process\n"));
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}


/*
*       This function is called when a file is created.
*       We can use this callback to do a user-mode scan from our antivirus
*/

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


    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "(*) SNKernelDriver -> SNKernelPostCreate\n"));

    // avoid scanning if it failed creating
    if (!NT_SUCCESS(Data->IoStatus.Status) ||
        (STATUS_REPARSE == Data->IoStatus.Status)
        ) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    status = FltGetFileNameInformation(Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo
    );

    if (!NT_SUCCESS(status)) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    FltParseFileNameInformation(nameInfo);

    matchedExtentionFile = SNKernelCheckExtension(&nameInfo->Extension);


    if (!matchedExtentionFile) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    
    (VOID) SNKernelAntivirusScanUM(nameInfo->Name);


    FltReleaseFileNameInformation(nameInfo);
    
   

    return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS SNKernelPreCleanup(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{
    UNREFERENCED_PARAMETER(Data);    
    UNREFERENCED_PARAMETER(CompletionContext = NULL);

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "(*) SNKernelDriver -> SNKernelPreCleanup\n"));

    (VOID) SNKernelAntivirusScanUM(FltObjects->FileObject->FileName);

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


    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "(*) SNKernelDriver -> SNKernelPreFileSystemControl\n"));

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

NTSTATUS SNKernelUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(Flags);

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "(*) SNKernelDriver -> SNKernelUnload\n"));

    SNKernelFreeExtensions();

    FltCloseCommunicationPort(SNKernelData.ServerPort);

    FltUnregisterFilter(SNKernelData.Filter);

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
    UNREFERENCED_PARAMETER(VolumeFilesystemType);

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "(*) SNKernelDriver -> SNKernelInstanceSetup\n"));

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

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "(*) SNKernelDriver -> SNKernelQueryTeardown\n"));

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
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);
    UNREFERENCED_PARAMETER(ConnectionCookie = NULL);

    //
    //  Set the user process and port. In a production filter it may
    //  be necessary to synchronize access to such fields with port
    //  lifetime. For instance, while filter manager will synchronize
    //  FltCloseClientPort with FltSendMessage's reading of the port
    //  handle, synchronizing access to the UserProcess would be up to
    //  the filter.
    //

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "(*) SNKernelDriver -> SNKernelPortConnect\n"));

    FLT_ASSERT(SNKernelData.ClientPort == NULL);
    FLT_ASSERT(SNKernelData.UserProcess == NULL);

    SNKernelData.UserProcess = PsGetCurrentProcess();
    SNKernelData.ClientPort = ClientPort;
    
    return STATUS_SUCCESS;
    
}


VOID
SNKernelPortDisconnect(
    _In_opt_ PVOID ConnectionCookie
) {
    UNREFERENCED_PARAMETER(ConnectionCookie = NULL);

    PAGED_CODE();

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "(*) SNKernelDriver -> SNKernelPortDisconnect\n"));

    FltCloseClientPort(SNKernelData.Filter, &SNKernelData.ClientPort);

    SNKernelData.UserProcess = NULL;
}


VOID
SNKernelFreeExtensions(
) {
    PAGED_CODE();

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "(*) SNKernelDriver -> SNKernelFreeExtensions\n"));

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

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "(*) SNKernelDriver -> SNKernelCheckExtension\n"));

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
    _In_ UNICODE_STRING FileInfo
) {
    
    NTSTATUS status;
    PSN_NOTIFICATION notification = NULL;    


    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "(*) SNKernelDriver -> SNKernelAntivirusScanUM\n"));

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
            FileInfo.Buffer,
            FileInfo.Length / sizeof(WCHAR)
        );

        notification->Length = FileInfo.Length;
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


NTSTATUS
SNKernelInitScannedExtentions(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
) {

    NTSTATUS status;
    HANDLE driverRegKey = NULL;
    UNICODE_STRING valueName;
    PKEY_VALUE_PARTIAL_INFORMATION valueBuffer = NULL;
    ULONG valueLength = 0;
    PWCHAR ch;
    SIZE_T length;
    ULONG count;
    PUNICODE_STRING ext;


    PAGED_CODE();

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "(*) SNKernelDriver -> SNKernelInitScannedExtentions\n"));

    ScannedExtensions = NULL;
    ScannedExtentionsCount = 0;

    status = SNKernelOpenServiceParametersKey(DriverObject,
        RegistryPath,
        &driverRegKey);

    if (!NT_SUCCESS(status)) {

        driverRegKey = NULL;
        goto ScannerInitializeScannedExtensionsCleanup;
    }

    //
    //   Query the length of the reg value
    //

    RtlInitUnicodeString(&valueName, L"Extensions");

    status = ZwQueryValueKey(driverRegKey,
        &valueName,
        KeyValuePartialInformation,
        NULL,
        0,
        &valueLength);

    if (status != STATUS_BUFFER_TOO_SMALL && status != STATUS_BUFFER_OVERFLOW) {

        status = STATUS_INVALID_PARAMETER;
        goto ScannerInitializeScannedExtensionsCleanup;
    }

    //
    //  Extract the path.
    //

    valueBuffer = ExAllocatePoolZero(NonPagedPool,
        valueLength,
        SNK_REG_TAG_DEF);

    if (valueBuffer == NULL) {

        status = STATUS_INSUFFICIENT_RESOURCES;
        goto ScannerInitializeScannedExtensionsCleanup;
    }

    status = ZwQueryValueKey(driverRegKey,
        &valueName,
        KeyValuePartialInformation,
        valueBuffer,
        valueLength,
        &valueLength);

    if (!NT_SUCCESS(status)) {

        goto ScannerInitializeScannedExtensionsCleanup;
    }

    ch = (PWCHAR)(valueBuffer->Data);

    count = 0;

    //
    //  Count how many strings are in the multi string
    //

    while (*ch != '\0') {

        ch = ch + wcslen(ch) + 1;
        count++;
    }

    ScannedExtensions = ExAllocatePoolZero(PagedPool,
        count * sizeof(UNICODE_STRING),
        SNK_STRING_TAG_DEF);

    if (ScannedExtensions == NULL) {
        goto ScannerInitializeScannedExtensionsCleanup;
    }

    ch = (PWCHAR)((PKEY_VALUE_PARTIAL_INFORMATION)valueBuffer->Data);
    ext = ScannedExtensions;

    while (ScannedExtentionsCount < count) {

        length = wcslen(ch) * sizeof(WCHAR);

        ext->MaximumLength = (USHORT)length;

        status = SNKernelAllocateUnicodeString(ext);
        

        if (!NT_SUCCESS(status)) {
            goto ScannerInitializeScannedExtensionsCleanup;
        }

        ext->Length = (USHORT)length;

        RtlCopyMemory(ext->Buffer, ch, length);

        ch = ch + length / sizeof(WCHAR) + 1;

        ScannedExtentionsCount++;

        ext++;

    }

ScannerInitializeScannedExtensionsCleanup:

    //
    //  Note that this function leaks the global buffers.
    //  On failure DriverEntry will clean up the globals
    //  so we don't have to do that here.
    //

    if (valueBuffer != NULL) {

        ExFreePoolWithTag(valueBuffer, SNK_REG_TAG_DEF);
        valueBuffer = NULL;
    }

    if (driverRegKey != NULL) {

        ZwClose(driverRegKey);
    }

    if (!NT_SUCCESS(status)) {        
        SNKernelFreeExtensions();
    }

    return status;
}


NTSTATUS
SNKernelOpenServiceParametersKey(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING ServiceRegistryPath,
    _Out_ PHANDLE ServiceParametersKey
) {
    

    NTSTATUS status;
    PFN_IoOpenDriverRegistryKey pIoOpenDriverRegistryKey;
    UNICODE_STRING Subkey;
    HANDLE ParametersKey = NULL;
    HANDLE ServiceRegKey = NULL;
    OBJECT_ATTRIBUTES Attributes;

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "(*) SNKernelDriver -> SNKernelOpenServiceParametersKey\n"));

    //
    //  Open the parameters key to read values from the INF, using the API to
    //  open the key if possible
    //

    pIoOpenDriverRegistryKey = SNKernelGetIoOpenDriverRegistryKey();

    if (pIoOpenDriverRegistryKey != NULL) {

        //
        //  Open the parameters key using the API
        //

        status = pIoOpenDriverRegistryKey(DriverObject,
            DriverRegKeyParameters,
            KEY_READ,
            0,
            &ParametersKey);

        if (!NT_SUCCESS(status)) {

            goto SNKernelOpenServiceParametersKeyCleanup;
        }

    }
    else {

        //
        //  Open specified service root key
        //

        InitializeObjectAttributes(&Attributes,
            ServiceRegistryPath,
            OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
            NULL,
            NULL);

        status = ZwOpenKey(&ServiceRegKey,
            KEY_READ,
            &Attributes);

        if (!NT_SUCCESS(status)) {

            goto SNKernelOpenServiceParametersKeyCleanup;
        }

        //
        //  Open the parameters key relative to service key path
        //

        RtlInitUnicodeString(&Subkey, L"Parameters");

        InitializeObjectAttributes(&Attributes,
            &Subkey,
            OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
            ServiceRegKey,
            NULL);

        status = ZwOpenKey(&ParametersKey,
            KEY_READ,
            &Attributes);

        if (!NT_SUCCESS(status)) {

            goto SNKernelOpenServiceParametersKeyCleanup;
        }
    }

    //
    //  Return value to caller
    //

    *ServiceParametersKey = ParametersKey;

SNKernelOpenServiceParametersKeyCleanup:

    if (ServiceRegKey != NULL) {

        ZwClose(ServiceRegKey);
    }

    return status;

}


PFN_IoOpenDriverRegistryKey
SNKernelGetIoOpenDriverRegistryKey(
    VOID
) {
    static PFN_IoOpenDriverRegistryKey pIoOpenDriverRegistryKey = NULL;
    UNICODE_STRING FunctionName = { 0 };

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "(*) SNKernelDriver -> SNKernelGetIoOpenDriverRegistryKey\n"));

    if (pIoOpenDriverRegistryKey == NULL) {
        RtlInitUnicodeString(&FunctionName, L"IoOpenDriverRegistryKey");
        pIoOpenDriverRegistryKey = (PFN_IoOpenDriverRegistryKey)MmGetSystemRoutineAddress(&FunctionName);
    }
    return pIoOpenDriverRegistryKey;
}



VOID
SNKernelFreeUnicodeString(
    _Inout_ PUNICODE_STRING String
) {
    PAGED_CODE();

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "(*) SNKernelDriver -> SNKernelFreeUnicodeString\n"));

    if (String->Buffer) {

        ExFreePoolWithTag(String->Buffer,            
        SNK_STRING_TAG_DEF);
        String->Buffer = NULL;
    }

    String->Length = String->MaximumLength = 0;
    String->Buffer = NULL;
}



NTSTATUS
SNKernelAllocateUnicodeString(
    _Inout_ PUNICODE_STRING String
) {
    PAGED_CODE();

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "(*) SNKernelDriver -> SNKernelAllocateUnicodeString\n"));

    String->Buffer = ExAllocatePoolZero(NonPagedPool,
        String->MaximumLength,
        SNK_STRING_TAG_DEF);

    if (String->Buffer == NULL) {

        return STATUS_INSUFFICIENT_RESOURCES;
    }

    String->Length = 0;

    return STATUS_SUCCESS;
}