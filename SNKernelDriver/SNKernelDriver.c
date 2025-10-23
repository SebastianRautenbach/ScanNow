#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include "SNKernelDefinitions.h"

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")

// global variables
SNKERNEL_DATA SNKernelData;



// alloc code sections for routines 
#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#endif

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT     DriverObject,
    _In_ PUNICODE_STRING    RegistryPath
)
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS status = STATUS_SUCCESS;


    //status = FltCreateCommunicationPort(
    //    NULL,
    //    NULL,
    //    
    //);



    return status;
}