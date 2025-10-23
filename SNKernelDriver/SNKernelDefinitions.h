


#ifndef __SNKERNELDEF_H__
#define __SNKERNELDEF_H__




typedef struct _SNKERNEL_DATA {

    PDRIVER_OBJECT DriverObject;

    PFLT_FILTER Filter;

    PFLT_PORT ServerPort;

    PEPROCESS UserProcess;

    PFLT_PORT ClientPort;

} SNKERNEL_DATA, * PSNKERNEL_DATA;

extern SNKERNEL_DATA SNKernelData;


DRIVER_INITIALIZE DriverEntry;
NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
);

#endif