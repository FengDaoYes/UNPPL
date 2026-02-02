#include <ntifs.h>
#include <ntddk.h>
#include <ntstrsafe.h>
#include <ntintsafe.h>

// 设备IO控制码定义
#define IOCTL_UNPPL_SET_PID CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

PSHORT NtBuildNumber = NULL;
#define PROTECTED_PROCESS_MASK	0x00000800
// Windows 版本 Build 号定义
#define KULL_M_WIN_MIN_BUILD_8    8000
#define KULL_M_WIN_MIN_BUILD_BLUE 9400

// 进程签名保护结构
typedef struct _KIWI_PROCESS_SIGNATURE_PROTECTION {
	UCHAR SignatureLevel;
	UCHAR SectionSignatureLevel;
	struct {
		UCHAR Type;
		UCHAR Audit;
		UCHAR Signer;
	} Protection;
} KIWI_PROCESS_SIGNATURE_PROTECTION, * PKIWI_PROCESS_SIGNATURE_PROTECTION;

// 进程保护信息结构
typedef struct _MIMIDRV_PROCESS_PROTECT_INFORMATION {
	ULONG processId;
	KIWI_PROCESS_SIGNATURE_PROTECTION SignatureProtection;
} MIMIDRV_PROCESS_PROTECT_INFORMATION, * PMIMIDRV_PROCESS_PROTECT_INFORMATION;

// 全局变量，存储进程保护信息
MIMIDRV_PROCESS_PROTECT_INFORMATION protectInfos = { 0 };

// Windows 版本信息
DWORD MIMIKATZ_NT_MAJOR_VERSION = 0;
DWORD MIMIKATZ_NT_MINOR_VERSION = 0;
DWORD MIMIKATZ_NT_BUILD_NUMBER = 0;

typedef enum _KIWI_OS_INDEX {
	KiwiOsIndex_UNK = 0,
	KiwiOsIndex_XP = 1,
	KiwiOsIndex_2K3 = 2,
	KiwiOsIndex_VISTA = 3,
	KiwiOsIndex_7 = 4,
	KiwiOsIndex_8 = 5,
	KiwiOsIndex_BLUE = 6,
	KiwiOsIndex_10_1507 = 7,
	KiwiOsIndex_10_1511 = 8,
	KiwiOsIndex_10_1607 = 9,
	KiwiOsIndex_10_1703 = 10,
	KiwiOsIndex_10_1709 = 11,
	KiwiOsIndex_10_1803 = 12,
	KiwiOsIndex_10_1809 = 13,
	KiwiOsIndex_10_1903 = 14,
	KiwiOsIndex_10_1909 = 15,
	KiwiOsIndex_10_2004 = 16,
	KiwiOsIndex_11_21H2 = 17,
	KiwiOsIndex_11_22H2 = 18,
	KiwiOsIndex_11_23H2 = 19,
	KiwiOsIndex_11_24H2_1 = 20,
	KiwiOsIndex_11_24H2_2 = 21,
	KiwiOsIndex_10_2004_2 = 22,
	KiwiOsIndex_MAX = 23,
} KIWI_OS_INDEX, * PKIWI_OS_INDEX;

KIWI_OS_INDEX KiwiOsIndex;

typedef enum _KIWI_PROCESS_INDEX {
	EprocessNext = 0,
	EprocessFlags2 = 1,
	TokenPrivs = 2,
	SignatureProtect = 3,

	Eprocess_MAX = 4,
} KIWI_PROCESS_INDEX, * PKIWI_PROCESS_INDEX;

const ULONG EPROCESS_OffSetTable[KiwiOsIndex_MAX][Eprocess_MAX] =
{					/*  EprocessNext, EprocessFlags2, TokenPrivs, SignatureProtect */
					/*  dt nt!_EPROCESS -n ActiveProcessLinks -n Flags2 -n SignatureLevel */
#if defined(_M_IX86)
	/* UNK	*/	{0},
	/* XP	*/	{0x0088},
	/* 2K3	*/	{0x0098},
	/* VISTA*/	{0x00a0, 0x0224, 0x0040},
	/* 7	*/	{0x00b8, 0x026c, 0x0040},
	/* 8	*/	{0x00b8, 0x00c0, 0x0040, 0x02d4},
	/* BLUE	*/	{0x00b8, 0x00c0, 0x0040, 0x02cc},
	/* 10_1507*/{0x00b8, 0x00c0, 0x0040, 0x02dc},
	/* 10_1511*/{0x00b8, 0x00c0, 0x0040, 0x02dc},
	/* 10_1607*/{0x00b8, 0x00c0, 0x0040, 0x02ec},
	/* 10_1703*/{0x00b8, 0x00c0, 0x0040, 0x02ec},
	/* 10_1709*/{0x00b8, 0x00c0, 0x0040, 0x02ec},
	/* 10_1803*/{0x00b8, 0x00c0, 0x0040, 0x02ec},
	/* 10_1809*/{0x00b8, 0x00c8, 0x0040, 0x02f4},
	/* 10_1903*/{0x00b8, 0x00c8, 0x0040, 0x0364},
	/* 10_1909*/{0x00b8, 0x00c8, 0x0040, 0x0364}, // ?
	/* 10_2004*/{0x00e8, 0x00f8, 0x0040, 0x03a4},
	#else
	/* UNK	*/	{0},
	/* XP	*/	{0},
	/* 2K3	*/	{0x00e0},
	/* VISTA*/	{0x00e8, 0x036c, 0x0040},
	/* 7	*/	{0x0188, 0x043c, 0x0040},
	/* 8	*/	{0x02e8, 0x02f8, 0x0040, 0x0648},
	/* BLUE	*/	{0x02e8, 0x02f8, 0x0040, 0x0678},
	/* 10_1507*/{0x02f0, 0x0300, 0x0040, 0x06a8},
	/* 10_1511*/{0x02f0, 0x0300, 0x0040, 0x06b0},
	/* 10_1607*/{0x02f0, 0x0300, 0x0040, 0x06c8},
	/* 10_1703*/{0x02e8, 0x0300, 0x0040, 0x06c8},
	/* 10_1709*/{0x02e8, 0x0300, 0x0040, 0x06c8},
	/* 10_1803*/{0x02e8, 0x0300, 0x0040, 0x06c8},
	/* 10_1809*/{0x02e8, 0x0300, 0x0040, 0x06c8},
	/* 10_1903*/{0x02f0, 0x0308, 0x0040, 0x06f8},
	/* 10_1909*/{0x02f0, 0x0308, 0x0040, 0x06f8}, // ?
	/* 10_2004*/{0x0448, 0x0460, 0x0040, 0x0878},
	/* 11_21H2*/{0x0448,0x0460,0x0040,0x0878},
	/* 11_22H2*/{0x0448,0x0460,0x0040,0x0878},
	/* 11_23H2*/{0x0448,0x0460,0x0040,0x0878},
	/* 11_24H2_1*/{0x01D8,0x01F0,0x0040,0x05F8},
	/* 11_24H2_1*/{0x01D8,0x01F0,0x0040,0x05F8}, //
	/* 10_2004_2*/{0x0448,0x0460,0x0040,0x0878},
	#endif
};


typedef VOID(NTAPI* PRTLGETNTVERSIONNUMBERS)(
	PULONG MajorVersion,
	PULONG MinorVersion,
	PULONG BuildNumber
	);

KIWI_OS_INDEX getWindowsIndex()
{

	switch (*NtBuildNumber)
	{
	case 2600:
		return KiwiOsIndex_XP;
		break;
	case 3790:
		return KiwiOsIndex_2K3;
		break;
	case 6000:
	case 6001:
	case 6002:
		return KiwiOsIndex_VISTA;
		break;
	case 7600:
	case 7601:
		return KiwiOsIndex_7;
		break;
	case 8102:
	case 8250:
	case 9200:
		return KiwiOsIndex_8;
	case 9431:
	case 9600:
		return KiwiOsIndex_BLUE;
		break;
	case 10240:
		return KiwiOsIndex_10_1507;
		break;
	case 10586:
		return KiwiOsIndex_10_1511;
		break;
	case 14393:
		return KiwiOsIndex_10_1607;
		break;
	case 15063:
		return KiwiOsIndex_10_1703;
		break;
	case 16299:
		return KiwiOsIndex_10_1709;
		break;
	case 17134:
		return KiwiOsIndex_10_1803;
		break;
	case 17763:
		return KiwiOsIndex_10_1809;
		break;
	case 18362:
		return KiwiOsIndex_10_1903;
		break;
	case 18363:
		return KiwiOsIndex_10_1909;
		break;
	case 19041:
		return KiwiOsIndex_10_2004;
		break;
	case 19044:
		return KiwiOsIndex_10_2004_2;
		break;
	case 22000:
		return KiwiOsIndex_11_21H2;
		break;
	case 22621:
		return KiwiOsIndex_11_22H2;
		break;
	case 22631:
		return KiwiOsIndex_11_23H2;
		break;
	case 26100:
		return KiwiOsIndex_11_24H2_1;
		break;
	case 26200:
		return KiwiOsIndex_11_24H2_2;
		break;

	default:
		return KiwiOsIndex_UNK;
	}
}

VOID InitializeNtBuildNumber() {
	UNICODE_STRING routineName;
	RtlInitUnicodeString(&routineName, L"NtBuildNumber");
	NtBuildNumber = (PSHORT)MmGetSystemRoutineAddress(&routineName);
	if (!NtBuildNumber) {
		DbgPrint("Failed to get NtBuildNumber address\n");
	}
}

VOID InitializeProtectInfos()
{
	// 获取 RtlGetNtVersionNumbers 函数地址
	UNICODE_STRING routineName;
	RtlInitUnicodeString(&routineName, L"RtlGetNtVersionNumbers");

	PRTLGETNTVERSIONNUMBERS RtlGetNtVersionNumbers = (PRTLGETNTVERSIONNUMBERS)MmGetSystemRoutineAddress(&routineName);
	if (RtlGetNtVersionNumbers)
	{
		RtlGetNtVersionNumbers(&MIMIKATZ_NT_MAJOR_VERSION, &MIMIKATZ_NT_MINOR_VERSION, &MIMIKATZ_NT_BUILD_NUMBER);
		MIMIKATZ_NT_BUILD_NUMBER &= 0x00007fff;
	}
	// 初始化 protectInfos
	RtlZeroMemory(&protectInfos, sizeof(protectInfos));

	if (MIMIKATZ_NT_BUILD_NUMBER < KULL_M_WIN_MIN_BUILD_8)
	{
		protectInfos.SignatureProtection.SignatureLevel = 1;
	}
	else if (MIMIKATZ_NT_BUILD_NUMBER < KULL_M_WIN_MIN_BUILD_BLUE)
	{
		protectInfos.SignatureProtection.SignatureLevel = 0x0f;
		protectInfos.SignatureProtection.SectionSignatureLevel = 0x0f;
	}
	else
	{
		protectInfos.SignatureProtection.SignatureLevel = 0x3f;
		protectInfos.SignatureProtection.SectionSignatureLevel = 0x3f;

		protectInfos.SignatureProtection.Protection.Type = 2;
		protectInfos.SignatureProtection.Protection.Audit = 0;
		protectInfos.SignatureProtection.Protection.Signer = 6;
	}
	//DbgPrint("Windows Version: %lu.%lu (Build %lu)\n",MIMIKATZ_NT_MAJOR_VERSION, MIMIKATZ_NT_MINOR_VERSION, MIMIKATZ_NT_BUILD_NUMBER);
	//DbgPrint("ProtectInfos Initialized: SignatureLevel=%d\n", protectInfos.SignatureProtection.SignatureLevel);
}

void xzPid(HANDLE pid) {
	KiwiOsIndex = getWindowsIndex();
	NTSTATUS status;
	PEPROCESS pProcess = NULL;
	PULONG pFlags2 = NULL;
	PKIWI_PROCESS_SIGNATURE_PROTECTION pSignatureProtect = NULL;
	PMIMIDRV_PROCESS_PROTECT_INFORMATION pInfos = &protectInfos;
	
	// 使用HandleToULong宏安全地将HANDLE转换为ULONG
	pInfos->processId = HandleToULong(pid);
	
	DbgPrint("[UNPPL] 开始设置进程保护，PID: %lu\n", HandleToULong(pid));
	DbgPrint("[UNPPL-DEBUG] 当前操作系统索引: %d\n", KiwiOsIndex);
	DbgPrint("[UNPPL-DEBUG] 全局保护信息地址: 0x%p\n", pInfos);

	if (KiwiOsIndex >= KiwiOsIndex_VISTA) {
		// 查找进程对象
		status = PsLookupProcessByProcessId((HANDLE)pid, &pProcess);
		if (NT_SUCCESS(status))
		{
			DbgPrint("[UNPPL-DEBUG] 成功获取进程对象，地址: 0x%p\n", pProcess);
			
			// 调试：打印设置的PPL值
			DbgPrint("[UNPPL-DEBUG] 设置前的PPL值 - SignatureLevel: 0x%02x, SectionSignatureLevel: 0x%02x\n", 
					 pInfos->SignatureProtection.SignatureLevel, 
					 pInfos->SignatureProtection.SectionSignatureLevel);
			
			if (KiwiOsIndex > KiwiOsIndex_8)
			{
				DbgPrint("[UNPPL-DEBUG] 完整PPL保护 - Type: %d, Audit: %d, Signer: %d\n",
						 pInfos->SignatureProtection.Protection.Type,
						 pInfos->SignatureProtection.Protection.Audit,
						 pInfos->SignatureProtection.Protection.Signer);
			}
			
			if (KiwiOsIndex < KiwiOsIndex_8)
			{
				// Windows 8之前的版本：设置Flags2标志
				pFlags2 = (PULONG)(((ULONG_PTR)pProcess) + EPROCESS_OffSetTable[KiwiOsIndex][EprocessFlags2]);
				
				DbgPrint("[UNPPL-DEBUG] Flags2地址: 0x%p (进程基址: 0x%p + 偏移: 0x%x)\n", 
						 pFlags2, pProcess, EPROCESS_OffSetTable[KiwiOsIndex][EprocessFlags2]);
				
				// 调试：打印设置前的Flags2值
				DbgPrint("[UNPPL-DEBUG] 设置前的Flags2值: 0x%08x\n", *pFlags2);
				DbgPrint("[UNPPL-DEBUG] 使用的SignatureLevel值: 0x%02x\n", pInfos->SignatureProtection.SignatureLevel);
				DbgPrint("[UNPPL-DEBUG] PROTECTED_PROCESS_MASK: 0x%08x\n", PROTECTED_PROCESS_MASK);
				
				// 记录原始值用于验证
				ULONG originalFlags2 = *pFlags2;
				
				if (pInfos->SignatureProtection.SignatureLevel)
				{
					*pFlags2 |= PROTECTED_PROCESS_MASK;
					DbgPrint("[UNPPL] 已设置进程保护标志 (Windows 8之前版本)\n");
				}
				else
				{
					*pFlags2 &= ~PROTECTED_PROCESS_MASK;
					DbgPrint("[UNPPL] 已清除进程保护标志 (Windows 8之前版本)\n");
				}
				
				// 调试：打印设置后的Flags2值
				DbgPrint("[UNPPL-DEBUG] 设置后的Flags2值: 0x%08x\n", *pFlags2);
				DbgPrint("[UNPPL-DEBUG] 验证设置结果: 0x%08x & 0x%08x = 0x%08x\n", 
						 *pFlags2, PROTECTED_PROCESS_MASK, (*pFlags2 & PROTECTED_PROCESS_MASK));
				DbgPrint("[UNPPL-DEBUG] 修改前后对比: 原始值=0x%08x, 新值=0x%08x\n", 
						 originalFlags2, *pFlags2);
			}
			else
			{
				// Windows 8及以后的版本：设置签名保护信息
				pSignatureProtect = (PKIWI_PROCESS_SIGNATURE_PROTECTION)(((ULONG_PTR)pProcess) + EPROCESS_OffSetTable[KiwiOsIndex][SignatureProtect]);
				
				DbgPrint("[UNPPL-DEBUG] 签名保护结构地址: 0x%p (进程基址: 0x%p + 偏移: 0x%x)\n", 
						 pSignatureProtect, pProcess, EPROCESS_OffSetTable[KiwiOsIndex][SignatureProtect]);
				
				// 调试：打印设置前的签名保护信息
				DbgPrint("[UNPPL-DEBUG] 设置前的签名保护 - SignatureLevel: 0x%02x, SectionSignatureLevel: 0x%02x\n",
						 pSignatureProtect->SignatureLevel, pSignatureProtect->SectionSignatureLevel);
				DbgPrint("[UNPPL-DEBUG] 将要设置的签名保护 - SignatureLevel: 0x%02x, SectionSignatureLevel: 0x%02x\n",
						 pInfos->SignatureProtection.SignatureLevel, pInfos->SignatureProtection.SectionSignatureLevel);
				
				// 记录原始值用于验证
				UCHAR originalSignatureLevel = pSignatureProtect->SignatureLevel;
				UCHAR originalSectionSignatureLevel = pSignatureProtect->SectionSignatureLevel;
				
				pSignatureProtect->SignatureLevel = pInfos->SignatureProtection.SignatureLevel;
				pSignatureProtect->SectionSignatureLevel = pInfos->SignatureProtection.SectionSignatureLevel;
				
				if (KiwiOsIndex > KiwiOsIndex_8)
				{
					// 记录原始完整保护信息
					UCHAR originalType = pSignatureProtect->Protection.Type;
					UCHAR originalAudit = pSignatureProtect->Protection.Audit;
					UCHAR originalSigner = pSignatureProtect->Protection.Signer;
					
					// 调试：打印设置前的完整保护信息
					DbgPrint("[UNPPL-DEBUG] 设置前的完整保护 - Type: %d, Audit: %d, Signer: %d\n",
							 pSignatureProtect->Protection.Type,
							 pSignatureProtect->Protection.Audit,
							 pSignatureProtect->Protection.Signer);
					DbgPrint("[UNPPL-DEBUG] 将要设置的完整保护 - Type: %d, Audit: %d, Signer: %d\n",
							 pInfos->SignatureProtection.Protection.Type,
							 pInfos->SignatureProtection.Protection.Audit,
							 pInfos->SignatureProtection.Protection.Signer);
					
					pSignatureProtect->Protection = pInfos->SignatureProtection.Protection;
					DbgPrint("[UNPPL] 已设置完整签名保护信息 (Windows 8.1及以后版本)\n");
					
					// 调试：打印设置后的完整保护信息
					DbgPrint("[UNPPL-DEBUG] 设置后的完整保护 - Type: %d, Audit: %d, Signer: %d\n",
							 pSignatureProtect->Protection.Type,
							 pSignatureProtect->Protection.Audit,
							 pSignatureProtect->Protection.Signer);
					DbgPrint("[UNPPL-DEBUG] 完整保护修改前后对比 - Type: %d->%d, Audit: %d->%d, Signer: %d->%d\n",
							 originalType, pSignatureProtect->Protection.Type,
							 originalAudit, pSignatureProtect->Protection.Audit,
							 originalSigner, pSignatureProtect->Protection.Signer);
				}
				else
				{
					DbgPrint("[UNPPL] 已设置基本签名保护信息 (Windows 8版本)\n");
				}
				
				// 调试：打印设置后的签名保护信息
				DbgPrint("[UNPPL-DEBUG] 设置后的签名保护 - SignatureLevel: 0x%02x, SectionSignatureLevel: 0x%02x\n",
						 pSignatureProtect->SignatureLevel, pSignatureProtect->SectionSignatureLevel);
				DbgPrint("[UNPPL-DEBUG] 验证设置结果 - 实际值: 0x%02x, 期望值: 0x%02x\n",
						 pSignatureProtect->SignatureLevel, pInfos->SignatureProtection.SignatureLevel);
				DbgPrint("[UNPPL-DEBUG] 签名保护修改前后对比 - SignatureLevel: 0x%02x->0x%02x, SectionSignatureLevel: 0x%02x->0x%02x\n",
						 originalSignatureLevel, pSignatureProtect->SignatureLevel,
						 originalSectionSignatureLevel, pSignatureProtect->SectionSignatureLevel);
				
				// 验证保护是否真正生效：尝试重新读取保护信息
				PKIWI_PROCESS_SIGNATURE_PROTECTION pVerifyProtect = 
					(PKIWI_PROCESS_SIGNATURE_PROTECTION)(((ULONG_PTR)pProcess) + EPROCESS_OffSetTable[KiwiOsIndex][SignatureProtect]);
				DbgPrint("[UNPPL-DEBUG] 验证读取 - SignatureLevel: 0x%02x, SectionSignatureLevel: 0x%02x\n",
						 pVerifyProtect->SignatureLevel, pVerifyProtect->SectionSignatureLevel);
			}
			
			// 释放进程对象引用
			ObDereferenceObject(pProcess);
			DbgPrint("[UNPPL] 进程保护设置成功，PID: %lu\n", HandleToULong(pid));
		}
		else
			{
			DbgPrint("[UNPPL] PsLookupProcessByProcessId失败，状态码: 0x%08X\n", status);
		}
	}
	else
	{
		DbgPrint("[UNPPL] 不支持的操作系统版本\n");
	}
}

// 设备IO控制处理函数
NTSTATUS UnpplDispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	NTSTATUS status = STATUS_SUCCESS;
	ULONG bytesReturned = 0;
	PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(Irp);
	ULONG ioControlCode = irpStack->Parameters.DeviceIoControl.IoControlCode;

	switch (ioControlCode) {
	case IOCTL_UNPPL_SET_PID:
	{
		// 获取输入缓冲区
		ULONG inputBufferLength = irpStack->Parameters.DeviceIoControl.InputBufferLength;
		if (inputBufferLength >= sizeof(ULONG)) {
			ULONG pid = *(PULONG)Irp->AssociatedIrp.SystemBuffer;
			//DbgPrint("[UNPPL] Received PID: %lu\n", pid);
			
			// 调用xzPid函数处理PID
			xzPid((HANDLE)pid);
			
			bytesReturned = sizeof(ULONG);
		}
		else {
			status = STATUS_INVALID_PARAMETER;
		}
		break;
	}
	default:
		status = STATUS_INVALID_DEVICE_REQUEST;
		break;
	}

	// 完成IRP
	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = bytesReturned;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return status;
}

// 设备创建/关闭处理函数
NTSTATUS UnpplDispatchCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);
	// 简单地完成IRP
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

// 驱动卸载函数
VOID DriverUnload(PDRIVER_OBJECT driver)
{
	UNREFERENCED_PARAMETER(driver);
	UNICODE_STRING symbolicLinkName;

	DbgPrint("[UNPPL] DriverUnload called, starting cleanup...\n");

	// 删除符号链接
	RtlInitUnicodeString(&symbolicLinkName, L"\\DosDevices\\UNPPL");
	NTSTATUS status = IoDeleteSymbolicLink(&symbolicLinkName);
	if (NT_SUCCESS(status)) {
		DbgPrint("[UNPPL] Symbolic link deleted successfully\n");
	}
	else {
		DbgPrint("[UNPPL] Failed to delete symbolic link, status: 0x%08X\n", status);
	}

	// 删除设备对象
	if (driver->DeviceObject) {
		IoDeleteDevice(driver->DeviceObject);
		DbgPrint("[UNPPL] Device object deleted successfully\n");
	}

	DbgPrint("[UNPPL] Driver unload completed\n");
}

// DriverEntry，入口函数。相当于main。
NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING reg_path)
{
	UNREFERENCED_PARAMETER(reg_path);
	NTSTATUS status;
	PDEVICE_OBJECT deviceObject = NULL;
	UNICODE_STRING deviceName;
	UNICODE_STRING symbolicLinkName;

#if DBG
	//       _asm int 3
#endif
	InitializeNtBuildNumber();
	InitializeProtectInfos();

	// 创建设备对象
	RtlInitUnicodeString(&deviceName, L"\\Device\\UNPPL");
	status = IoCreateDevice(
		driver,
		0,                      // DeviceExtensionSize
		&deviceName,            // DeviceName
		FILE_DEVICE_UNKNOWN,    // DeviceType
		FILE_DEVICE_SECURE_OPEN,// DeviceCharacteristics
		FALSE,                  // Exclusive
		&deviceObject           // DeviceObject
	);

	if (!NT_SUCCESS(status)) {
		DbgPrint("[UNPPL] Failed to create device object, status: 0x%08X\n", status);
		return status;
	}

	// 创建符号链接
	RtlInitUnicodeString(&symbolicLinkName, L"\\DosDevices\\UNPPL");
	status = IoCreateSymbolicLink(&symbolicLinkName, &deviceName);

	if (!NT_SUCCESS(status)) {
		DbgPrint("[UNPPL] Failed to create symbolic link, status: 0x%08X\n", status);
		IoDeleteDevice(deviceObject);
		return status;
	}

	// 注册分发例程
	for (int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {
		driver->MajorFunction[i] = UnpplDispatchCreateClose;
	}

	
	// 注册特定的分发例程
	driver->MajorFunction[IRP_MJ_CREATE] = UnpplDispatchCreateClose;
	driver->MajorFunction[IRP_MJ_CLOSE] = UnpplDispatchCreateClose;
	driver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = UnpplDispatchDeviceControl;

	driver->DriverUnload = DriverUnload;
	
	
	return STATUS_SUCCESS;
}

