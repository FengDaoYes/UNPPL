#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <string.h>

#pragma comment(lib, "advapi32.lib")

// 驱动程序相关常量定义
#define DRIVER_NAME "UNPPL"
#define DRIVER_DISPLAY_NAME "UNPPL Service"
#define DRIVER_PATH "UNPPL.sys"
#define DRIVER_DEVICE_NAME "\\\\.\\UNPPL"

// 设备IO控制代码定义
#define IOCTL_UNPPL_SET_PID CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

// 错误代码定义
#define SETPPL_ERROR_SUCCESS 0
#define SETPPL_ERROR_DRIVER_NOT_FOUND 1
#define SETPPL_ERROR_SERVICE_CREATE_FAILED 2
#define SETPPL_ERROR_SERVICE_START_FAILED 3
#define SETPPL_ERROR_PID_NOT_FOUND 4
#define SETPPL_ERROR_DEVICE_OPEN_FAILED 5
#define SETPPL_ERROR_DEVICE_IO_FAILED 6
#define SETPPL_ERROR_INVALID_PARAMETER 7

// 全局变量
int g_bQuietMode = 0; // 静默模式标志

/**
 * @brief 设置控制台编码为GBK
 * @return 设置是否成功
 */
int SetConsoleToGBK() {
    // 设置控制台输出编码为GBK
    SetConsoleOutputCP(936);
    // 设置控制台输入编码为GBK
    SetConsoleCP(936);
    
    return 1;
}

/**
 * @brief 打印消息（考虑静默模式）
 * @param message 要打印的消息
 */
void PrintMessage(const char* message) {
    if (!g_bQuietMode) {
        printf("%s\n", message);
    }
}

/**
 * @brief 检查驱动程序状态
 * @return 驱动程序状态：0-未安装、1-已安装未运行、2-正在运行
 */
int CheckDriverStatus() {
    SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCManager) {
        return 0; // 无法打开服务管理器，假设驱动程序未安装
    }

    SC_HANDLE hService = OpenServiceA(hSCManager, DRIVER_NAME, SERVICE_QUERY_STATUS);
    if (!hService) {
        CloseServiceHandle(hSCManager);
        return 0; // 服务不存在
    }

    SERVICE_STATUS serviceStatus;
    if (!QueryServiceStatus(hService, &serviceStatus)) {
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCManager);
        return 0; // 查询状态失败
    }

    int status = 0;
    switch (serviceStatus.dwCurrentState) {
    case SERVICE_RUNNING:
        status = 2;
        break;
    case SERVICE_STOPPED:
        status = 1;
        break;
    default:
        status = 0;
        break;
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
    return status;
}

/**
 * @brief 安装并启动驱动程序
 * @param driverPath 驱动程序文件路径
 * @return 错误代码
 */
int InstallAndStartDriver(const char* driverPath) {
    SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hSCManager) {
        char errorMsg[256];
        sprintf_s(errorMsg, sizeof(errorMsg), "[-] 无法打开服务管理器，错误代码: %lu", GetLastError());
        PrintMessage(errorMsg);
        return SETPPL_ERROR_SERVICE_CREATE_FAILED;
    }

    // 创建服务
    SC_HANDLE hService = CreateServiceA(
        hSCManager,
        DRIVER_NAME,
        DRIVER_DISPLAY_NAME,
        SERVICE_ALL_ACCESS,
        SERVICE_KERNEL_DRIVER,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_NORMAL,
        driverPath,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL
    );

    DWORD lastError = GetLastError();
    if (!hService) {
        if (lastError == ERROR_SERVICE_EXISTS) {
            // 服务已存在，打开现有服务
            hService = OpenServiceA(hSCManager, DRIVER_NAME, SERVICE_ALL_ACCESS);
            if (!hService) {
                char errorMsg[256];
                sprintf_s(errorMsg, sizeof(errorMsg), "[-] 服务存在但无法打开，错误代码: %lu", GetLastError());
                PrintMessage(errorMsg);
                CloseServiceHandle(hSCManager);
                return SETPPL_ERROR_SERVICE_CREATE_FAILED;
            }
        }
        else {
            char errorMsg[256];
            sprintf_s(errorMsg, sizeof(errorMsg), "[-] 创建服务失败，错误代码: %lu", lastError);
            PrintMessage(errorMsg);
            CloseServiceHandle(hSCManager);
            return SETPPL_ERROR_SERVICE_CREATE_FAILED;
        }
    }

    // 启动服务
    if (!StartService(hService, 0, NULL)) {
        lastError = GetLastError();
        if (lastError != ERROR_SERVICE_ALREADY_RUNNING) {
            char errorMsg[256];
            sprintf_s(errorMsg, sizeof(errorMsg), "[-] 启动服务失败，错误代码: %lu", lastError);
            PrintMessage(errorMsg);
            CloseServiceHandle(hService);
            CloseServiceHandle(hSCManager);
            return SETPPL_ERROR_SERVICE_START_FAILED;
        }
    }

    PrintMessage("[+] 驱动程序安装并启动成功");
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
    return SETPPL_ERROR_SUCCESS;
}

/**
 * @brief 停止并移除驱动程序
 */
void StopAndRemoveDriver() {
    SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hSCManager) {
        return;
    }

    SC_HANDLE hService = OpenServiceA(hSCManager, DRIVER_NAME, SERVICE_ALL_ACCESS);
    if (!hService) {
        CloseServiceHandle(hSCManager);
        return;
    }

    // 停止服务
    SERVICE_STATUS serviceStatus;
    ControlService(hService, SERVICE_CONTROL_STOP, &serviceStatus);

    // 删除服务
    DeleteService(hService);

    PrintMessage("[+] 驱动程序已停止并移除");
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
}

/**
 * @brief 发送PID到驱动程序
 * @param pid 进程ID
 * @return 是否成功
 */
int SendPidToDriver(DWORD pid) {
    // 打开设备
    HANDLE hDevice = CreateFileA(
        DRIVER_DEVICE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hDevice == INVALID_HANDLE_VALUE) {
        char errorMsg[256];
        sprintf_s(errorMsg, sizeof(errorMsg), "[-] 无法打开设备，错误代码: %lu", GetLastError());
        PrintMessage(errorMsg);
        return 0;
    }

    // 发送PID到驱动程序
    DWORD bytesReturned;
    BOOL result = DeviceIoControl(
        hDevice,
        IOCTL_UNPPL_SET_PID,
        &pid,           // 输入缓冲区
        sizeof(pid),    // 输入缓冲区大小
        NULL,           // 输出缓冲区
        0,              // 输出缓冲区大小
        &bytesReturned, // 返回字节数
        NULL            // 重叠
    );

    if (!result) {
        char errorMsg[256];
        sprintf_s(errorMsg, sizeof(errorMsg), "[-] 设备IO操作失败，错误代码: %lu", GetLastError());
        PrintMessage(errorMsg);
        CloseHandle(hDevice);
        return 0;
    }

    char successMsg[256];
    sprintf_s(successMsg, sizeof(successMsg), "[+] 成功发送PID到驱动程序: %lu", pid);
    PrintMessage(successMsg);
    CloseHandle(hDevice);
    return 1;
}



/**
 * @brief 检查文件是否存在
 * @param filename 文件名
 * @return 文件是否存在
 */
int FileExists(const char* filename) {
    WIN32_FIND_DATAA findFileData;
    HANDLE hFind = FindFirstFileA(filename, &findFileData);
    if (hFind != INVALID_HANDLE_VALUE) {
        FindClose(hFind);
        return 1;
    }
    return 0;
}

/**
 * @brief 显示帮助信息
 */
void ShowHelp() {
    printf("UNPPLControl - UNPPL保护工具\n");
    printf("使用方法:\n");
    printf("  UNPPLControl.exe status              - 检查驱动程序状态\n");
    printf("  UNPPLControl.exe install             - 安装并启动驱动程序\n");
    printf("  UNPPLControl.exe uninstall           - 卸载驱动程序\n");
    printf("  UNPPLControl.exe use <PID>           - 为指定进程设置UNPPL保护\n");
    printf("  UNPPLControl.exe auto <PID>          - 自动安装并设置指定PID\n");
    printf("  UNPPLControl.exe -q <command>        - 静默模式执行命令\n");
    printf("\n");
    printf("示例:\n");
    printf("  UNPPLControl.exe status\n");
    printf("  UNPPLControl.exe use 1234\n");
    printf("  UNPPLControl.exe auto 5678\n");
    printf("  UNPPLControl.exe -q use 1234\n");
}

/**
 * @brief 处理状态检查命令
 * @return 退出代码
 */
int HandleStatusCommand() {
    int status = CheckDriverStatus();
    
    switch (status) {
    case 0:
        PrintMessage("[状态] 驱动程序未安装");
        break;
    case 1:
        PrintMessage("[状态] 驱动程序已安装但未运行");
        break;
    case 2:
        PrintMessage("[状态] 驱动程序正在运行");
        break;
    default:
        PrintMessage("[状态] 未知状态");
        break;
    }
    
    return SETPPL_ERROR_SUCCESS;
}

/**
 * @brief 处理安装命令
 * @return 退出代码
 */
int HandleInstallCommand() {
    // 获取当前目录
    char currentDir[MAX_PATH];
    GetCurrentDirectoryA(MAX_PATH, currentDir);
    
    // 构建驱动程序完整路径
    char driverFullPath[MAX_PATH];
    sprintf_s(driverFullPath, sizeof(driverFullPath), "%s\\%s", currentDir, DRIVER_PATH);
    
    // 检查驱动程序文件是否存在
    if (!FileExists(driverFullPath)) {
        char errorMsg[512];
        sprintf_s(errorMsg, sizeof(errorMsg), "[-] 驱动程序文件不存在: %s", driverFullPath);
        PrintMessage(errorMsg);
        return SETPPL_ERROR_DRIVER_NOT_FOUND;
    }
    
    char pathMsg[512];
    sprintf_s(pathMsg, sizeof(pathMsg), "[+] 驱动程序路径: %s", driverFullPath);
    PrintMessage(pathMsg);
    
    // 安装并启动驱动程序
    int result = InstallAndStartDriver(driverFullPath);
    if (result != SETPPL_ERROR_SUCCESS) {
        char errorMsg[256];
        sprintf_s(errorMsg, sizeof(errorMsg), "[-] 驱动程序安装失败，错误代码: %d", result);
        PrintMessage(errorMsg);
        return result;
    }
    
    PrintMessage("[+] 驱动程序安装成功");
    return SETPPL_ERROR_SUCCESS;
}

/**
 * @brief 处理卸载命令
 * @return 退出代码
 */
int HandleUninstallCommand() {
    StopAndRemoveDriver();
    return SETPPL_ERROR_SUCCESS;
}

/**
 * @brief 处理使用命令
 * @param pidStr PID字符串
 * @return 退出代码
 */
int HandleUseCommand(const char* pidStr) {
    // 检查驱动程序状态
    int status = CheckDriverStatus();
    if (status != 2) {
        PrintMessage("[-] 驱动程序未运行，请先安装并启动驱动程序");
        return SETPPL_ERROR_SERVICE_START_FAILED;
    }
    
    // 解析PID
    DWORD pid = atoi(pidStr);
    if (pid == 0) {
        PrintMessage("[-] 无效的PID格式");
        return SETPPL_ERROR_INVALID_PARAMETER;
    }
    
    // 注意：对于高权限进程（如PPL进程），无法通过常规方式检测存在性
    // 直接发送PID到驱动程序，由驱动程序处理不存在的PID情况
    char successMsg[256];
    sprintf_s(successMsg, sizeof(successMsg), "[+] 目标进程PID: %lu", pid);
    PrintMessage(successMsg);
    
    // 等待进程稳定
    Sleep(1000);
    
    // 发送PID到驱动程序
    if (!SendPidToDriver(pid)) {
        PrintMessage("[-] 发送PID到驱动程序失败");
        return SETPPL_ERROR_DEVICE_IO_FAILED;
    }
    
    PrintMessage("[+] 成功为进程取消PPL保护");
    return SETPPL_ERROR_SUCCESS;
}

/**
 * @brief 处理自动命令
 * @param pidStr PID字符串
 * @return 退出代码
 */
int HandleAutoCommand(const char* pidStr) {
    // 检查驱动程序状态
    int status = CheckDriverStatus();
    
    if (status == 0) {
        // 驱动程序未安装，先安装
        PrintMessage("[+] 驱动程序未安装，正在安装...");
        int installResult = HandleInstallCommand();
        if (installResult != SETPPL_ERROR_SUCCESS) {
            return installResult;
        }
    } else if (status == 1) {
        // 驱动程序已安装但未运行，启动
        PrintMessage("[+] 驱动程序已安装但未运行，正在启动...");
        int installResult = HandleInstallCommand();
        if (installResult != SETPPL_ERROR_SUCCESS) {
            return installResult;
        }
    }
    
    // 使用PID设置保护
    return HandleUseCommand(pidStr);
}

/**
 * @brief 主函数
 */
int main(int argc, char* argv[]) {
    // 设置控制台编码
    SetConsoleToGBK();
    
    // 检查参数数量
    if (argc < 2) {
        ShowHelp();
        return SETPPL_ERROR_INVALID_PARAMETER;
    }
    
    // 处理静默模式
    char* command = argv[1];
    if (strcmp(command, "-q") == 0) {
        g_bQuietMode = 1;
        if (argc < 3) {
            return SETPPL_ERROR_INVALID_PARAMETER;
        }
        command = argv[2];
    }
    
    // 处理不同命令
    if (strcmp(command, "status") == 0) {
        return HandleStatusCommand();
    }
    else if (strcmp(command, "install") == 0) {
        return HandleInstallCommand();
    }
    else if (strcmp(command, "uninstall") == 0) {
        return HandleUninstallCommand();
    }
    else if (strcmp(command, "use") == 0) {
        if (argc < 3) {
            PrintMessage("[-] 缺少PID参数");
            ShowHelp();
            return SETPPL_ERROR_INVALID_PARAMETER;
        }
        return HandleUseCommand(argv[2]);
    }
    else if (strcmp(command, "auto") == 0) {
        if (argc < 3) {
            PrintMessage("[-] 缺少PID参数");
            ShowHelp();
            return SETPPL_ERROR_INVALID_PARAMETER;
        }
        return HandleAutoCommand(argv[2]);
    }
    else {
        ShowHelp();
        return SETPPL_ERROR_INVALID_PARAMETER;
    }
    
    return SETPPL_ERROR_SUCCESS;
}
