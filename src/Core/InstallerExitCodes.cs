// SPDX-License-Identifier: MIT
using System.ComponentModel;

namespace WhitehatSecurity.Core;

/// <summary>Windows error codes used by the unattended installer contract.</summary>
public static class InstallerExitCodes
{
    public const int AccessDenied = 5;
    public const int InvalidParameter = 87;
    public const int ElevationRequired = 740;
    public const int Cancelled = 1223;
    public const int Timeout = 1460;
    public const int InstallFailure = 1603;

    public static int FromException(Exception exception) => exception switch
    {
        Win32Exception { NativeErrorCode: > 0 } native => native.NativeErrorCode,
        UnauthorizedAccessException => AccessDenied,
        ArgumentException => InvalidParameter,
        TimeoutException => Timeout,
        _ => InstallFailure,
    };
}
