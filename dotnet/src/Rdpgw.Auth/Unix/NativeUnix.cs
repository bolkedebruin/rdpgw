using System.Runtime.InteropServices;

namespace Rdpgw.Auth;

/// <summary>
/// Native Unix file-permission helpers used to prepare the authentication socket.
/// </summary>
internal static class NativeUnix
{
    /// <summary>
    /// Changes the mode bits of a filesystem path.
    /// </summary>
    /// <param name="pathname">Path whose permissions should be changed.</param>
    /// <param name="mode">Unix permission bits to apply.</param>
    /// <returns>Zero on success, or -1 when libc sets errno.</returns>
    [DllImport("libc", SetLastError = true, EntryPoint = "chmod")]
    internal static extern int chmod([MarshalAs(UnmanagedType.LPUTF8Str)] string pathname, uint mode);

    /// <summary>
    /// Sets the process file creation mask.
    /// </summary>
    /// <param name="mask">New umask value.</param>
    /// <returns>The previous umask value.</returns>
    [DllImport("libc", SetLastError = true, EntryPoint = "umask")]
    internal static extern uint umask(uint mask);
}
