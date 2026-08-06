using System.Runtime.InteropServices;

namespace Rdpgw.Auth;

internal static class NativeUnix
{
    [DllImport("libc", SetLastError = true, EntryPoint = "chmod")]
    internal static extern int chmod([MarshalAs(UnmanagedType.LPUTF8Str)] string pathname, uint mode);

    [DllImport("libc", SetLastError = true, EntryPoint = "umask")]
    internal static extern uint umask(uint mask);
}
