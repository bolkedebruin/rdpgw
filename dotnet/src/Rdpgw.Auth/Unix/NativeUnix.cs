using System.Runtime.InteropServices;

namespace Rdpgw.Auth.Unix;

internal static partial class NativeUnix
{
    [LibraryImport("libc", SetLastError = true)]
    internal static partial int chmod([MarshalAs(UnmanagedType.LPUTF8Str)] string pathname, uint mode);

    [LibraryImport("libc", SetLastError = true)]
    internal static partial uint umask(uint mask);
}
