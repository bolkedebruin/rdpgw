using System.Runtime.InteropServices;

namespace Rdpgw.Auth.Pam;

internal static partial class NativePam
{
    internal const int PamSuccess = 0;
    internal const int PamPromptEchoOff = 1;
    internal const int PamPromptEchoOn = 2;
    internal const int PamErrorMsg = 3;
    internal const int PamTextInfo = 4;

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate int PamConversationCallback(int numMsg, IntPtr msg, out IntPtr resp, IntPtr appDataPtr);

    [StructLayout(LayoutKind.Sequential)]
    internal struct PamMessage
    {
        public int MsgStyle;
        public IntPtr Msg;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PamResponse
    {
        public IntPtr Resp;
        public int RespRetcode;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PamConv
    {
        public PamConversationCallback Conv;
        public IntPtr AppDataPtr;
    }

    [LibraryImport("libpam.so.0", StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int pam_start(string serviceName, string user, ref PamConv pamConv, out IntPtr pamh);

    [LibraryImport("libpam.so.0")]
    internal static partial int pam_authenticate(IntPtr pamh, int flags);

    [LibraryImport("libpam.so.0")]
    internal static partial int pam_acct_mgmt(IntPtr pamh, int flags);

    [LibraryImport("libpam.so.0")]
    internal static partial int pam_end(IntPtr pamh, int pamStatus);

    [LibraryImport("libpam.so.0")]
    internal static partial IntPtr pam_strerror(IntPtr pamh, int errnum);
}
