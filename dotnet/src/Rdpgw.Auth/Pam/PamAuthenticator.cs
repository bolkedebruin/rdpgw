using System.Runtime.InteropServices;

namespace Rdpgw.Auth;

public sealed class PamAuthenticator
{
    private readonly string serviceName;

    public PamAuthenticator(string serviceName)
    {
        this.serviceName = serviceName;
    }

    public (bool Authenticated, string Error) Authenticate(string username, string password)
    {
        if (!OperatingSystem.IsLinux())
        {
            return (false, "PAM authentication is only supported on Linux");
        }

        var conversation = new NativePam.PamConversationCallback((numMsg, msg, out resp, appData) => Conversation(numMsg, msg, out resp, password));
        var conv = new NativePam.PamConv { Conv = conversation, AppDataPtr = IntPtr.Zero };
        var startCode = NativePam.pam_start(serviceName, username, ref conv, out var handle);
        GC.KeepAlive(conversation);
        if (startCode != NativePam.PamSuccess)
        {
            return (false, PamError(handle, startCode));
        }

        try
        {
            var authCode = NativePam.pam_authenticate(handle, 0);
            if (authCode != NativePam.PamSuccess)
            {
                return (false, PamError(handle, authCode));
            }

            var acctCode = NativePam.pam_acct_mgmt(handle, 0);
            if (acctCode != NativePam.PamSuccess)
            {
                return (false, PamError(handle, acctCode));
            }

            return (true, string.Empty);
        }
        finally
        {
            NativePam.pam_end(handle, 0);
            GC.KeepAlive(conversation);
        }
    }

    private static int Conversation(int numMsg, IntPtr msg, out IntPtr resp, string password)
    {
        resp = Marshal.AllocHGlobal(Marshal.SizeOf<NativePam.PamResponse>() * numMsg);
        Span<byte> zero = stackalloc byte[Marshal.SizeOf<NativePam.PamResponse>()];
        for (var i = 0; i < numMsg; i++)
        {
            var msgPtr = Marshal.ReadIntPtr(msg, i * IntPtr.Size);
            var pamMessage = Marshal.PtrToStructure<NativePam.PamMessage>(msgPtr);
            var response = new NativePam.PamResponse { RespRetcode = 0 };
            response.Resp = pamMessage.MsgStyle switch
            {
                NativePam.PamPromptEchoOff => Marshal.StringToHGlobalAnsi(password),
                NativePam.PamPromptEchoOn or NativePam.PamErrorMsg or NativePam.PamTextInfo => IntPtr.Zero,
                _ => IntPtr.Zero
            };
            Marshal.Copy(zero.ToArray(), 0, resp + i * Marshal.SizeOf<NativePam.PamResponse>(), zero.Length);
            Marshal.StructureToPtr(response, resp + i * Marshal.SizeOf<NativePam.PamResponse>(), false);
        }
        return NativePam.PamSuccess;
    }

    private static string PamError(IntPtr handle, int code)
    {
        var ptr = NativePam.pam_strerror(handle, code);
        return Marshal.PtrToStringAnsi(ptr) ?? $"PAM error {code}";
    }
}
