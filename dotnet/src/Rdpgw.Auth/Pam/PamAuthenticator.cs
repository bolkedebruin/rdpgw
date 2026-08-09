using System.Runtime.InteropServices;

namespace Rdpgw.Auth;

/// <summary>
/// Authenticates username/password credentials against Linux PAM.
/// </summary>
public sealed class PamAuthenticator
{
    private readonly string serviceName;

    /// <summary>
    /// Initializes a new instance of the <see cref="PamAuthenticator"/> class.
    /// </summary>
    /// <param name="serviceName">PAM service name to use for authentication.</param>
    public PamAuthenticator(string serviceName)
    {
        this.serviceName = serviceName;
    }

    /// <summary>
    /// Authenticates a user with PAM and verifies the account is allowed to log in.
    /// </summary>
    /// <param name="username">Username to authenticate.</param>
    /// <param name="password">Password supplied by the client.</param>
    /// <returns>A tuple containing the authentication result and an error message when authentication fails.</returns>
    public (bool Authenticated, string Error) Authenticate(string username, string password)
    {
        if (!OperatingSystem.IsLinux())
        {
            return (false, "PAM authentication is only supported on Linux");
        }

        // Capture the password in the managed callback instead of using appDataPtr
        // so libpam receives a standard pam_conv function with no extra state.
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

            // Account management enforces PAM policies such as expired accounts,
            // access restrictions, and time-based login rules after authentication.
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

    /// <summary>
    /// Handles PAM conversation prompts by returning the supplied password for hidden prompts.
    /// </summary>
    /// <param name="numMsg">Number of messages in the native message array.</param>
    /// <param name="msg">Pointer to an array of native PAM message pointers.</param>
    /// <param name="resp">Receives the allocated native response array.</param>
    /// <param name="password">Password to supply to hidden password prompts.</param>
    /// <returns><see cref="NativePam.PamSuccess"/> when responses were populated.</returns>
    private static int Conversation(int numMsg, IntPtr msg, out IntPtr resp, string password)
    {
        resp = Marshal.AllocHGlobal(Marshal.SizeOf<NativePam.PamResponse>() * numMsg);
        Span<byte> zero = stackalloc byte[Marshal.SizeOf<NativePam.PamResponse>()];
        for (var i = 0; i < numMsg; i++)
        {
            // libpam passes pam_message**; read each pointer before marshalling
            // the pointed-to pam_message structure.
            var msgPtr = Marshal.ReadIntPtr(msg, i * IntPtr.Size);
            var pamMessage = Marshal.PtrToStructure<NativePam.PamMessage>(msgPtr);
            var response = new NativePam.PamResponse { RespRetcode = 0 };
            response.Resp = pamMessage.MsgStyle switch
            {
                NativePam.PamPromptEchoOff => Marshal.StringToHGlobalAnsi(password),
                NativePam.PamPromptEchoOn or NativePam.PamErrorMsg or NativePam.PamTextInfo => IntPtr.Zero,
                _ => IntPtr.Zero
            };
            // Clear the destination slot before StructureToPtr so every field has
            // deterministic native contents matching pam_response layout.
            Marshal.Copy(zero.ToArray(), 0, resp + i * Marshal.SizeOf<NativePam.PamResponse>(), zero.Length);
            Marshal.StructureToPtr(response, resp + i * Marshal.SizeOf<NativePam.PamResponse>(), false);
        }
        return NativePam.PamSuccess;
    }

    /// <summary>
    /// Converts a PAM status code to a readable error string.
    /// </summary>
    /// <param name="handle">PAM transaction handle.</param>
    /// <param name="code">PAM status code.</param>
    /// <returns>The PAM-provided error text, or a fallback string.</returns>
    private static string PamError(IntPtr handle, int code)
    {
        var ptr = NativePam.pam_strerror(handle, code);
        return Marshal.PtrToStringAnsi(ptr) ?? $"PAM error {code}";
    }
}
