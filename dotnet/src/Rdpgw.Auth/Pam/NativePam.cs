using System.Runtime.InteropServices;

namespace Rdpgw.Auth;

/// <summary>
/// Native bindings and data structures for Linux PAM authentication.
/// </summary>
/// <remarks>
/// The structure layouts mirror libpam's C ABI and are used only by
/// <see cref="PamAuthenticator"/> on Linux.
/// </remarks>
internal static class NativePam
{
    /// <summary>
    /// PAM return code indicating success.
    /// </summary>
    internal const int PamSuccess = 0;

    /// <summary>
    /// Conversation message style requesting hidden input such as a password.
    /// </summary>
    internal const int PamPromptEchoOff = 1;

    /// <summary>
    /// Conversation message style requesting visible input.
    /// </summary>
    internal const int PamPromptEchoOn = 2;

    /// <summary>
    /// Conversation message style carrying an error message.
    /// </summary>
    internal const int PamErrorMsg = 3;

    /// <summary>
    /// Conversation message style carrying informational text.
    /// </summary>
    internal const int PamTextInfo = 4;

    /// <summary>
    /// Managed delegate shape for the pam_conv callback invoked by libpam.
    /// </summary>
    /// <param name="numMsg">Number of PAM messages supplied by the module.</param>
    /// <param name="msg">Pointer to an array of PAM message pointers.</param>
    /// <param name="resp">Receives a pointer to an allocated array of PAM responses.</param>
    /// <param name="appDataPtr">Application data pointer supplied in the conversation structure.</param>
    /// <returns>A PAM status code.</returns>
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate int PamConversationCallback(int numMsg, IntPtr msg, out IntPtr resp, IntPtr appDataPtr);

    /// <summary>
    /// Native pam_message structure passed to the conversation callback.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct PamMessage
    {
        /// <summary>
        /// Gets or sets the PAM message style.
        /// </summary>
        public int MsgStyle;

        /// <summary>
        /// Gets or sets a native pointer to the message text.
        /// </summary>
        public IntPtr Msg;
    }

    /// <summary>
    /// Native pam_response structure returned from the conversation callback.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct PamResponse
    {
        /// <summary>
        /// Gets or sets a native pointer to the response string.
        /// </summary>
        public IntPtr Resp;

        /// <summary>
        /// Gets or sets the PAM response return code.
        /// </summary>
        public int RespRetcode;
    }

    /// <summary>
    /// Native pam_conv structure that registers the conversation callback.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct PamConv
    {
        /// <summary>
        /// Gets or sets the callback invoked by PAM modules for prompts.
        /// </summary>
        public PamConversationCallback Conv;

        /// <summary>
        /// Gets or sets the opaque application data pointer passed to the callback.
        /// </summary>
        public IntPtr AppDataPtr;
    }

    /// <summary>
    /// Starts a PAM transaction for a service and user.
    /// </summary>
    /// <param name="serviceName">PAM service name.</param>
    /// <param name="user">Username to authenticate.</param>
    /// <param name="pamConv">Conversation callback descriptor.</param>
    /// <param name="pamh">Receives the PAM transaction handle.</param>
    /// <returns>A PAM status code.</returns>
    [DllImport("libpam.so.0", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    internal static extern int pam_start(string serviceName, string user, ref PamConv pamConv, out IntPtr pamh);

    /// <summary>
    /// Authenticates the user associated with a PAM transaction.
    /// </summary>
    /// <param name="pamh">PAM transaction handle.</param>
    /// <param name="flags">PAM authentication flags.</param>
    /// <returns>A PAM status code.</returns>
    [DllImport("libpam.so.0", CallingConvention = CallingConvention.Cdecl)]
    internal static extern int pam_authenticate(IntPtr pamh, int flags);

    /// <summary>
    /// Performs PAM account management checks after successful authentication.
    /// </summary>
    /// <param name="pamh">PAM transaction handle.</param>
    /// <param name="flags">PAM account-management flags.</param>
    /// <returns>A PAM status code.</returns>
    [DllImport("libpam.so.0", CallingConvention = CallingConvention.Cdecl)]
    internal static extern int pam_acct_mgmt(IntPtr pamh, int flags);

    /// <summary>
    /// Ends a PAM transaction and releases native PAM resources.
    /// </summary>
    /// <param name="pamh">PAM transaction handle.</param>
    /// <param name="pamStatus">Final PAM status to pass to libpam.</param>
    /// <returns>A PAM status code.</returns>
    [DllImport("libpam.so.0", CallingConvention = CallingConvention.Cdecl)]
    internal static extern int pam_end(IntPtr pamh, int pamStatus);

    /// <summary>
    /// Gets the native text description for a PAM status code.
    /// </summary>
    /// <param name="pamh">PAM transaction handle.</param>
    /// <param name="errnum">PAM status code.</param>
    /// <returns>A pointer to a null-terminated ANSI error string owned by libpam.</returns>
    [DllImport("libpam.so.0", CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr pam_strerror(IntPtr pamh, int errnum);
}
