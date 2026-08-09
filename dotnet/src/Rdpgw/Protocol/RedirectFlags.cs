namespace Rdpgw.Protocol;

/// <summary>
/// Configures which client device redirection channels are allowed in tunnel authorization responses.
/// </summary>
public sealed class RedirectFlags
{
    /// <summary>Allow clipboard redirection when true; otherwise emit the disable-clipboard bit.</summary>
    public bool Clipboard;
    /// <summary>Allow serial or parallel port redirection when true.</summary>
    public bool Port;
    /// <summary>Allow drive redirection when true.</summary>
    public bool Drive;
    /// <summary>Allow printer redirection when true.</summary>
    public bool Printer;
    /// <summary>Allow Plug and Play device redirection when true.</summary>
    public bool Pnp;
    /// <summary>Force all redirection channels off regardless of individual flags.</summary>
    public bool DisableAll;
    /// <summary>Force all redirection channels on regardless of individual flags.</summary>
    public bool EnableAll;
}
