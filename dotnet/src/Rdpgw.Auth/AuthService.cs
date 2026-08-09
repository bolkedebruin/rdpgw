using Grpc.Core;
using Rdpgw.Auth.Database;
using Rdpgw.Auth.Ntlm;
using ProtoAuth = Rdpgw.Shared.Auth;

namespace Rdpgw.Auth;

/// <summary>
/// Implements the gRPC authentication sidecar endpoints used by the gateway.
/// </summary>
/// <remarks>
/// Password authentication is attempted through PAM first and then through the
/// local configuration database. NTLM authentication is delegated to
/// <see cref="NtlmAuth"/>, which maintains the per-session NTLM challenge state.
/// </remarks>
public sealed class AuthService : ProtoAuth.Authenticate.AuthenticateBase
{
    private readonly PamAuthenticator pamAuthenticator;
    private readonly IUserDatabase database;
    private readonly NtlmAuth ntlm;
    private readonly ILogger<AuthService> logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="AuthService"/> class.
    /// </summary>
    /// <param name="pamAuthenticator">PAM authenticator used for system-account password checks.</param>
    /// <param name="database">Local configured-user database used as a fallback and for NTLM secrets.</param>
    /// <param name="ntlm">NTLM authenticator that processes NTLMSSP negotiate and authenticate messages.</param>
    /// <param name="logger">Logger for authentication success and failure events.</param>
    public AuthService(PamAuthenticator pamAuthenticator, IUserDatabase database, NtlmAuth ntlm, ILogger<AuthService> logger)
    {
        this.pamAuthenticator = pamAuthenticator;
        this.database = database;
        this.ntlm = ntlm;
        this.logger = logger;
    }

    /// <summary>
    /// Authenticates a username and password through PAM or the local configuration file.
    /// </summary>
    /// <param name="request">gRPC request containing the username and password.</param>
    /// <param name="context">Server call context supplied by gRPC.</param>
    /// <returns>An authentication response indicating success or the failure reason.</returns>
    public override Task<ProtoAuth.AuthResponse> Authenticate(ProtoAuth.UserPass request, ServerCallContext context)
    {
        var response = new ProtoAuth.AuthResponse { Authenticated = false };
        var (authenticated, error) = pamAuthenticator.Authenticate(request.Username, request.Password);
        if (authenticated)
        {
            logger.LogInformation("User: {User} authenticated", request.Username);
            response.Authenticated = true;
            return Task.FromResult(response);
        }

        // Config-file passwords are checked only after PAM so local system accounts
        // keep their normal authentication policy precedence.
        var configuredPassword = database.GetPassword(request.Username);
        if (!string.IsNullOrEmpty(configuredPassword) && configuredPassword == request.Password)
        {
            logger.LogInformation("User: {User} authenticated using local config", request.Username);
            response.Authenticated = true;
            return Task.FromResult(response);
        }

        logger.LogInformation("Authentication for user: {User} failed due to: {Error}", request.Username, error);
        response.Error = error;
        return Task.FromResult(response);
    }

    /// <summary>
    /// Processes one step of the stateful NTLMSSP authentication exchange.
    /// </summary>
    /// <param name="request">gRPC request containing the session id and base64 NTLMSSP message.</param>
    /// <param name="context">Server call context supplied by gRPC.</param>
    /// <returns>An NTLM response containing a challenge message or final authentication result.</returns>
    public override Task<ProtoAuth.NtlmResponse> NTLM(ProtoAuth.NtlmRequest request, ServerCallContext context)
    {
        try
        {
            var response = ntlm.Authenticate(request);
            if (response.Authenticated)
            {
                logger.LogInformation("[{Session}] User: {User} authenticated using NTLM", request.Session, response.Username);
            }
            else if (!string.IsNullOrEmpty(response.NtlmMessage))
            {
                logger.LogInformation("[{Session}] Sending NTLM challenge", request.Session);
            }
            return Task.FromResult(response);
        }
        catch (Exception ex)
        {
            logger.LogInformation(ex, "[{Session}] NTLM failed: {Message}", request.Session, ex.Message);
            throw new RpcException(new Status(StatusCode.InvalidArgument, ex.Message));
        }
    }
}
