using Grpc.Core;
using Rdpgw.Auth.Database;
using Rdpgw.Auth.Ntlm;
using Rdpgw.Auth.Pam;
using ProtoAuth = Rdpgw.Shared.Auth;

namespace Rdpgw.Auth;

public sealed class AuthService : ProtoAuth.Authenticate.AuthenticateBase
{
    private readonly PamAuthenticator pamAuthenticator;
    private readonly IUserDatabase database;
    private readonly NtlmAuth ntlm;
    private readonly ILogger<AuthService> logger;

    public AuthService(PamAuthenticator pamAuthenticator, IUserDatabase database, NtlmAuth ntlm, ILogger<AuthService> logger)
    {
        this.pamAuthenticator = pamAuthenticator;
        this.database = database;
        this.ntlm = ntlm;
        this.logger = logger;
    }

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
