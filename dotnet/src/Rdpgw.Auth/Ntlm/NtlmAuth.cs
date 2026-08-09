using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using Rdpgw.Auth.Database;
using AuthMessages = Rdpgw.Shared.Auth;

namespace Rdpgw.Auth.Ntlm;

public sealed class NtlmAuth
{
    private static readonly TimeSpan CacheExpiration = TimeSpan.FromMinutes(1);
    private readonly ConcurrentDictionary<string, NtlmContext> contexts = new(StringComparer.Ordinal);
    private readonly IUserDatabase database;
    private readonly ILogger<NtlmAuth> logger;

    public string ServerName { get; init; } = string.Empty;
    public string DomainName { get; init; } = string.Empty;
    public string DnsServerName { get; init; } = string.Empty;
    public string DnsDomainName { get; init; } = string.Empty;
    public string DnsTreeName { get; init; } = string.Empty;

    public NtlmAuth(IUserDatabase database, ILogger<NtlmAuth> logger)
    {
        this.database = database;
        this.logger = logger;
    }

    public AuthMessages.NtlmResponse Authenticate(AuthMessages.NtlmRequest message)
    {
        var response = new AuthMessages.NtlmResponse { Authenticated = false };
        if (string.IsNullOrEmpty(message.Session))
        {
            throw new InvalidOperationException("Invalid (empty) session specified");
        }
        if (string.IsNullOrEmpty(message.NtlmMessage))
        {
            throw new InvalidOperationException("Empty NTLM message specified");
        }

        CleanupExpired();
        var context = contexts.GetOrAdd(message.Session, _ => new NtlmContext(this));
        try
        {
            context.Authenticate(message.NtlmMessage, response);
            if (response.Authenticated)
            {
                contexts.TryRemove(message.Session, out _);
            }
        }
        catch
        {
            contexts.TryRemove(message.Session, out _);
            throw;
        }
        return response;
    }

    private void CleanupExpired()
    {
        var now = DateTimeOffset.UtcNow;
        foreach (var pair in contexts)
        {
            if (now - pair.Value.LastSeen > CacheExpiration)
            {
                contexts.TryRemove(pair.Key, out _);
            }
        }
    }

    private sealed class NtlmContext
    {
        private readonly NtlmAuth owner;
        private byte[]? challenge;
        private byte[]? targetInfo;
        public DateTimeOffset LastSeen { get; private set; } = DateTimeOffset.UtcNow;

        public NtlmContext(NtlmAuth owner)
        {
            this.owner = owner;
        }

        public void Authenticate(string encodedMessage, AuthMessages.NtlmResponse response)
        {
            LastSeen = DateTimeOffset.UtcNow;
            byte[] message;
            try
            {
                message = Convert.FromBase64String(encodedMessage);
            }
            catch (FormatException ex)
            {
                throw new InvalidOperationException($"Failed to decode NTLM Authorisation header: {ex.Message}", ex);
            }

            var type = NtlmMessage.GetMessageType(message);
            switch (type)
            {
                case 1:
                    Negotiate(message, response);
                    return;
                case 3:
                    if (challenge is null || targetInfo is null)
                    {
                        throw new InvalidOperationException("NTLM Authenticate requires active session: first call negotioate");
                    }
                    AuthenticateType3(message, response);
                    return;
                default:
                    if (challenge is null)
                    {
                        throw new InvalidOperationException("New NTLM auth sequence should start with negotioate request");
                    }
                    throw new InvalidOperationException("Failed to parse NTLM Authorisation header: unsupported NTLM message type");
            }
        }

        private void Negotiate(byte[] message, AuthMessages.NtlmResponse response)
        {
            var negotiateFlags = NtlmMessage.ReadUInt32(message, 12);
            challenge = RandomNumberGenerator.GetBytes(8);
            targetInfo = NtlmMessage.BuildTargetInfo(owner);
            var challengeMessage = NtlmMessage.CreateChallenge(negotiateFlags, challenge, targetInfo, owner.DomainName, owner.ServerName);
            response.NtlmMessage = Convert.ToBase64String(challengeMessage);
        }

        private void AuthenticateType3(byte[] message, AuthMessages.NtlmResponse response)
        {
            var flags = message.Length >= 64 ? NtlmMessage.ReadUInt32(message, 60) : NtlmMessage.NegotiateUnicode;
            var unicode = (flags & NtlmMessage.NegotiateUnicode) != 0;
            var ntResponse = NtlmMessage.ReadSecurityBuffer(message, 20);
            var domain = NtlmMessage.ReadSecurityBufferString(message, 28, unicode);
            var username = NtlmMessage.ReadSecurityBufferString(message, 36, unicode);

            var password = owner.database.GetPassword(username);
            if (string.IsNullOrEmpty(password))
            {
                owner.logger.LogWarning("NTLM: unknown username specified: {User}", username);
                return;
            }
            if (ntResponse.Length < 24)
            {
                return;
            }

            var proof = ntResponse[..16];
            var blob = ntResponse[16..];
            var ntowfv2 = NtlmCrypto.NtowfV2(username, password, domain);
            var expected = NtlmCrypto.HmacMd5(ntowfv2, challenge!.Concat(blob).ToArray());
            if (!CryptographicOperations.FixedTimeEquals(proof, expected))
            {
                owner.logger.LogWarning("Failed to process NTLM authenticate message: invalid NTLMv2 response");
                return;
            }

            response.Authenticated = true;
            response.Username = username;
        }
    }
}
