using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using Rdpgw.Auth.Database;
using AuthMessages = Rdpgw.Shared.Auth;

namespace Rdpgw.Auth.Ntlm;

/// <summary>
/// Performs stateful NTLMv2 authentication for gRPC authentication requests.
/// </summary>
/// <remarks>
/// NTLM is a multi-message protocol. Instances keep short-lived per-session
/// context so a client's type 3 AUTHENTICATE_MESSAGE can be verified against
/// the challenge emitted for its type 1 NEGOTIATE_MESSAGE.
/// </remarks>
public sealed class NtlmAuth
{
    private static readonly TimeSpan CacheExpiration = TimeSpan.FromMinutes(1);
    private readonly ConcurrentDictionary<string, NtlmContext> contexts = new(StringComparer.Ordinal);
    private readonly IUserDatabase database;
    private readonly ILogger<NtlmAuth> logger;

    /// <summary>
    /// Gets the NetBIOS server name advertised in NTLM target information.
    /// </summary>
    public string ServerName { get; init; } = string.Empty;

    /// <summary>
    /// Gets the NetBIOS domain name advertised in NTLM target information.
    /// </summary>
    public string DomainName { get; init; } = string.Empty;

    /// <summary>
    /// Gets the DNS server name advertised in NTLM target information.
    /// </summary>
    public string DnsServerName { get; init; } = string.Empty;

    /// <summary>
    /// Gets the DNS domain name advertised in NTLM target information.
    /// </summary>
    public string DnsDomainName { get; init; } = string.Empty;

    /// <summary>
    /// Gets the DNS tree name advertised in NTLM target information.
    /// </summary>
    public string DnsTreeName { get; init; } = string.Empty;

    /// <summary>
    /// Initializes a new instance of the <see cref="NtlmAuth"/> class.
    /// </summary>
    /// <param name="database">User database containing passwords needed for NTLMv2 proof verification.</param>
    /// <param name="logger">Logger used for NTLM diagnostics.</param>
    public NtlmAuth(IUserDatabase database, ILogger<NtlmAuth> logger)
    {
        this.database = database;
        this.logger = logger;
    }

    /// <summary>
    /// Processes a base64-encoded NTLMSSP message for a session.
    /// </summary>
    /// <param name="message">Request containing a session identifier and NTLMSSP payload.</param>
    /// <returns>A response with either a challenge message or final authentication result.</returns>
    /// <exception cref="InvalidOperationException">Thrown when the session or NTLM message is invalid.</exception>
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
        // The gRPC caller supplies a stable session key so the type 3 message can
        // be checked against the exact random challenge sent in the type 2 reply.
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

    /// <summary>
    /// Removes abandoned NTLM contexts whose challenge can no longer be completed safely.
    /// </summary>
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

    /// <summary>
    /// Holds the challenge state for one in-progress NTLM exchange.
    /// </summary>
    private sealed class NtlmContext
    {
        private readonly NtlmAuth owner;
        private byte[]? challenge;
        private byte[]? targetInfo;

        /// <summary>
        /// Gets the time this context last processed a message.
        /// </summary>
        public DateTimeOffset LastSeen { get; private set; } = DateTimeOffset.UtcNow;

        /// <summary>
        /// Initializes a new instance of the <see cref="NtlmContext"/> class.
        /// </summary>
        /// <param name="owner">Owning NTLM authenticator.</param>
        public NtlmContext(NtlmAuth owner)
        {
            this.owner = owner;
        }

        /// <summary>
        /// Processes an NTLMSSP message within this session context.
        /// </summary>
        /// <param name="encodedMessage">Base64-encoded NTLMSSP message bytes.</param>
        /// <param name="response">Response object to populate.</param>
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
                    // Type 1 is the client NEGOTIATE_MESSAGE (MS-NLMP 2.2.1.1).
                    Negotiate(message, response);
                    return;
                case 3:
                    if (challenge is null || targetInfo is null)
                    {
                        throw new InvalidOperationException("NTLM Authenticate requires active session: first call negotioate");
                    }
                    // Type 3 is the client AUTHENTICATE_MESSAGE (MS-NLMP 2.2.1.3).
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

        /// <summary>
        /// Handles an NTLM type 1 NEGOTIATE_MESSAGE and emits a type 2 challenge.
        /// </summary>
        /// <param name="message">Raw NEGOTIATE_MESSAGE bytes.</param>
        /// <param name="response">Response to populate with the base64 challenge.</param>
        private void Negotiate(byte[] message, AuthMessages.NtlmResponse response)
        {
            var negotiateFlags = NtlmMessage.ReadUInt32(message, 12);
            challenge = RandomNumberGenerator.GetBytes(8);
            targetInfo = NtlmMessage.BuildTargetInfo(owner);
            // The type 2 CHALLENGE_MESSAGE carries the server nonce and target
            // info that the client must echo inside the NTLMv2 response blob.
            var challengeMessage = NtlmMessage.CreateChallenge(negotiateFlags, challenge, targetInfo, owner.DomainName, owner.ServerName);
            response.NtlmMessage = Convert.ToBase64String(challengeMessage);
        }

        /// <summary>
        /// Verifies an NTLM type 3 AUTHENTICATE_MESSAGE against the stored challenge.
        /// </summary>
        /// <param name="message">Raw AUTHENTICATE_MESSAGE bytes.</param>
        /// <param name="response">Response to mark authenticated when the NTLM proof is valid.</param>
        private void AuthenticateType3(byte[] message, AuthMessages.NtlmResponse response)
        {
            var flags = message.Length >= 64 ? NtlmMessage.ReadUInt32(message, 60) : NtlmMessage.NegotiateUnicode;
            var unicode = (flags & NtlmMessage.NegotiateUnicode) != 0;
            // Offsets are AUTHENTICATE_MESSAGE security buffers from MS-NLMP
            // section 2.2.1.3: NtChallengeResponse, DomainName, and UserName.
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
            // MS-NLMP 3.3.2 verifies the NTProofStr as HMAC-MD5 over the server
            // challenge concatenated with the client's NTLMv2 response blob.
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
