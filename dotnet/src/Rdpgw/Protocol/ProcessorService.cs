using System.Buffers.Binary;
using System.Net.Sockets;
using Rdpgw.Identity;
using static Rdpgw.Protocol.Caps;
using static Rdpgw.Protocol.Fields;
using static Rdpgw.Protocol.PacketType;
using static Rdpgw.Protocol.ProtocolErrors;

namespace Rdpgw.Protocol;

/// <summary>
/// Implements the MS-TSGU tunnel state machine and bridges accepted DATA packets to the target RDP server.
/// </summary>
/// <remarks>
/// The processor follows the gateway sequence handshake, tunnel create, tunnel authorize, channel create, data, and close.
/// </remarks>
public sealed class ProcessorService(ILogger<ProcessorService> logger)
{
    private readonly CancellationTokenSource _disconnect = new();

    /// <summary>Cancellation token observed by the tunnel processing loop; cancelled by <see cref="SignalDisconnect"/>.</summary>
    public CancellationToken DisconnectToken => _disconnect.Token;

    /// <summary>Requests that the tunnel currently driven by this processor stop processing and disconnect.</summary>
    public void SignalDisconnect()
    {
        logger.LogInformation("Signaling disconnect for tunnel processor");
        _disconnect.Cancel();
    }
}
