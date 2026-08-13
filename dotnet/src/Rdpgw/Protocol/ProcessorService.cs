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
   
}
