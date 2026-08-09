namespace Rdpgw.Auth;

/// <summary>
/// Parsed command-line options for the authentication sidecar process.
/// </summary>
public sealed record class CommandLineOptions
{
    /// <summary>
    /// Gets the PAM service name used when authenticating username/password requests.
    /// </summary>
    public string ServiceName { get; private init; } = "rdpgw";

    /// <summary>
    /// Gets the Unix domain socket path where the gRPC authentication service listens.
    /// </summary>
    public string SocketAddr { get; private init; } = "/tmp/rdpgw-auth.sock";

    /// <summary>
    /// Gets the YAML configuration file containing locally configured users.
    /// </summary>
    public string ConfigFile { get; private init; } = "rdpgw-auth.yaml";

    /// <summary>
    /// Gets additional user ids accepted for CLI compatibility with the Go implementation.
    /// </summary>
    public List<int> AllowUid { get; private init; } = [];

    /// <summary>
    /// Gets additional group ids accepted for CLI compatibility with the Go implementation.
    /// </summary>
    public List<int> AllowGid { get; private init; } = [];

    /// <summary>
    /// Gets a value indicating whether help output was requested.
    /// </summary>
    public bool Help { get; private init; }

    /// <summary>
    /// Parses command-line arguments into immutable option values.
    /// </summary>
    /// <param name="args">Arguments passed to the auth sidecar executable.</param>
    /// <returns>The parsed command-line options.</returns>
    /// <exception cref="ArgumentException">Thrown when an option is unknown, missing a value, or has an invalid value.</exception>
    public static CommandLineOptions Parse(string[] args)
    {
        var options = new CommandLineOptions();
        for (var i = 0; i < args.Length; i++)
        {
            var arg = args[i];
            string? NextValue()
            {
                if (i + 1 >= args.Length)
                {
                    throw new ArgumentException($"Missing value for {arg}");
                }
                return args[++i];
            }

            string ReadValue(string longName)
            {
                var prefix = longName + "=";
                // Long options support both "--name value" and "--name=value" forms.
                return arg.StartsWith(prefix, StringComparison.Ordinal) ? arg[prefix.Length..] : NextValue()!;
            }

            switch (arg)
            {
                case "-h":
                case "--help":
                    options = options.withHelp();
                    break;
                case "-n":
                case "--name":
                    options = options with { ServiceName = NextValue()! };
                    break;
                case var _ when arg.StartsWith("--name=", StringComparison.Ordinal):
                    options = options with { ServiceName = ReadValue("--name") };
                    break;
                case "-s":
                case "--socket":
                    options = options with { SocketAddr = NextValue()! };
                    break;
                case var _ when arg.StartsWith("--socket=", StringComparison.Ordinal):
                    options = options with { SocketAddr = ReadValue("--socket") };
                    break;
                case "-c":
                case "--conf":
                    options = options with { ConfigFile = NextValue()! };
                    break;
                case var _ when arg.StartsWith("--conf=", StringComparison.Ordinal):
                    options = options with { ConfigFile = ReadValue("--conf") };
                    break;
                case "--allow-uid":
                    options.AllowUid.Add(ParseInt("--allow-uid", NextValue()!));
                    break;
                case var _ when arg.StartsWith("--allow-uid=", StringComparison.Ordinal):
                    options.AllowUid.Add(ParseInt("--allow-uid", ReadValue("--allow-uid")));
                    break;
                case "--allow-gid":
                    options.AllowGid.Add(ParseInt("--allow-gid", NextValue()!));
                    break;
                case var _ when arg.StartsWith("--allow-gid=", StringComparison.Ordinal):
                    options.AllowGid.Add(ParseInt("--allow-gid", ReadValue("--allow-gid")));
                    break;
                default:
                    throw new ArgumentException($"Unknown option: {arg}");
            }
        }
        return options;
    }

    /// <summary>
    /// Writes command-line usage and acknowledgements.
    /// </summary>
    /// <param name="writer">Destination for the help text.</param>
    public static void PrintHelp(TextWriter writer)
    {
        writer.WriteLine("Usage: rdpgw-auth [OPTIONS]");
        writer.WriteLine("  -n, --name        the PAM service name to use (default: rdpgw)");
        writer.WriteLine("  -s, --socket      the location of the socket (default: /tmp/rdpgw-auth.sock)");
        writer.WriteLine("  -c, --conf        users config file for NTLM (yaml) (default: rdpgw-auth.yaml)");
        writer.WriteLine("      --allow-uid   additional UIDs allowed to connect to the socket (repeatable)");
        writer.WriteLine("      --allow-gid   GIDs allowed to connect to the socket (repeatable)");
        writer.WriteLine("Acknowledgements:");
        writer.WriteLine(" - This product includes software developed by the Thomson Reuters Global Resources. (go-ntlm - https://github.com/m7913d/go-ntlm - BSD-4 License)");
    }

    /// <summary>
    /// Returns a copy with the help flag enabled.
    /// </summary>
    /// <returns>A copy of this option set with <see cref="Help"/> set.</returns>
    private CommandLineOptions withHelp() => this with { Help = true };

    /// <summary>
    /// Parses an integer option value and reports the owning option on failure.
    /// </summary>
    /// <param name="option">Option name used in an error message.</param>
    /// <param name="value">Value to parse.</param>
    /// <returns>The parsed integer value.</returns>
    private static int ParseInt(string option, string value) => int.TryParse(value, out var parsed)
        ? parsed
        : throw new ArgumentException($"Invalid integer for {option}: {value}");
}
