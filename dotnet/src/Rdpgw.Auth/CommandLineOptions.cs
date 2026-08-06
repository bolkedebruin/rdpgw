namespace Rdpgw.Auth;

public sealed record class CommandLineOptions
{
    public string ServiceName { get; private init; } = "rdpgw";
    public string SocketAddr { get; private init; } = "/tmp/rdpgw-auth.sock";
    public string ConfigFile { get; private init; } = "rdpgw-auth.yaml";
    public List<int> AllowUid { get; private init; } = [];
    public List<int> AllowGid { get; private init; } = [];
    public bool Help { get; private init; }

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

    private CommandLineOptions withHelp() => this with { Help = true };

    private static int ParseInt(string option, string value) => int.TryParse(value, out var parsed)
        ? parsed
        : throw new ArgumentException($"Invalid integer for {option}: {value}");
}
