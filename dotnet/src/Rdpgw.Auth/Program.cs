using Microsoft.AspNetCore.Server.Kestrel.Core;
using Rdpgw.Auth;
using Rdpgw.Auth.Config;
using Rdpgw.Auth.Database;
using Rdpgw.Auth.Ntlm;
using Rdpgw.Auth.Pam;
using Rdpgw.Auth.Unix;

CommandLineOptions options;
try
{
    options = CommandLineOptions.Parse(args);
}
catch (Exception ex)
{
    Console.Error.WriteLine(ex.Message);
    CommandLineOptions.PrintHelp(Console.Error);
    return 2;
}

if (options.Help)
{
    CommandLineOptions.PrintHelp(Console.Out);
    return 0;
}

var configuration = Configuration.Load(options.ConfigFile);
if (File.Exists(options.SocketAddr))
{
    File.Delete(options.SocketAddr);
}

if (options.AllowUid.Count > 0 || options.AllowGid.Count > 0)
{
    Console.Error.WriteLine("rdpgw-auth: --allow-uid/--allow-gid are accepted for CLI compatibility; ASP.NET Core transport relies on socket file permissions.");
}

var builder = WebApplication.CreateBuilder(new WebApplicationOptions { Args = [] });
builder.Services.AddGrpc();
builder.Services.AddSingleton(configuration);
builder.Services.AddSingleton<IUserDatabase>(_ => new ConfigDatabase(configuration.Users));
builder.Services.AddSingleton(_ => new PamAuthenticator(options.ServiceName));
builder.Services.AddSingleton<NtlmAuth>();
builder.Services.AddSingleton<AuthService>();
builder.WebHost.ConfigureKestrel(kestrel =>
{
    kestrel.ListenUnixSocket(options.SocketAddr, listenOptions =>
    {
        listenOptions.Protocols = HttpProtocols.Http2;
    });
});

var app = builder.Build();
app.MapGrpcService<AuthService>();

Console.Error.WriteLine($"Starting auth server on {options.SocketAddr}");
uint oldUmask = 0;
var changedUmask = OperatingSystem.IsLinux();
if (changedUmask)
{
    oldUmask = NativeUnix.umask(Convert.ToUInt32("117", 8));
}

try
{
    await app.StartAsync();
}
finally
{
    if (changedUmask)
    {
        NativeUnix.umask(oldUmask);
    }
}

if (OperatingSystem.IsLinux() && File.Exists(options.SocketAddr))
{
    var rc = NativeUnix.chmod(options.SocketAddr, Convert.ToUInt32("660", 8));
    if (rc != 0)
    {
        Console.Error.WriteLine($"Failed to chmod socket {options.SocketAddr}: errno {Environment.ProcessId}");
    }
}

await app.WaitForShutdownAsync();
return 0;
