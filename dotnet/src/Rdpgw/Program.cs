using Microsoft.AspNetCore.Authentication.Negotiate;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using MudBlazor.Services;
using Prometheus;
using Rdpgw.Components;
using Rdpgw.Config;
using Rdpgw.KdcProxy;
using Rdpgw.Protocol;
using Rdpgw.Security;
using Rdpgw.Web;

const string GatewayEndPoint = "/remoteDesktopGateway/";
const string KdcProxyEndPoint = "/KdcProxy";

var configFile = "rdpgw.yaml";
for (var i = 0; i < args.Length; i++)
{
    if ((args[i] == "-c" || args[i] == "--conf") && i + 1 < args.Length) configFile = args[++i];
    else if (args[i].StartsWith("--conf=", StringComparison.Ordinal)) configFile = args[i][7..];
}
var conf = Configuration.Load(configFile);

var gwAddress = string.IsNullOrEmpty(conf.Server.GatewayAddress) ? new Uri("https://localhost") : new Uri(conf.Server.GatewayAddress, UriKind.RelativeOrAbsolute);
if (!gwAddress.IsAbsoluteUri) gwAddress = new Uri("https:" + conf.Server.GatewayAddress);
var cb = new UriBuilder(gwAddress) { Path = "callback" }.Uri;

SecurityOptions.VerifyClientIP = conf.Security.VerifyClientIp;
SecurityOptions.SigningKey = System.Text.Encoding.UTF8.GetBytes(conf.Security.PAATokenSigningKey);
SecurityOptions.EncryptionKey = System.Text.Encoding.UTF8.GetBytes(conf.Security.PAATokenEncryptionKey);
SecurityOptions.UserEncryptionKey = System.Text.Encoding.UTF8.GetBytes(conf.Security.UserTokenEncryptionKey);
SecurityOptions.UserSigningKey = System.Text.Encoding.UTF8.GetBytes(conf.Security.UserTokenSigningKey);
SecurityOptions.QuerySigningKey = System.Text.Encoding.UTF8.GetBytes(conf.Security.QueryTokenSigningKey);
SecurityOptions.HostSelection = conf.Server.HostSelection;
SecurityOptions.Hosts = conf.Server.Hosts;

Sessions.InitStore(System.Text.Encoding.UTF8.GetBytes(conf.Server.SessionKey), System.Text.Encoding.UTF8.GetBytes(conf.Server.SessionEncryptionKey), conf.Server.SessionStore, conf.Server.MaxSessionLength);
ContextMiddleware.InitTrustedProxies(conf.Server.TrustedProxies);

var webConfig = new WebHandlerConfig
{
    QueryInfo = Security.QueryInfo,
    QueryTokenIssuer = conf.Security.QueryTokenIssuer,
    EnableUserToken = conf.Security.EnableUserToken,
    Hosts = conf.Server.Hosts,
    HostSelection = conf.Server.HostSelection,
    RdpOpts = new RdpOpts { UsernameTemplate = conf.Client.UsernameTemplate, SplitUserDomain = conf.Client.SplitUserDomain, NoUsername = conf.Client.NoUsername, OverridableRdpKeys = conf.Client.RdpOverridableKeys },
    GatewayAddress = gwAddress,
    TemplateFile = conf.Client.Defaults,
    RdpSigningCert = conf.Client.SigningCert,
    RdpSigningKey = conf.Client.SigningKey,
    AllowedDestinationPorts = conf.Server.AllowedDestinationPorts,
    AllowPrivateDestinations = conf.Server.AllowPrivateDestinations,
};
if (conf.Caps.TokenAuth) webConfig.PAATokenGenerator = Security.GeneratePAAToken;
if (conf.Security.EnableUserToken) webConfig.UserTokenGenerator = Security.GenerateUserToken;
var web = webConfig.NewHandler();

Console.WriteLine("Starting remote desktop gateway server");
var builder = WebApplication.CreateBuilder(args);
builder.Services.AddAuthentication(NegotiateDefaults.AuthenticationScheme).AddNegotiate();
builder.Services.AddAuthorization();
builder.Services.AddMetricServer(options => { });
builder.Services.AddSingleton(web);
builder.Services.AddHttpContextAccessor();
builder.Services.AddRazorComponents().AddInteractiveServerComponents();
builder.Services.AddMudServices();
builder.WebHost.ConfigureKestrel(options =>
{
    options.ListenAnyIP(conf.Server.Port, listen =>
    {
        listen.Protocols = HttpProtocols.Http1;
        if (conf.Server.Tls == Configuration.TlsDisable)
        {
            Console.WriteLine("TLS disabled - rdp gw connections require tls, make sure to have a terminator");
        }
        else if (!string.IsNullOrEmpty(conf.Server.CertFile) && !string.IsNullOrEmpty(conf.Server.KeyFile))
        {
            var cert = System.Security.Cryptography.X509Certificates.X509Certificate2.CreateFromPemFile(conf.Server.CertFile, conf.Server.KeyFile);
            listen.UseHttps(cert);
        }
        else
        {
            Console.WriteLine("ACME/autocert is unsupported in the .NET port; configure certfile/keyfile or set tls: disable");
            throw new InvalidOperationException("TLS requires certfile/keyfile in the .NET port");
        }
    });
});

var app = builder.Build();
app.UseWebSockets();
app.UseAuthentication();
app.UseAuthorization();
app.Use(async (ctx, next) => await ContextMiddleware.EnrichContext(ctx, next));
app.UseAntiforgery();
app.UseMetricServer("/metrics");

var gw = new Gateway
{
    RedirectFlags = new RedirectFlags { Clipboard = conf.Caps.EnableClipboard, Drive = conf.Caps.EnableDrive, Printer = conf.Caps.EnablePrinter, Port = conf.Caps.EnablePort, Pnp = conf.Caps.EnablePnp, DisableAll = conf.Caps.DisableRedirect, EnableAll = conf.Caps.RedirectAll },
    IdleTimeout = conf.Caps.IdleTimeout,
    SmartCardAuth = conf.Caps.SmartCardAuth,
    TokenAuth = conf.Caps.TokenAuth,
    ReceiveBuf = conf.Server.ReceiveBuf,
    SendBuf = conf.Server.SendBuf,
};
if (conf.Caps.TokenAuth)
{
    gw.CheckPAACookie = Security.CheckPAACookie;
    gw.CheckHost = Security.CheckSession(Security.CheckHost);
}
else gw.CheckHost = Security.CheckHost;

OIDC? oidc = null;
HeaderAuth? headerAuth = null;
NTLMAuthHandler? ntlmAuth = null;
BasicAuthHandler? basicAuth = null;
bool kerberosEnabled = false;
var authMux = new AuthMux();

async Task WebAuth(HttpContext ctx, Func<Task> next)
{
    if (oidc is not null) { await oidc.Authenticated(ctx, next); return; }
    if (headerAuth is not null) { await headerAuth.Authenticated(ctx, next); return; }
    await next();
}

app.UseWhen(
    ctx => ctx.Request.Path == "/" || ctx.Request.Path.StartsWithSegments("/_blazor"),
    branch => branch.Use(async (ctx, next) => await WebAuth(ctx, () => next(ctx))));

app.Map("/tokeninfo", TokenInfoEndpoint.TokenInfo);

if (conf.Server.OpenIDEnabled())
{
    Console.WriteLine("enabling openid extended authentication");
    oidc = new OidcConfig { ProviderUrl = conf.OpenId.ProviderUrl, ClientId = conf.OpenId.ClientId, ClientSecret = conf.OpenId.ClientSecret, RedirectUrl = cb.ToString() }.New();
    app.Map("/callback", oidc.HandleCallback);
}
if (conf.Server.HeaderEnabled())
{
    if (conf.Header.TrustedProxies.Count == 0) throw new InvalidOperationException("header authentication is enabled but `header.trustedproxies` is empty; refusing to start in an exploitable configuration");
    Console.WriteLine($"enabling header authentication with user header: {conf.Header.UserHeader} (trusted proxies: {string.Join(',', conf.Header.TrustedProxies)})");
    headerAuth = new HeaderAuthConfig { UserHeader = conf.Header.UserHeader, UserIdHeader = conf.Header.UserIdHeader, EmailHeader = conf.Header.EmailHeader, DisplayNameHeader = conf.Header.DisplayNameHeader, TrustedProxies = conf.Header.TrustedProxies }.New();
}

if (oidc is not null || headerAuth is not null)
{
    app.Map("/connect", ctx => WebAuth(ctx, () => web.HandleDownload(ctx)));
    app.Map("/api/v1/hosts", ctx => WebAuth(ctx, () => web.HandleHostList(ctx)));
    app.Map("/api/v1/user", ctx => WebAuth(ctx, () => web.HandleUserInfo(ctx)));
    app.MapRazorComponents<App>().AddInteractiveServerRenderMode();
}

app.MapStaticAssets();
app.Map("/assets/connect.svg", ctx => web.ServeAssetFile(ctx, "connect.svg"));
app.Map("/assets/icon.svg", ctx => web.ServeAssetFile(ctx, "icon.svg"));

if (conf.Server.NtlmEnabled())
{
    Console.WriteLine("enabling NTLM authentication");
    ntlmAuth = new NTLMAuthHandler { SocketAddress = conf.Server.AuthSocket, Timeout = conf.Server.BasicAuthTimeout };
    authMux.Register(["NTLM", "Negotiate"], ctx => ctx.Request.Headers["Sec-WebSocket-Protocol"] != "binary");
}
if (conf.Server.BasicAuthEnabled())
{
    Console.WriteLine("enabling basic authentication");
    basicAuth = new BasicAuthHandler { SocketAddress = conf.Server.AuthSocket, Timeout = conf.Server.BasicAuthTimeout };
    authMux.Register(["Basic realm=\"restricted\", charset=\"UTF-8\""], null);
}
if (conf.Server.KerberosEnabled())
{
    Console.WriteLine("enabling kerberos authentication");
    kerberosEnabled = true;
    authMux.Register(["Negotiate"], null);
    var kdc = KerberosProxy.InitKdcProxy(conf.Kerberos.Krb5Conf);
    app.MapPost(KdcProxyEndPoint, kdc.Handler);
}

var unauthGateway = (oidc is not null && !conf.Server.KerberosEnabled() && !conf.Server.BasicAuthEnabled() && !conf.Server.NtlmEnabled() && !conf.Server.HeaderEnabled())
    || (headerAuth is not null && !conf.Server.KerberosEnabled() && !conf.Server.BasicAuthEnabled() && !conf.Server.NtlmEnabled() && !conf.Server.OpenIDEnabled());
if (unauthGateway) app.MapMethods(GatewayEndPoint, ["RDG_IN_DATA", "RDG_OUT_DATA"], gw.HandleGatewayProtocol);
else app.MapMethods(GatewayEndPoint, ["RDG_IN_DATA", "RDG_OUT_DATA"], GatewayDispatch);
await app.RunAsync();

async Task GatewayDispatch(HttpContext ctx)
{
    var auth = ctx.Request.Headers.Authorization.ToString();
    if (ntlmAuth is not null && (auth.StartsWith("NTLM", StringComparison.Ordinal) || auth.StartsWith("Negotiate", StringComparison.Ordinal))) { await ntlmAuth.NTLMAuth(ctx, () => gw.HandleGatewayProtocol(ctx)); return; }
    if (basicAuth is not null && auth.StartsWith("Basic", StringComparison.Ordinal)) { await basicAuth.BasicAuth(ctx, () => gw.HandleGatewayProtocol(ctx)); return; }
    if (kerberosEnabled && auth.StartsWith("Negotiate", StringComparison.OrdinalIgnoreCase))
    {
        var result = await ctx.AuthenticateAsync(NegotiateDefaults.AuthenticationScheme);
        if (result.Succeeded && result.Principal is not null)
        {
            ctx.User = result.Principal;
            await ContextMiddleware.TransposeSPNEGOContext(ctx, () => gw.HandleGatewayProtocol(ctx));
            return;
        }
        await ctx.ChallengeAsync(NegotiateDefaults.AuthenticationScheme);
        return;
    }
    await authMux.SetAuthenticate(ctx);
}
