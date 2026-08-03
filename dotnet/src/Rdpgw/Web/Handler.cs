using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Http;
using Rdpgw.Data;
using Rdpgw.Identity;
using Rdpgw.Rdp;

namespace Rdpgw.Web;

public delegate Task<string> TokenGeneratorFunc(HttpContext context, string username, string server);
public delegate Task<string> UserTokenGeneratorFunc(HttpContext context, string username);
public delegate Task<string> QueryInfoFunc(HttpContext context, string token, string issuer);

public sealed class WebHandlerConfig
{
    public TokenGeneratorFunc? PAATokenGenerator { get; set; }
    public UserTokenGeneratorFunc? UserTokenGenerator { get; set; }
    public QueryInfoFunc? QueryInfo { get; set; }
    public string QueryTokenIssuer { get; set; } = string.Empty;
    public bool EnableUserToken { get; set; }
    public HostStore? HostStore { get; set; }
    public string HostSelection { get; set; } = string.Empty;
    public Uri GatewayAddress { get; set; } = new("https://localhost");
    public RdpOpts RdpOpts { get; set; } = new();
    public string TemplateFile { get; set; } = string.Empty;
    public string RdpSigningCert { get; set; } = string.Empty;
    public string RdpSigningKey { get; set; } = string.Empty;
    public string TemplatesPath { get; set; } = string.Empty;
    public List<int> AllowedDestinationPorts { get; set; } = [];
    public bool AllowPrivateDestinations { get; set; }
    public Handler NewHandler() => new(this);
}

public sealed class RdpOpts
{
    public string UsernameTemplate { get; set; } = string.Empty;
    public bool SplitUserDomain { get; set; }
    public bool NoUsername { get; set; }
    public List<string> OverridableRdpKeys { get; set; } = [];
}

public sealed class WebConfig
{
    public BrandingConfig Branding { get; set; } = new();
    public MessagesConfig Messages { get; set; } = new();
    public UiConfig UI { get; set; } = new();
    public ThemeConfig Theme { get; set; } = new();
    public sealed class BrandingConfig { public string Title { get; set; } = "RDP Gateway"; public string Logo { get; set; } = "RDP Gateway"; public string PageTitle { get; set; } = "Select a Server to Connect"; }
    public sealed class MessagesConfig { public string SelectServer { get; set; } = "Select a server to connect"; public string Preparing { get; set; } = "Preparing your connection..."; }
    public sealed class UiConfig { public int ProgressAnimationDurationMs { get; set; } = 2000; public bool AutoSelectDefault { get; set; } = true; public bool ShowUserAvatar { get; set; } = true; }
    public sealed class ThemeConfig { public string PrimaryColor { get; set; } = "#667eea"; public string SecondaryColor { get; set; } = "#764ba2"; public string SuccessColor { get; set; } = "#38b2ac"; public string ErrorColor { get; set; } = "#c53030"; }
}

public sealed class Handler
{
    private readonly TokenGeneratorFunc? _paaTokenGenerator;
    private readonly bool _enableUserToken;
    private readonly UserTokenGeneratorFunc? _userTokenGenerator;
    private readonly QueryInfoFunc? _queryInfo;
    private readonly string _queryTokenIssuer;
    private readonly Uri _gatewayAddress;
    private readonly HostStore _hostStore;
    private readonly string _hostSelection;
    private readonly RdpOpts _rdpOpts;
    private readonly string _rdpDefaults;
    private readonly string _rdpSigningCert;
    private readonly string _rdpSigningKey;
    private readonly string _templatesPath;
    private readonly DestinationPolicy _destPolicy;
    private readonly WebConfig _webConfig = new();

    public WebConfig WebConfig => _webConfig;

    public Handler(WebHandlerConfig c)
    {
        if (c.HostStore is null) throw new InvalidOperationException("No host store specified");
        _paaTokenGenerator = c.PAATokenGenerator;
        _enableUserToken = c.EnableUserToken;
        _userTokenGenerator = c.UserTokenGenerator;
        _queryInfo = c.QueryInfo;
        _queryTokenIssuer = c.QueryTokenIssuer;
        _gatewayAddress = c.GatewayAddress;
        _hostStore = c.HostStore;
        _hostSelection = c.HostSelection;
        _rdpOpts = c.RdpOpts;
        _rdpDefaults = c.TemplateFile;
        _rdpSigningCert = c.RdpSigningCert;
        _rdpSigningKey = c.RdpSigningKey;
        _templatesPath = string.IsNullOrEmpty(c.TemplatesPath) ? "./templates" : c.TemplatesPath;
        _destPolicy = new DestinationPolicy(c.AllowedDestinationPorts, c.AllowPrivateDestinations);
        if (!string.IsNullOrEmpty(_rdpSigningCert) || !string.IsNullOrEmpty(_rdpSigningKey)) Console.WriteLine("RDP file signing is configured but not implemented in the .NET port; unsigned RDP files will be returned");
    }

    public async Task HandleDownload(HttpContext ctx)
    {
        var id = IdentityContext.FromContext(ctx) ?? new User();
        if (!id.Authenticated) { Console.WriteLine($"unauthenticated user {id.UserName}"); ctx.Response.StatusCode = 500; await ctx.Response.WriteAsync("cannot find session or user"); return; }
        string host;
        try { host = await GetHost(ctx); }
        catch (Exception ex) { ctx.Response.StatusCode = 400; await ctx.Response.WriteAsync(ex.Message); return; }
        host = host.Replace("{{ preferred_username }}", id.UserName, StringComparison.Ordinal);
        var user = id.UserName; var domain = string.Empty;
        if (_rdpOpts.SplitUserDomain)
        {
            var creds = id.UserName.Split('@', 2); user = creds[0]; if (creds.Length > 1) domain = creds[1];
        }
        var render = user;
        if (!string.IsNullOrEmpty(_rdpOpts.UsernameTemplate))
        {
            render = _rdpOpts.UsernameTemplate.Replace("{{ username }}", user, StringComparison.Ordinal);
            if (render == _rdpOpts.UsernameTemplate) { ctx.Response.StatusCode = 500; await ctx.Response.WriteAsync("invalid server configuration"); return; }
        }
        if (_paaTokenGenerator is null) { ctx.Response.StatusCode = 500; await ctx.Response.WriteAsync("unable to generate gateway credentials"); return; }
        string token;
        try { token = await _paaTokenGenerator(ctx, user, host); }
        catch (Exception ex) { Console.WriteLine($"Cannot generate PAA token for user {user} due to {ex}"); ctx.Response.StatusCode = 500; await ctx.Response.WriteAsync("unable to generate gateway credentials"); return; }
        if (_enableUserToken && _userTokenGenerator is not null)
        {
            try { render = render.Replace("{{ token }}", await _userTokenGenerator(ctx, user), StringComparison.Ordinal); }
            catch (Exception ex) { Console.WriteLine($"Cannot generate token for user {user} due to {ex}"); ctx.Response.StatusCode = 500; await ctx.Response.WriteAsync("unable to generate gateway credentials"); return; }
        }
        var fn = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant() + ".rdp";
        ctx.Response.Headers.ContentDisposition = "attachment; filename=" + fn;
        ctx.Response.ContentType = "application/x-rdp";
        Builder b;
        try { b = string.IsNullOrEmpty(_rdpDefaults) ? Builder.NewBuilder() : Builder.NewBuilderFromFile(_rdpDefaults); }
        catch (Exception ex) { Console.WriteLine($"Cannot load RDP template file {_rdpDefaults} due to {ex}"); ctx.Response.StatusCode = 500; await ctx.Response.WriteAsync("unable to load RDP template"); return; }
        try { b.ApplyOverrides(ctx.Request.Query, _rdpOpts.OverridableRdpKeys); }
        catch (Exception ex) { Console.WriteLine($"rejected rdp override for user {id.UserName}: {ex.Message}"); ctx.Response.StatusCode = 400; await ctx.Response.WriteAsync(ex.Message); return; }
        if (!_rdpOpts.NoUsername) { b.Settings.Username = render; if (!string.IsNullOrEmpty(domain)) b.Settings.Domain = domain; }
        b.Settings.FullAddress = host;
        var gatewayHost = _hostStore.GetGatewayAddressForHost(id.UserName, host);
        b.Settings.GatewayHostname = gatewayHost ?? (_gatewayAddress.IsDefaultPort ? _gatewayAddress.Host : _gatewayAddress.Authority);
        b.Settings.GatewayCredentialsSource = RdpCredentialSource.Cookie;
        b.Settings.GatewayAccessToken = token;
        b.Settings.GatewayCredentialMethod = 1;
        b.Settings.GatewayUsageMethod = 1;
        await ctx.Response.WriteAsync(b.ToString());
    }

    public List<Host> GetHosts(string userName)
    {
        if (_hostSelection == "roundrobin")
            return [new Host("roundrobin", "Available Servers", "", "Connect to an available server automatically", true)];
        var entries = _hostStore.GetVisible(userName);
        var hasDefault = entries.Any(h => h.IsDefault);
        return entries.Select((h, i) => new Host($"host_{h.Id}", h.Name, h.Address, h.Description, hasDefault ? h.IsDefault : i == 0)).ToList();
    }

    public async Task HandleHostList(HttpContext ctx)
    {
        var id = IdentityContext.FromContext(ctx) ?? new User();
        if (!id.Authenticated) { ctx.Response.StatusCode = 401; await ctx.Response.WriteAsync("Unauthorized"); return; }
        ctx.Response.ContentType = "application/json";
        await JsonSerializer.SerializeAsync(ctx.Response.Body, GetHosts(id.UserName), JsonOptions);
    }

    public async Task HandleUserInfo(HttpContext ctx)
    {
        var id = IdentityContext.FromContext(ctx) ?? new User();
        if (!id.Authenticated) { ctx.Response.StatusCode = 401; await ctx.Response.WriteAsync("Unauthorized"); return; }
        ctx.Response.ContentType = "application/json";
        await JsonSerializer.SerializeAsync(ctx.Response.Body, new { username = id.UserName, authenticated = id.Authenticated, authTime = id.AuthTime });
    }

    public async Task ServeAssetFile(HttpContext ctx, string filename)
    {
        var candidates = new List<string> { "./assets/" + filename, "/app/assets/" + filename, "/opt/rdpgw/assets/" + filename, Path.Combine("assets", filename) };
        if (!string.IsNullOrEmpty(_templatesPath))
        {
            var current = Path.GetFullPath(_templatesPath);
            for (var i = 0; i < 5; i++) { current = Directory.GetParent(current)?.FullName ?? current; candidates.Add(Path.Combine(current, "assets", filename)); }
        }
        var found = candidates.FirstOrDefault(File.Exists);
        if (found is null) { Console.WriteLine($"Asset file not found: {filename}. Tried paths: {string.Join(',', candidates)}"); ctx.Response.StatusCode = 404; return; }
        await ServeFile(ctx, found, filename);
    }

    private async Task ServeFile(HttpContext ctx, string path, string filename)
    {
        if (!File.Exists(path)) { ctx.Response.StatusCode = 404; return; }
        ctx.Response.ContentType = Path.GetExtension(filename).ToLowerInvariant() switch { ".css" => "text/css", ".js" => "application/javascript", ".svg" => "image/svg+xml", ".png" => "image/png", ".jpg" or ".jpeg" => "image/jpeg", _ => "application/octet-stream" };
        ctx.Response.Headers.CacheControl = "public, max-age=3600";
        await ctx.Response.SendFileAsync(path);
    }

    private async Task<string> GetHost(HttpContext ctx) => _hostSelection switch
    {
        "roundrobin" => SelectRandomHost(ctx),
        "signed" => await GetSignedHost(ctx),
        "unsigned" => GetUnsignedHost(ctx),
        "any" => await GetAnyHost(ctx),
        _ => SelectRandomHost(ctx),
    };
    private static string UserFromContext(HttpContext ctx) => IdentityContext.FromContext(ctx)?.UserName ?? string.Empty;
    private string SelectRandomHost(HttpContext ctx)
    {
        var hosts = _hostStore.GetHostAddresses(UserFromContext(ctx));
        if (hosts.Count < 1) throw new InvalidOperationException("no hosts configured in the host database");
        return hosts[Random.Shared.Next(hosts.Count)];
    }
    private async Task<string> GetSignedHost(HttpContext ctx)
    {
        var token = ctx.Request.Query["host"].FirstOrDefault();
        if (string.IsNullOrEmpty(token) || _queryInfo is null) throw new InvalidOperationException("invalid query parameter");
        var host = await _queryInfo(ctx, token, _queryTokenIssuer);
        if (!_hostStore.GetHostAddresses(UserFromContext(ctx)).Contains(host)) throw new InvalidOperationException("invalid host specified in query token");
        return host;
    }
    private string GetUnsignedHost(HttpContext ctx)
    {
        var host = ctx.Request.Query["host"].FirstOrDefault();
        if (string.IsNullOrEmpty(host)) throw new InvalidOperationException("invalid query parameter");
        if (!_hostStore.GetHostAddresses(UserFromContext(ctx)).Contains(host)) throw new InvalidOperationException("invalid host specified in query parameter");
        return host;
    }
    private async Task<string> GetAnyHost(HttpContext ctx)
    {
        var host = ctx.Request.Query["host"].FirstOrDefault();
        if (string.IsNullOrEmpty(host)) throw new InvalidOperationException("invalid query parameter");
        await _destPolicy.Allow(host);
        return host;
    }

    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
    public sealed record Host(string Id, string Name, string Address, string Description, bool IsDefault);
    private sealed class DestinationPolicy(List<int> allowedPorts, bool allowPrivate)
    {
        private readonly HashSet<int> _allowedPorts = allowedPorts.Count == 0 ? [3389] : allowedPorts.ToHashSet();
        public async Task Allow(string hostport)
        {
            var host = hostport; var port = 3389;
            var m = Regex.Match(hostport, @"^\[(?<h>.+)\]:(?<p>\d+)$|^(?<h>[^:]+):(?<p>\d+)$");
            if (m.Success) { host = m.Groups["h"].Value; port = int.Parse(m.Groups["p"].Value); }
            if (!_allowedPorts.Contains(port)) throw new InvalidOperationException($"destination not allowed: port {port} not in allow-list");
            if (allowPrivate) return;
            IPAddress[] addrs = IPAddress.TryParse(host, out var ip) ? [ip] : await Dns.GetHostAddressesAsync(host);
            foreach (var a in addrs) if (!IsPublic(a)) throw new InvalidOperationException($"destination not allowed: destination {host} ({a}) is in a private or non-routable range");
        }
        private static bool IsPublic(IPAddress ip) => !IPAddress.IsLoopback(ip) && !ip.IsIPv6LinkLocal && !ip.IsIPv6Multicast && !ip.Equals(IPAddress.Any) && !ip.Equals(IPAddress.IPv6Any) && !IsPrivate(ip);
        private static bool IsPrivate(IPAddress ip)
        {
            var b = ip.MapToIPv4().GetAddressBytes();
            return b[0] == 10 || b[0] == 127 || (b[0] == 172 && b[1] >= 16 && b[1] <= 31) || (b[0] == 192 && b[1] == 168) || (b[0] == 169 && b[1] == 254);
        }
    }
}
