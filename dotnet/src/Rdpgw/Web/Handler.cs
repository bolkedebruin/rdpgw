using System.Net;
using System.Text.Json;
using System.Text.RegularExpressions;
using Rdpgw.Data;
using Rdpgw.Identity;
using Rdpgw.Rdp;

namespace Rdpgw.Web;


/// <summary>Generates an optional user token for username templating.</summary>
/// <param name="context">Current HTTP context.</param>
/// <param name="username">Authenticated username.</param>
/// <returns>A token string for the generated username.</returns>
public delegate Task<string> UserTokenGeneratorFunc(HttpContext context, string username);
/// <summary>Validates a signed query token and returns the embedded host/query subject.</summary>
/// <param name="context">Current HTTP context.</param>
/// <param name="token">Signed query token.</param>
/// <param name="issuer">Expected issuer.</param>
/// <returns>The token subject.</returns>
public delegate Task<string> QueryInfoFunc(HttpContext context, string token, string issuer);

/// <summary>
/// Configuration object used to construct the web handler outside the ASP.NET options binder.
/// </summary>
public sealed class WebHandlerConfig
{
    /// <summary>Gets or sets the signed query-token validator for signed host selection.</summary>
    public QueryInfoFunc? QueryInfo { get; set; }
    /// <summary>Gets or sets the expected issuer for signed host-selection query tokens.</summary>
    public string QueryTokenIssuer { get; set; } = string.Empty;
    /// <summary>Gets or sets whether username templates may contain generated user tokens.</summary>
    public bool EnableUserToken { get; set; }
    /// <summary>Gets or sets the host-selection mode.</summary>
    public string HostSelection { get; set; } = string.Empty;
    /// <summary>Gets or sets the default gateway address for generated RDP files.</summary>
    public Uri GatewayAddress { get; set; } = new("https://localhost");
    /// <summary>Gets or sets RDP rendering options.</summary>
    public RdpOpts RdpOpts { get; set; } = new();
    /// <summary>Gets or sets the RDP template file path.</summary>
    public string TemplateFile { get; set; } = string.Empty;
    /// <summary>Gets or sets the RDP signing certificate path.</summary>
    public string RdpSigningCert { get; set; } = string.Empty;
    /// <summary>Gets or sets the RDP signing private-key path.</summary>
    public string RdpSigningKey { get; set; } = string.Empty;
    /// <summary>Gets or sets the templates/assets root path used for asset lookup.</summary>
    public string TemplatesPath { get; set; } = string.Empty;
    /// <summary>Gets or sets destination ports allowed in arbitrary-host mode.</summary>
    public List<int> AllowedDestinationPorts { get; set; } = [];
    /// <summary>Gets or sets whether arbitrary-host mode may connect to private addresses.</summary>
    public bool AllowPrivateDestinations { get; set; }
    /// <summary>Creates the request handler using a supplied logger.</summary>
    /// <param name="logger">Logger for request handling diagnostics.</param>
    /// <param name="hostStore">Host store used to resolve destination hosts.</param>
    /// <param name="builderService">Builder service used to produce RDP files.</param>
    /// <returns>A configured <see cref="Handler"/>.</returns>
    public Handler NewHandler(ILogger<Handler> logger, HostStore hostStore, IBuilderService builderService) => new(this, logger, hostStore, builderService);
}

/// <summary>
/// Options controlling username rendering and permitted RDP query-string overrides.
/// </summary>
public sealed class RdpOpts
{
    /// <summary>Gets or sets the username template written into generated RDP files.</summary>
    public string UsernameTemplate { get; set; } = string.Empty;
    /// <summary>Gets or sets whether user@domain names are split into username and domain fields.</summary>
    public bool SplitUserDomain { get; set; }
    /// <summary>Gets or sets whether generated RDP files omit username and domain fields.</summary>
    public bool NoUsername { get; set; }
    /// <summary>Gets or sets RDP setting keys users may override via query string.</summary>
    public List<string> OverridableRdpKeys { get; set; } = [];
}

/// <summary>
/// UI text, branding, and theme defaults exposed to the Blazor web application.
/// </summary>
public sealed class WebConfig
{
    /// <summary>Gets or sets web branding strings.</summary>
    public BrandingConfig Branding { get; set; } = new();
    /// <summary>Gets or sets user-facing status and instruction messages.</summary>
    public MessagesConfig Messages { get; set; } = new();
    /// <summary>Gets or sets user-interface behavior flags.</summary>
    public UiConfig UI { get; set; } = new();
    /// <summary>Gets or sets theme color values.</summary>
    public ThemeConfig Theme { get; set; } = new();
    /// <summary>Branding strings displayed by the web UI.</summary>
    public sealed class BrandingConfig
    {
        /// <summary>Gets or sets the application title.</summary>
        public string Title { get; set; } = "RDP Gateway";
        /// <summary>Gets or sets the logo text or asset reference.</summary>
        public string Logo { get; set; } = "RDP Gateway";
        /// <summary>Gets or sets the host-selection page title.</summary>
        public string PageTitle { get; set; } = "Select a Server to Connect";
    }
    /// <summary>User-facing messages displayed during host selection and download preparation.</summary>
    public sealed class MessagesConfig
    {
        /// <summary>Gets or sets the select-server prompt.</summary>
        public string SelectServer { get; set; } = "Select a server to connect";
        /// <summary>Gets or sets the preparation status message.</summary>
        public string Preparing { get; set; } = "Preparing your connection...";
    }
    /// <summary>Behavior flags for the web UI.</summary>
    public sealed class UiConfig
    {
        /// <summary>Gets or sets progress animation duration in milliseconds.</summary>
        public int ProgressAnimationDurationMs { get; set; } = 2000;
        /// <summary>Gets or sets whether the default host is selected automatically.</summary>
        public bool AutoSelectDefault { get; set; } = true;
        /// <summary>Gets or sets whether the user avatar is displayed.</summary>
        public bool ShowUserAvatar { get; set; } = true;
    }
    /// <summary>Theme colors used by the web UI.</summary>
    public sealed class ThemeConfig
    {
        /// <summary>Gets or sets the primary theme color.</summary>
        public string PrimaryColor { get; set; } = "#667eea";
        /// <summary>Gets or sets the secondary theme color.</summary>
        public string SecondaryColor { get; set; } = "#764ba2";
        /// <summary>Gets or sets the success color.</summary>
        public string SuccessColor { get; set; } = "#38b2ac";
        /// <summary>Gets or sets the error color.</summary>
        public string ErrorColor { get; set; } = "#c53030";
    }
}

/// <summary>
/// Handles web endpoints that list hosts, expose user info, serve assets, and generate RDP files.
/// </summary>
public sealed class Handler
{
    private readonly HostStore _hostStore;
    private readonly IBuilderService _builderService;
    private readonly bool _enableUserToken;
    private readonly QueryInfoFunc? _queryInfo;
    private readonly string _queryTokenIssuer;
    private readonly Uri _gatewayAddress;
    private readonly RdpOpts _rdpOpts;
    private readonly string _rdpDefaults;
    private readonly string _rdpSigningCert;
    private readonly string _rdpSigningKey;
    private readonly string _templatesPath;
    private readonly string _hostSelection;
    private readonly DestinationPolicy _destPolicy;
    private readonly WebConfig _webConfig = new();
    private readonly ILogger<Handler> _logger;

    /// <summary>Gets the UI configuration object consumed by Razor components.</summary>
    public WebConfig WebConfig => _webConfig;

    /// <summary>Initializes a new web handler from validated startup configuration.</summary>
    /// <param name="c">Handler configuration.</param>
    /// <param name="logger">Logger for request diagnostics.</param>
    public Handler(WebHandlerConfig c, ILogger<Handler> logger, HostStore hostStore, IBuilderService builderService)
    {
        _logger = logger;
        _hostStore = hostStore;
        _builderService = builderService;

        _enableUserToken = c.EnableUserToken;
        _queryInfo = c.QueryInfo;
        _queryTokenIssuer = c.QueryTokenIssuer;
        _gatewayAddress = c.GatewayAddress;
        _rdpOpts = c.RdpOpts;
        _rdpSigningCert = c.RdpSigningCert;
        _rdpSigningKey = c.RdpSigningKey;
        _templatesPath = string.IsNullOrEmpty(c.TemplatesPath) ? "./templates" : c.TemplatesPath;
        _hostSelection = c.HostSelection;
        _destPolicy = new DestinationPolicy(c.AllowedDestinationPorts, c.AllowPrivateDestinations);
    }

    /// <summary>Builds and returns a personalized RDP file for the authenticated user.</summary>
    /// <param name="ctx">Current HTTP context.</param>
    public async Task HandleDownload(HttpContext ctx)
    {
        var id = IdentityContext.FromContext(ctx) ?? new User();
        if (!id.Authenticated) { _logger.LogWarning("unauthenticated user {UserName}", id.UserName); ctx.Response.StatusCode = 500; await ctx.Response.WriteAsync("cannot find session or user"); return; }
        string host;
        try { host = await GetHost(ctx); }
        catch (Exception ex) { ctx.Response.StatusCode = 400; await ctx.Response.WriteAsync(ex.Message); return; }
        host = host.Replace("{{ preferred_username }}", id.UserName, StringComparison.Ordinal);
        
        var user = id.UserName;
        var domain = string.Empty;
        
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

        var entry = await _hostStore.FindByAddressAsync(host);
        if (entry is null) { ctx.Response.StatusCode = 400; await ctx.Response.WriteAsync("invalid host"); return; }

        string rdpFile;
        try
        {
            var clientIp = ctx.Connection.RemoteIpAddress?.ToString() ?? string.Empty;
            rdpFile = await _builderService.BuildRdpFile(clientIp, render, entry.Id);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to build RDP file for user {UserName} host {HostEntryId}", id.UserName, entry.Id);
            ctx.Response.StatusCode = 500;
            await ctx.Response.WriteAsync("failed to prepare RDP connection");
            return;
        }

        ctx.Response.ContentType = "application/x-rdp";
        ctx.Response.Headers.ContentDisposition = "attachment; filename=connection.rdp";
        await ctx.Response.WriteAsync(rdpFile);
    }

    /// <summary>Resolves the host destination for a request based on the configured host-selection mode.</summary>
    /// <param name="ctx">Current HTTP context.</param>
    /// <returns>The validated host or host:port destination.</returns>
    private Task<string> GetHost(HttpContext ctx) => _hostSelection switch
    {
        "signed" => GetSignedHost(ctx),
        "any" => GetAnyHost(ctx),
        _ => GetUnsignedHost(ctx),
    };

    /// <summary>Returns the host-picker model for a user.</summary>
    /// <param name="userName">Authenticated username.</param>
    /// <returns>Visible host options with exactly one default when possible.</returns>
    public async Task<List<Host>> GetHosts(string userName)
    {
        var entries = await _hostStore.GetVisible(userName);
        var hasDefault = entries.Any(h => h.IsDefault);
        return [.. entries.Select((h, i) => new Host($"host_{h.Id}", h.Name, h.Address, h.Description, hasDefault ? h.IsDefault : i == 0))];
    }

    /// <summary>Writes the authenticated user's host list as JSON.</summary>
    /// <param name="ctx">Current HTTP context.</param>
    public async Task HandleHostList(HttpContext ctx)
    {
        var id = IdentityContext.FromContext(ctx) ?? new User();
        if (!id.Authenticated) { ctx.Response.StatusCode = 401; await ctx.Response.WriteAsync("Unauthorized"); return; }
        ctx.Response.ContentType = "application/json";
        await JsonSerializer.SerializeAsync(ctx.Response.Body, await GetHosts(id.UserName), JsonOptions);
    }

    /// <summary>Writes basic information about the authenticated user as JSON.</summary>
    /// <param name="ctx">Current HTTP context.</param>
    public async Task HandleUserInfo(HttpContext ctx)
    {
        var id = IdentityContext.FromContext(ctx) ?? new User();
        if (!id.Authenticated) { ctx.Response.StatusCode = 401; await ctx.Response.WriteAsync("Unauthorized"); return; }
        ctx.Response.ContentType = "application/json";
        await JsonSerializer.SerializeAsync(ctx.Response.Body, new { username = id.UserName, authenticated = id.Authenticated, authTime = id.AuthTime });
    }

    /// <summary>Serves a static asset from known deployment-relative locations.</summary>
    /// <param name="ctx">Current HTTP context.</param>
    /// <param name="filename">Asset filename to serve.</param>
    public async Task ServeAssetFile(HttpContext ctx, string filename)
    {
        var candidates = new List<string> { "./assets/" + filename, "/app/assets/" + filename, "/opt/rdpgw/assets/" + filename, Path.Combine("assets", filename) };
        if (!string.IsNullOrEmpty(_templatesPath))
        {
            var current = Path.GetFullPath(_templatesPath);
            for (var i = 0; i < 5; i++) { current = Directory.GetParent(current)?.FullName ?? current; candidates.Add(Path.Combine(current, "assets", filename)); }
        }
        var found = candidates.FirstOrDefault(File.Exists);
        if (found is null) { _logger.LogWarning("Asset file not found: {FileName}. Tried paths: {Paths}", filename, string.Join(',', candidates)); ctx.Response.StatusCode = 404; return; }
        await ServeFile(ctx, found, filename);
    }

    private async Task ServeFile(HttpContext ctx, string path, string filename)
    {
        if (!File.Exists(path)) { ctx.Response.StatusCode = 404; return; }
        ctx.Response.ContentType = Path.GetExtension(filename).ToLowerInvariant() switch { ".css" => "text/css", ".js" => "application/javascript", ".svg" => "image/svg+xml", ".png" => "image/png", ".jpg" or ".jpeg" => "image/jpeg", _ => "application/octet-stream" };
        ctx.Response.Headers.CacheControl = "public, max-age=3600";
        await ctx.Response.SendFileAsync(path);
    }

    private static string UserFromContext(HttpContext ctx) => IdentityContext.FromContext(ctx)?.UserName ?? string.Empty;

    private async Task<string> GetSignedHost(HttpContext ctx)
    {
        var token = ctx.Request.Query["host"].FirstOrDefault();
        if (string.IsNullOrEmpty(token) || _queryInfo is null) throw new InvalidOperationException("invalid query parameter");
        var host = await _queryInfo(ctx, token, _queryTokenIssuer);
        if (!(await _hostStore.GetHostAddresses(UserFromContext(ctx))).Contains(host)) throw new InvalidOperationException("invalid host specified in query token");
        return host;
    }
    private async Task<string> GetUnsignedHost(HttpContext ctx)
    {
        var host = ctx.Request.Query["host"].FirstOrDefault();
        if (string.IsNullOrEmpty(host)) throw new InvalidOperationException("invalid query parameter");
        if (!(await _hostStore.GetHostAddresses(UserFromContext(ctx))).Contains(host)) throw new InvalidOperationException("invalid host specified in query parameter");
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
    /// <summary>Host option returned to the web UI.</summary>
    /// <param name="Id">Stable UI identifier.</param>
    /// <param name="Name">Display name.</param>
    /// <param name="Address">RDP destination address.</param>
    /// <param name="Description">Descriptive text.</param>
    /// <param name="IsDefault">Whether this host should be selected by default.</param>
    public sealed record Host(string Id, string Name, string Address, string Description, bool IsDefault);
    private sealed class DestinationPolicy(List<int> allowedPorts, bool allowPrivate)
    {
        private readonly HashSet<int> _allowedPorts = allowedPorts.Count == 0 ? [3389] : [.. allowedPorts];
        /// <summary>Validates that an arbitrary destination is allowed by port and address-range policy.</summary>
        /// <param name="hostport">Host or host:port destination requested by the user.</param>
        public async Task Allow(string hostport)
        {
            var host = hostport; var port = 3389;
            var m = Regex.Match(hostport, @"^\[(?<h>.+)\]:(?<p>\d+)$|^(?<h>[^:]+):(?<p>\d+)$");
            if (m.Success) { host = m.Groups["h"].Value; port = int.Parse(m.Groups["p"].Value); }
            if (!_allowedPorts.Contains(port)) throw new InvalidOperationException($"destination not allowed: port {port} not in allow-list");
            if (allowPrivate) return;
            IPAddress[] addrs = IPAddress.TryParse(host, out var ip) ? [ip] : await Dns.GetHostAddressesAsync(host);
            // Resolve hostnames before private-range checks so DNS rebinding to internal networks is blocked.
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
