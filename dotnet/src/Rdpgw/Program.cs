using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Negotiate;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using MudBlazor.Services;
using Prometheus;
using Rdpgw.Components;
using Rdpgw.Config;
using Rdpgw.Data;
using Rdpgw.Gateway;
using Rdpgw.Protocol;
using Rdpgw.Security;
using Rdpgw.Security.GatewayToken;
using Rdpgw.Web;

var builder = WebApplication.CreateBuilder(args);

builder.Configuration.AddEnvironmentVariables("RDPGW_");

builder.Services
    .AddOptions<ServerConfig>()
    .BindConfiguration("Server")
    .ValidateDataAnnotations()
    .ValidateOnStart();
builder.Services
    .AddOptions<SecurityConfig>()
    .BindConfiguration("Security")
	.ValidateDataAnnotations()
	.ValidateOnStart();
builder.Services
	.AddOptions<CapsConfig>()
	.BindConfiguration("Caps")
	.ValidateDataAnnotations()
	.ValidateOnStart();
builder.Services
    .AddOptions<OpenIdConfig>()
	.BindConfiguration("OpenId")
	.ValidateDataAnnotations()
	.ValidateOnStart();
builder.Services
	.AddOptions<OrchestratorConfig>()
	.BindConfiguration("Orchestrator")
	.ValidateDataAnnotations()
	.ValidateOnStart();

//builder.Services.AddSingleton<IOptions<KerberosConfig>>(Options.Create(configuration.Kerberos));
//builder.Services.AddSingleton<IOptions<ClientConfig>>(Options.Create(configuration.Client));

var dbOptions = new DbContextOptionsBuilder<RdpgwDbContext>().UseSqlite($"Data Source=rdpgw.db").Options;
var dbFactory = new PooledDbContextFactory<RdpgwDbContext>(dbOptions);

builder.Services.AddTransient<HostStore>();
builder.Services.AddHttpClient<GatewayStore>();

builder.Services.AddTransient<ITokenService, TokenService>();
builder.Services.AddTransient<TokenService>();
builder.Services.AddTransient<ProcessorService>();
builder.Services.AddTransient<GatewayService>();
builder.Services.AddDbContext<RdpgwDbContext>(options => options.UseSqlite($"Data Source=rdpgw.db"));

builder.Services.AddMemoryCache();

builder.Services.AddSingleton<GatewayTokenReplayValidator>();
builder.Services.AddSingleton<GatewayRegistrationRateLimiter>();
builder.Services.AddSingleton<IGatewayAdoptionState, GatewayAdoptionState>();

builder.Services.AddHttpClient<JwksClient>();

builder.Services.AddHttpClient<GatewayRegistrationInitializer>();
builder.Services.AddHostedService<GatewayRegistrationInitializer>();

builder.Services.AddAuthentication(NegotiateDefaults.AuthenticationScheme).AddNegotiate();
builder.Services.AddAuthorization();

builder.Services.AddHttpContextAccessor();
builder.Services.AddRazorComponents().AddInteractiveServerComponents();
builder.Services.AddMudServices();
builder.WebHost.ConfigureKestrel(options =>
{
    //options.ListenAnyIP(configuration.Server.Port, listen =>
    //{
    //    listen.Protocols = HttpProtocols.Http1;
    //    if (configuration.Server.Tls == Configuration.TlsDisable)
    //    {
            
    //    }
    //    else if (!string.IsNullOrEmpty(configuration.Server.CertFile) && !string.IsNullOrEmpty(configuration.Server.KeyFile))
    //    {
    //        var cert = System.Security.Cryptography.X509Certificates.X509Certificate2.CreateFromPemFile(configuration.Server.CertFile, configuration.Server.KeyFile);
    //        listen.UseHttps(cert);
    //    }
    //    else
    //    {
    //        throw new InvalidOperationException("TLS requires certfile/keyfile in the .NET port");
    //    }
    //});
});


builder.Services.AddHttpContextAccessor();

builder.Services
    .AddAuthentication()
    .AddScheme<AuthenticationSchemeOptions, GatewayTokenAuthenticationHandler>("GatewayToken", options => { })
    .AddScheme<AuthenticationSchemeOptions, GatewayRegistrationAuthenticationHandler>(
        GatewayRegistrationAuthenticationHandler.SchemeName, options => { })
    .AddScheme<AuthenticationSchemeOptions, GatewayAdoptionAuthenticationHandler>(
        GatewayAdoptionAuthenticationHandler.SchemeName, options => { });

builder.Services
    .AddAuthorizationBuilder()
	.AddPolicy("GatewayLog", policy =>
		{
			policy.AddAuthenticationSchemes("GatewayToken");
			policy.RequireAuthenticatedUser();
            policy.RequireClaim("gatewayName");
		})
	.AddPolicy("GatewayRegister", policy =>
		{
			// Unregistered gateways authenticate with the pre-shared registration key.
			policy.AddAuthenticationSchemes(GatewayRegistrationAuthenticationHandler.SchemeName);
			policy.RequireAuthenticatedUser();
			policy.RequireClaim("gatewayName");
		})
	.AddPolicy("GatewayRegistrationStatus", policy =>
		{
			// A gateway may check its status before or after its key is known to us,
			// so both the registration key and its own signing key are accepted.
			policy.AddAuthenticationSchemes(
				GatewayRegistrationAuthenticationHandler.SchemeName,
				"GatewayToken");
			policy.RequireAuthenticatedUser();
			policy.RequireClaim("gatewayName");
		})
	.AddPolicy("GatewayRegisterOrAdopt", policy =>
		{
			// An orchestrator receives registration requests signed with the pre-shared
			// registration key; a gateway receives adoption notifications signed with
			// the orchestrator's message key (validated via its published JWKS).
			policy.AddAuthenticationSchemes(
				GatewayRegistrationAuthenticationHandler.SchemeName,
				GatewayAdoptionAuthenticationHandler.SchemeName);
			policy.RequireAuthenticatedUser();
			policy.RequireClaim("gatewayName");
		});

var app = builder.Build();

// Middleware order matters: WebSockets first for RDG_IN/OUT upgrades, authentication/authorization next,
// then rdpgw identity enrichment so later web and gateway handlers share the same request identity.
app.UseWebSockets();
app.UseAuthentication();
app.UseAuthorization();
#warning fix middleware enrichment
//app.Use(async (ctx, next) => await ContextMiddleware.EnrichContext(ctx, next));
app.UseAntiforgery();
app.UseMetricServer("/metrics");

//if (!string.IsNullOrEmpty(configuration.Server.PrimaryGateway))
//{
//    // Subservient gateway: PAA tokens are issued by the primary, so validate them
//    // against the primary's federation endpoint using the shared key. The token's
//    // remoteServer claim (checked by CheckSession) authorizes the target host.
//    log.LogInformation("running as subservient gateway; validating tokens against primary at {PrimaryGateway}", configuration.Server.PrimaryGateway);
//    var remoteValidator = new GatewayFederation.RemoteTokenValidator(new Uri(configuration.Server.PrimaryGateway), configuration.Security.GatewaySharedKey);
//    gw.CheckHost = Security.CheckSession((_, _) => Task.FromResult(true));
//}

bool kerberosEnabled = false;
var authMux = new AuthMux();

async Task WebAuth(HttpContext ctx, Func<Task> next)
{
    // Browser-facing routes use trusted-header sessions; gateway protocol auth is dispatched separately.
    // OIDC browser authentication is not implemented yet (see Web/Oidc.cs), so this is currently a pass-through.
    await next();
}

app.UseWhen(
    ctx => ctx.Request.Path == "/" || ctx.Request.Path.StartsWithSegments("/hosts") || ctx.Request.Path.StartsWithSegments("/gateways") || ctx.Request.Path.StartsWithSegments("/_blazor"),
    // Restrict web UI authentication middleware to browser routes so it does not interfere with RDP gateway verbs.
    branch => branch.Use(async (ctx, next) => await WebAuth(ctx, () => next(ctx))));



//app.Map("/callback", oidc.HandleCallback);
//app.Map("/connect", ctx => WebAuth(ctx, () => web.HandleDownload(ctx)));

app.MapRazorComponents<App>().AddInteractiveServerRenderMode();

app.MapStaticAssets();
app.MapControllers();

await app.RunAsync();
