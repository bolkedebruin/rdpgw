using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Rdpgw.Config;
using Rdpgw.Data;
using Rdpgw.Security.GatewayToken;

namespace Rdpgw.Gateway;

/// <summary>
/// API endpoints used by gateways to register with the orchestrator node and to
/// query the status of an existing registration request. In <see cref="ServerMode.Gateway"/>
/// the POST verb instead handles an incoming adoption notification from the orchestrator.
/// </summary>
[ApiController]
[Route("api/gateway/register")]
public sealed class RegistrationController(
	ILogger<RegistrationController> logger,
	RdpgwDbContext dbContext,
	IOptions<ServerConfig> serverConfig,
	IGatewayAdoptionState adoptionState) : ControllerBase
{
	private const int NotRegistered = 0;
	private const int RegistrationPending = 1;
	private const int RegistrationComplete = 2;

	/// <summary>Returns the registration status of the calling gateway.</summary>
	[HttpGet]
	[Authorize(Policy = "GatewayRegistrationStatus")]
	public async Task<IActionResult> GetRegistrationStatusAsync(CancellationToken cancellationToken = default)
	{
		var gatewayName = User.Identity?.Name;
		if (string.IsNullOrWhiteSpace(gatewayName))
		{
			logger.LogError("Gateway identity is null or empty. Validation of this property should have occured in the authentication handler.");
			return Unauthorized(new { error = "Gateway identity is null or empty" });
		}

		var isRegistered = await dbContext.Gateways
			.AsNoTracking()
			.AnyAsync(g => g.Name == gatewayName, cancellationToken);

		if (isRegistered)
		{
			return Ok(new GatewayRegistrationDto { RegistrationStatus = RegistrationComplete });
		}

		var isPending = await dbContext.PendingGateways
			.AsNoTracking()
			.AnyAsync(g => g.Name == gatewayName, cancellationToken);

		return Ok(new GatewayRegistrationDto
		{
			RegistrationStatus = isPending ? RegistrationPending : NotRegistered
		});
	}

	/// <summary>
	/// Creates a pending registration request for the calling gateway (orchestrator mode),
	/// or accepts the orchestrator's notification that this gateway has been adopted (gateway mode).
	/// </summary>
	[HttpPost]
	[Authorize(Policy = "GatewayRegisterOrAdopt")]
	public Task<IActionResult> PostRegistrationAsync(CancellationToken cancellationToken = default) =>
		serverConfig.Value.Mode == ServerMode.Gateway
			? PostAdoptionNotificationAsync()
			: PostRegistrationRequestAsync(cancellationToken);

	/// <summary>Orchestrator-side handling: records a pending registration request for the calling gateway.</summary>
	private async Task<IActionResult> PostRegistrationRequestAsync(CancellationToken cancellationToken)
	{
		var gatewayName = User.Identity?.Name;
		if (string.IsNullOrWhiteSpace(gatewayName))
		{
			logger.LogError("Gateway identity is null or empty. Validation of this property should have occured in the authentication handler.");
			return Unauthorized(new { error = "Gateway identity is null or empty" });
		}

		var isRegistered = await dbContext.Gateways
			.AsNoTracking()
			.AnyAsync(g => g.Name == gatewayName, cancellationToken);

		if (isRegistered)
		{
			return Ok(new GatewayRegistrationDto { RegistrationStatus = RegistrationComplete });
		}

		var isPending = await dbContext.PendingGateways
			.AsNoTracking()
			.AnyAsync(g => g.Name == gatewayName, cancellationToken);

		if (isPending)
		{
			return Ok(new GatewayRegistrationDto { RegistrationStatus = RegistrationPending });
		}

		try
		{
			// The gateway names itself using its own configured host address (see
			// GatewayRegistrationInitializer), so the same value is used to fetch its
			// JWKS document on adoption; it is signed as part of the registration
			// token's claims, so it is trusted to the same degree as the token itself.
			dbContext.PendingGateways.Add(new PendingGatewayEntry { Name = gatewayName });
			await dbContext.SaveChangesAsync(cancellationToken);
		}
		catch (Exception ex)
		{
			logger.LogError(ex, "Error saving pending registration for gateway '{GatewayName}'", gatewayName);
			return StatusCode(500, new { error = "Error saving pending registration" });
		}

		return Ok(new GatewayRegistrationDto { RegistrationStatus = RegistrationPending });
	}

	/// <summary>Gateway-side handling: accepts the orchestrator's adoption notification.</summary>
	private Task<IActionResult> PostAdoptionNotificationAsync()
	{
		var gatewayName = User.Identity?.Name;
		if (string.IsNullOrWhiteSpace(gatewayName))
		{
			logger.LogError("Adoption notification is missing a gatewayName claim. Validation of this property should have occured in the authentication handler.");
			return Task.FromResult<IActionResult>(Unauthorized(new { error = "Adoption notification is missing a gateway name" }));
		}

		adoptionState.SetAdopted(true);
		logger.LogInformation("gateway adoption notification accepted for '{GatewayName}'", gatewayName);

		return Task.FromResult<IActionResult>(Ok(new GatewayRegistrationDto { RegistrationStatus = RegistrationComplete }));
	}
}
