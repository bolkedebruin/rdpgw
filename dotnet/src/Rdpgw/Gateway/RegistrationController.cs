using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Rdpgw.Data;
using Rdpgw.Security.GatewayToken;

namespace Rdpgw.Gateway;

/// <summary>
/// API endpoints used by gateways to register with the orchestrator node and to
/// query the status of an existing registration request. The POST verb also handles
/// an incoming adoption notification from the orchestrator; which behavior applies is
/// determined by which authentication scheme actually validated the request (see
/// <see cref="PostRegistrationAsync"/>), not by local server configuration, since only
/// the authentication result is cryptographic proof of which party sent the request.
/// </summary>
[ApiController]
[Route("api/gateway/register")]
public sealed class RegistrationController(
	ILogger<RegistrationController> logger,
	RdpgwDbContext dbContext,
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
	/// Creates a pending registration request for the calling gateway, or accepts the
	/// orchestrator's notification that this gateway has been adopted. Which behavior
	/// applies is determined by which authentication scheme actually validated the
	/// request: the two schemes attached to the "GatewayRegisterOrAdopt" policy each
	/// prove a distinct claim (possession of the pre-shared registration key, or a
	/// signature from the orchestrator's own message key). Branching on that proof,
	/// rather than on this node's local <c>ServerConfig.Mode</c>, means a request can
	/// never be routed to the wrong handler just because a node is misconfigured or
	/// running in an unexpected mode.
	/// </summary>
	[HttpPost]
	[Authorize(Policy = "GatewayRegisterOrAdopt")]
	public Task<IActionResult> PostRegistrationAsync(CancellationToken cancellationToken = default)
	{
		var authenticationType = User.Identity?.AuthenticationType;

		if (string.Equals(authenticationType, GatewayAdoptionAuthenticationHandler.SchemeName, StringComparison.Ordinal))
		{
			return PostAdoptionNotificationAsync();
		}

		if (string.Equals(authenticationType, GatewayRegistrationAuthenticationHandler.SchemeName, StringComparison.Ordinal))
		{
			return PostRegistrationRequestAsync(cancellationToken);
		}

		logger.LogError("Unexpected authentication scheme '{AuthenticationType}' on gateway register/adopt request.", authenticationType);
		return Task.FromResult<IActionResult>(Unauthorized(new { error = "Unrecognized authentication scheme" }));
	}

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
