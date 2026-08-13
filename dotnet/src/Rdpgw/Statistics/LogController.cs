using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Rdpgw.Data;
using Rdpgw.Security;

namespace Rdpgw.Statistics;

/// <summary>
/// API endpoints for gateway statistics and logging.
/// </summary>
[ApiController]
[Route("api/log")]
public sealed partial class LogController(ILogger<LogController> logger, RdpgwDbContext dbContext, TokenService tokenService) : ControllerBase
{
	[HttpPost]
	[Authorize(Policy = "GatewayLog")]
	public async Task<IActionResult> PostLogAsync([FromBody] LogDto logDto, CancellationToken cancellationToken = default)
	{
		var gatewayName = User.Identity?.Name;
		if (string.IsNullOrWhiteSpace(gatewayName))
		{
			logger.LogError("Gateway identity is null or empty. Validation of this property should have occured in the authentication handler.");
			return Unauthorized(new { error = "Gateway identity is null or empty" });
		}

		try
		{
			// Validate the DTO
			logDto.Validate();
		}
		catch (Exception ex)
		{
			logger.LogError(ex, "Validation failed for log DTO");
			return BadRequest(new { error = "Validation failed for log DTO" });
		}

		// Authorization and authentication middleware has already validated the token
		// Look up the gateway by name and insert the log entry into the database
		var gateway = await dbContext.Gateways
			.FirstOrDefaultAsync(g => g.Name == gatewayName, cancellationToken);

		if (gateway == null)
		{
			logger.LogError("Gateway '{GatewayName}' not found in the database", gatewayName);
			return Unauthorized(new { error = $"Gateway '{gatewayName}' not found" });
		}

		try
		{
			var logEntry = new LogEntry
			{
				GatewayId = gateway.Id,
				Timestamp = logDto.Timestamp,
				LogMessage = logDto.LogMessage
			};
			dbContext.Logs.Add(logEntry);
			await dbContext.SaveChangesAsync(cancellationToken);

			return Ok(new
			{
				message = "Log entry created successfully",
				id = logEntry.Id,
				gatewayId = gateway.Id
			});
		}
		catch (Exception ex)
		{
			logger.LogError(ex, "Error saving log entry");
			return StatusCode(500, new { error = "Error saving log entry" });
		}
	}
}
