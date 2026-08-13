using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.Extensions.Options;
using Rdpgw.Config;
using Rdpgw.Data;
using Rdpgw.Security;

namespace Rdpgw.Gateway;

/// <summary>
/// Hosted service that, when running in <see cref="ServerMode.Gateway"/>, periodically
/// checks this gateway's registration status with the configured orchestrator. It
/// registers itself if it is not yet registered or pending (this also covers recovery
/// from a failed or interrupted registration/adoption attempt), and clears the local
/// adoption state if the orchestrator no longer reports it as registered (covering
/// revocation: an administrator removing the gateway from the orchestrator). Runs an
/// initial check immediately at startup, then repeats on
/// <see cref="OrchestratorConfig.RegistrationPollIntervalSeconds"/>.
/// </summary>
public sealed class GatewayRegistrationInitializer(
	HttpClient httpClient,
	IOptions<ServerConfig> serverConfig,
	IOptions<OrchestratorConfig> orchestratorConfig,
	ITokenService tokenService,
	IGatewayAdoptionState adoptionState,
	ILogger<GatewayRegistrationInitializer> logger) : BackgroundService
{
	private const int NotRegistered = 0;
	private const int RegistrationPending = 1;
	private const int RegistrationComplete = 2;

	private static readonly JsonSerializerOptions JsonOptions = new()
	{
		PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
		PropertyNameCaseInsensitive = true,
	};

	/// <inheritdoc />
	protected override async Task ExecuteAsync(CancellationToken stoppingToken)
	{
		if (serverConfig.Value.Mode != ServerMode.Gateway)
		{
			// Orchestrators don't register with anyone.
			return;
		}

		var orchestratorAddress = orchestratorConfig.Value.OrchestratorAddress;
		if (string.IsNullOrWhiteSpace(orchestratorAddress))
		{
			logger.LogError("running in gateway mode but no orchestrator address is configured; skipping self-registration");
			return;
		}

		var gatewayName = serverConfig.Value.GatewayAddress;
		if (string.IsNullOrWhiteSpace(gatewayName))
		{
			logger.LogError("running in gateway mode but no gateway address is configured; skipping self-registration");
			return;
		}

		var registerUri = new Uri(new Uri(orchestratorAddress), "api/gateway/register");
		var pollInterval = TimeSpan.FromSeconds(Math.Max(1, orchestratorConfig.Value.RegistrationPollIntervalSeconds));

		// Run an initial check immediately, then continue on the configured interval.
		using var timer = new PeriodicTimer(pollInterval);
		do
		{
			await CheckAndRegisterAsync(registerUri, gatewayName, orchestratorAddress, stoppingToken);
		}
		while (await timer.WaitForNextTickAsync(stoppingToken));
	}

	private async Task CheckAndRegisterAsync(Uri registerUri, string gatewayName, string orchestratorAddress, CancellationToken cancellationToken)
	{
		try
		{
			var status = await GetRegistrationStatusAsync(registerUri, gatewayName, cancellationToken);
			if (status is null)
			{
				return;
			}

			switch (status.RegistrationStatus)
			{
				case RegistrationComplete:
					adoptionState.SetAdopted(true);
					logger.LogInformation("gateway '{GatewayName}' is registered with orchestrator {OrchestratorAddress}", gatewayName, orchestratorAddress);
					return;
				case RegistrationPending:
					// Not yet approved; clear any previously-set adoption state in case
					// this follows a revocation (see NotRegistered below).
					adoptionState.SetAdopted(false);
					logger.LogInformation("gateway '{GatewayName}' registration is pending with orchestrator {OrchestratorAddress}", gatewayName, orchestratorAddress);
					return;
				case NotRegistered:
					// Covers both "never registered" and "was registered, then revoked":
					// either way, the gateway is not currently adopted and should register.
					adoptionState.SetAdopted(false);
					await RegisterAsync(registerUri, gatewayName, orchestratorAddress, cancellationToken);
					return;
				default:
					logger.LogWarning("orchestrator returned unexpected registration status {RegistrationStatus} for gateway '{GatewayName}'", status.RegistrationStatus, gatewayName);
					return;
			}
		}
		catch (Exception ex) when (ex is not OperationCanceledException)
		{
			// Failure to reach the orchestrator should not stop the polling loop; the
			// next tick will retry.
			logger.LogError(ex, "failed to check or perform self-registration with orchestrator {OrchestratorAddress}", orchestratorAddress);
		}
	}

	private async Task<GatewayRegistrationDto?> GetRegistrationStatusAsync(Uri registerUri, string gatewayName, CancellationToken cancellationToken)
	{
		var token = await tokenService.GenerateRegistrationToken(gatewayName);

		using var request = new HttpRequestMessage(HttpMethod.Get, registerUri);
		request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

		using var response = await httpClient.SendAsync(request, cancellationToken);
		if (!response.IsSuccessStatusCode)
		{
			logger.LogError("orchestrator returned {StatusCode} while checking registration status for gateway '{GatewayName}'", (int)response.StatusCode, gatewayName);
			return null;
		}

		var dto = await JsonSerializer.DeserializeAsync<GatewayRegistrationDto>(await response.Content.ReadAsStreamAsync(cancellationToken), JsonOptions, cancellationToken);
		if (dto is null)
		{
			logger.LogError("orchestrator returned an empty registration status response for gateway '{GatewayName}'", gatewayName);
		}

		return dto;
	}

	private async Task RegisterAsync(Uri registerUri, string gatewayName, string orchestratorAddress, CancellationToken cancellationToken)
	{
		var token = await tokenService.GenerateRegistrationToken(gatewayName);

		using var request = new HttpRequestMessage(HttpMethod.Post, registerUri);
		request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

		using var response = await httpClient.SendAsync(request, cancellationToken);
		if (!response.IsSuccessStatusCode)
		{
			logger.LogError("orchestrator returned {StatusCode} while registering gateway '{GatewayName}'", (int)response.StatusCode, gatewayName);
			return;
		}

		logger.LogInformation("gateway '{GatewayName}' submitted registration request to orchestrator {OrchestratorAddress}", gatewayName, orchestratorAddress);
	}
}
