namespace Rdpgw.Config;

public class OrchestratorConfig
{
	public string OrchestratorAddress { get; set; } = string.Empty;

	/// <summary>
	/// How often, in seconds, a gateway re-checks its registration status with the
	/// orchestrator. This covers both recovery (retrying registration after a failed
	/// or interrupted attempt) and revocation detection (noticing it has been removed
	/// from the orchestrator's gateway list). Defaults to 60 seconds.
	/// </summary>
	public int RegistrationPollIntervalSeconds { get; set; } = 60;
}
