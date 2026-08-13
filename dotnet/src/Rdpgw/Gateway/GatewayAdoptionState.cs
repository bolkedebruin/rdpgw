namespace Rdpgw.Gateway;

/// <summary>
/// Holds whether this gateway has been adopted by its orchestrator. Registered as a
/// singleton so any class resolved from DI can observe the current adoption state
/// without needing its own storage or database access.
/// </summary>
public interface IGatewayAdoptionState
{
	/// <summary>Gets whether the orchestrator has adopted this gateway.</summary>
	bool IsAdopted { get; }

	/// <summary>Sets the current adoption state.</summary>
	/// <param name="adopted"><see langword="true"/> when the orchestrator has adopted this gateway.</param>
	void SetAdopted(bool adopted);
}

/// <inheritdoc cref="IGatewayAdoptionState"/>
public sealed class GatewayAdoptionState : IGatewayAdoptionState
{
	private volatile bool _isAdopted;

	/// <inheritdoc />
	public bool IsAdopted => _isAdopted;

	/// <inheritdoc />
	public void SetAdopted(bool adopted) => _isAdopted = adopted;
}
