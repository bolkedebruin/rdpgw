using Microsoft.Extensions.Logging;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace Rdpgw.Auth.Config;

/// <summary>
/// Root YAML configuration for the authentication sidecar.
/// </summary>
public sealed class Configuration
{
    /// <summary>
    /// Gets or sets users whose passwords are available to local password and NTLM authentication.
    /// </summary>
    public List<UserConfig> Users { get; set; } = [];

    /// <summary>
    /// Loads the authentication sidecar configuration from a YAML file.
    /// </summary>
    /// <param name="configFile">Path to the YAML configuration file.</param>
    /// <param name="logger">Logger used to report missing optional configuration.</param>
    /// <returns>The parsed configuration, or an empty configuration when the file is missing or empty.</returns>
    public static Configuration Load(string configFile, ILogger logger)
    {
        if (!File.Exists(configFile))
        {
            logger.LogWarning("Config file {ConfigFile} not found, skipping config file", configFile);
            return new Configuration();
        }

        var deserializer = new DeserializerBuilder()
            .WithNamingConvention(CamelCaseNamingConvention.Instance)
            .IgnoreUnmatchedProperties()
            .Build();

        using var reader = File.OpenText(configFile);
        // Treat an empty YAML document the same as an absent user list.
        return deserializer.Deserialize<Configuration>(reader) ?? new Configuration();
    }
}
