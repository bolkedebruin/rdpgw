using Microsoft.Extensions.Logging;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace Rdpgw.Auth.Config;

public sealed class Configuration
{
    public List<UserConfig> Users { get; set; } = [];

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
        return deserializer.Deserialize<Configuration>(reader) ?? new Configuration();
    }
}
