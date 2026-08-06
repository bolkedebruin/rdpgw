using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace Rdpgw.Auth.Config;

public sealed class Configuration
{
    public List<UserConfig> Users { get; set; } = [];

    public static Configuration Load(string configFile)
    {
        if (!File.Exists(configFile))
        {
            Console.Error.WriteLine($"Config file {configFile} not found, skipping config file");
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
