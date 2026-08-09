using Microsoft.Extensions.Logging.Abstractions;

namespace Rdpgw.Logging;

/// <summary>
/// Provides access to the application's ILoggerFactory for classes that are not
/// constructed through dependency injection (static helpers, config-built objects).
/// Program.cs assigns <see cref="Factory"/> right after the host is built.
/// </summary>
public static class Log
{
    public static ILoggerFactory Factory { get; set; } = NullLoggerFactory.Instance;

    public static ILogger For<T>() => Factory.CreateLogger<T>();

    public static ILogger For(Type type) => Factory.CreateLogger(type);

    public static ILogger For(string category) => Factory.CreateLogger(category);
}
