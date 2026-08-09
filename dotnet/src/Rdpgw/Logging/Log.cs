using Microsoft.Extensions.Logging.Abstractions;

namespace Rdpgw.Logging;

/// <summary>
/// Provides access to the application's ILoggerFactory for classes that are not
/// constructed through dependency injection (static helpers, config-built objects).
/// Program.cs assigns <see cref="Factory"/> right after the host is built.
/// </summary>
public static class Log
{
    /// <summary>Gets or sets the logger factory used by static and manually constructed components.</summary>
    public static ILoggerFactory Factory { get; set; } = NullLoggerFactory.Instance;

    /// <summary>Creates a logger whose category is the specified type.</summary>
    /// <typeparam name="T">Type to use as the logger category.</typeparam>
    /// <returns>An <see cref="ILogger"/> for <typeparamref name="T"/>.</returns>
    public static ILogger For<T>() => Factory.CreateLogger<T>();

    /// <summary>Creates a logger whose category is the specified runtime type.</summary>
    /// <param name="type">Type to use as the logger category.</param>
    /// <returns>An <see cref="ILogger"/> for <paramref name="type"/>.</returns>
    public static ILogger For(Type type) => Factory.CreateLogger(type);

    /// <summary>Creates a logger for an explicit category name.</summary>
    /// <param name="category">Logger category name.</param>
    /// <returns>An <see cref="ILogger"/> for <paramref name="category"/>.</returns>
    public static ILogger For(string category) => Factory.CreateLogger(category);
}
