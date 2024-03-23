// Abblix OpenID Connect Server Library
// Copyright (c) 2024 by Abblix LLP
// 
// This software is provided 'as-is', without any express or implied warranty. In no
// event will the authors be held liable for any damages arising from the use of this
// software.
// 
// Permitted Use: This software is open for use and extension by non-profit,
// educational and community projects under the condition that it remains unmodified
// and used in its entirety through official Nuget packages. Any unauthorized
// modification, forking of the whole repository, or altering individual files is
// strictly prohibited to ensure development occurs solely within the official Abblix LLP
// repository.
// 
// Prohibited Actions: Redistribution, modification, incorporation of this software or
// any part thereof into other products, and creation of derivative works are not
// permitted without obtaining a commercial license from Abblix LLP.
// 
// Commercial Use: A separate license is required for commercial use, including
// functionalities extended beyond the original software. For information on obtaining
// a commercial license, please contact Abblix LLP.
// 
// Enforcement: Unauthorized redistribution, modification, or use of this software in
// other projects or products is strictly prohibited without prior written permission
// from the copyright holder. Violations may be subject to legal action.
// 
// For more information, please refer to the license agreement located at:
// https://github.com/Abblix/Oidc.Server/blob/master/README.md

using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Abblix.Oidc.Server.Features.Licensing;

/// <summary>
/// A specialized logger for licensing checks, extending the standard logging functionality to include
/// throttling capabilities for repetitive log messages.
/// </summary>
internal class LicenseLogger: ILogger
{
    private LicenseLogger()
    {
        var dictionary = new ConcurrentDictionary<object, DateTimeOffset>();

        _timer = new Timer(state =>
            {
                var dict = (ConcurrentDictionary<object, DateTimeOffset>)state!;
                var utcNow = DateTimeOffset.UtcNow;
                foreach (var item in dict)
                {
                    if (item.Value < utcNow)
                        dict.TryRemove(item.Key, out _);
                }
            },
            dictionary,
            TimeSpan.FromMinutes(1),
            TimeSpan.FromMinutes(1));

        _nextAllowedTimes = dictionary;
    }

    public static LicenseLogger Instance { get; } = new();

    /// <summary>
    /// Logs a message if the specified conditions are met, implementing throttling to prevent excessive logging
    /// of similar messages.
    /// </summary>
    /// <typeparam name="TState">The type of the object to log.</typeparam>
    /// <param name="logLevel">The severity level of the log message.</param>
    /// <param name="eventId">The event ID of the log message.</param>
    /// <param name="state">The state related to the log message.</param>
    /// <param name="exception">The exception related to the log message, if any.</param>
    /// <param name="formatter">A function to create a string message from the state and exception.</param>
    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        => _logger.Log(logLevel, eventId, state, exception, formatter);

    /// <summary>
    /// Checks if logging at the specified log level is enabled.
    /// </summary>
    /// <param name="logLevel">The log level to check.</param>
    /// <returns>True if logging is enabled at the specified log level; otherwise, false.</returns>
    public bool IsEnabled(LogLevel logLevel)
        => _logger.IsEnabled(logLevel);

    /// <summary>
    /// Begins a logical operation scope.
    /// </summary>
    /// <typeparam name="TState">The type of the state for the scope.</typeparam>
    /// <param name="state">The state for the new scope.</param>
    /// <returns>An IDisposable representing the scope.</returns>
    public IDisposable? BeginScope<TState>(TState state) where TState : notnull
        => _logger.BeginScope(state);

    private const string LoggerName = "Abblix.Oidc.Server";
    private ILogger _logger = NullLogger.Instance;
    private readonly ConcurrentDictionary<object, DateTimeOffset> _nextAllowedTimes;
    private Timer _timer;

    /// <summary>
    /// Initializes the logger with a specific logger factory.
    /// </summary>
    /// <param name="loggerFactory">The factory used to create the underlying logger instance.</param>
    internal void Init(ILoggerFactory loggerFactory) => _logger = loggerFactory.CreateLogger(LoggerName);

    /// <summary>
    /// Determines whether a log write operation is allowed based on the specified key and period.
    /// </summary>
    /// <param name="key">The key identifying the log operation, used to prevent repetitive logging of similar messages.</param>
    /// <param name="utcNow">The current UTC time, used to calculate the time elapsed since the last log write.</param>
    /// <param name="period">The period within which repetitive log messages are throttled.</param>
    /// <returns>True if the log write operation is allowed; otherwise, false.</returns>
    /// <remarks>
    /// This method helps to throttle logging by allowing log messages to be written only if a specified period has elapsed
    /// since the last log write for a given key. This prevents flooding the log with repetitive messages.
    /// </remarks>
    public bool IsAllowed(object key, DateTimeOffset utcNow, TimeSpan period)
    {
        var newTime = utcNow + period;
        if (_nextAllowedTimes.TryAdd(key, newTime))
        {
            return true;
        }

        if (_nextAllowedTimes.TryGetValue(key, out var nextAllowedTime) && nextAllowedTime < utcNow &&
            _nextAllowedTimes.TryUpdate(key, newTime, nextAllowedTime))
        {
            return true;
        }

        return false;
    }
}
