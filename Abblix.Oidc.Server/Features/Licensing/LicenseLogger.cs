// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
// 
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
// 
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
// 
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
// 
// For full licensing terms, please visit:
// 
// https://oidc.abblix.com/license
// 
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
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

    [SuppressMessage("CodeQuality", "IDE0052:Remove unread private members", Justification = "Timer must be kept alive to prevent garbage collection")]
    [SuppressMessage("SonarLint", "S4487:Unread private fields should be removed", Justification = "Timer must be kept alive to prevent garbage collection")]
    private readonly Timer _timer;

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
