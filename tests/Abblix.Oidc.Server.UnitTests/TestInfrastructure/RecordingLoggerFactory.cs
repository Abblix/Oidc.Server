// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.UnitTests.TestInfrastructure;

/// <summary>What a single log write carried.</summary>
/// <remarks>
/// The EXCEPTION is kept as well as the formatted message, because they are two channels and a sink
/// renders both. A recorder that kept only the message made every assertion about what a log line does
/// NOT contain blind to whatever the exception carried - and a store's own fault routinely quotes the
/// key it failed on.
/// </remarks>
internal sealed record LogRecord(
    LogLevel Level,
    EventId EventId,
    string Message,
    Exception? Exception = null,
    IReadOnlyList<KeyValuePair<string, object?>>? State = null)
{
    /// <summary>
    /// What the record carries under one of its named values, or null when it carries none of that name.
    /// </summary>
    /// <remarks>
    /// A name read here is the one a structured sink writes, which the formatted message cannot tell from
    /// the same text arriving in another field.
    /// </remarks>
    public object? Value(string name)
        => State?.FirstOrDefault(pair => pair.Key == name).Value;

    /// <summary>
    /// Whether the record names a value at all, which a null value cannot answer.
    /// </summary>
    public bool Names(string name) => State?.Any(pair => pair.Key == name) == true;
}

/// <summary>
/// A factory whose loggers keep what was written, so a test can assert on the record itself.
/// </summary>
/// <remarks>
/// Shared because a record is the only observable a decision taken in a log leaves behind. Where the
/// product reports rather than returns - a license limit refused, a license expired - asserting that the
/// decision happened means asserting the write, and a test without a recorder can only observe silence,
/// which is what an unreported decision looks like too.
/// </remarks>
internal sealed class RecordingLoggerFactory : ILoggerFactory
{
    public List<LogRecord> Entries { get; } = [];

    public ILogger CreateLogger(string categoryName) => new RecordingLogger(Entries);

    public void AddProvider(ILoggerProvider provider)
    {
    }

    public void Dispose()
    {
    }

    private sealed class RecordingLogger(List<LogRecord> entries) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
            => entries.Add(
                new LogRecord(
                    logLevel,
                    eventId,
                    formatter(state, exception),
                    exception,
                    state as IReadOnlyList<KeyValuePair<string, object?>>));
    }
}
