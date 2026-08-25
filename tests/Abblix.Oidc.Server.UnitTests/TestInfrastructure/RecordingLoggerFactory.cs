// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Collections.Generic;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.UnitTests.TestInfrastructure;

/// <summary>What a single log write carried.</summary>
internal sealed record LogRecord(LogLevel Level, EventId EventId, string Message);

/// <summary>
/// A factory whose loggers keep what was written, so a test can assert on the record itself.
/// </summary>
/// <remarks>
/// Shared because a record is the only observable a decision taken in a log leaves behind. Where the
/// product reports rather than returns - a licence limit refused, a licence expired - asserting that the
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
            => entries.Add(new LogRecord(logLevel, eventId, formatter(state, exception)));
    }
}
