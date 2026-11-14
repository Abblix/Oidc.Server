// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.MultiTenancy.E2E.Tests;

/// <summary>
/// Keeps the level and message of every entry logged, so a test can tell whether anything was logged as an error.
/// </summary>
internal sealed class LevelRecordingLoggerProvider : ILoggerProvider
{
    /// <summary>
    /// Every entry logged, with its level and message.
    /// </summary>
    public ConcurrentQueue<(LogLevel Level, string Message)> Entries { get; } = new();

    /// <inheritdoc />
    public ILogger CreateLogger(string categoryName) => new Recorder(Entries);

    /// <inheritdoc />
    public void Dispose()
    {
        // Nothing is held
    }

    private sealed class Recorder(ConcurrentQueue<(LogLevel Level, string Message)> entries) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
            => entries.Enqueue((logLevel, formatter(state, exception)));
    }
}
