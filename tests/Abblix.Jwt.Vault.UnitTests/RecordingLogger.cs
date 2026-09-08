// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.Logging;

namespace Abblix.Jwt.Vault.UnitTests;

/// <summary>
/// Keeps what was logged, so a test can assert on the line an operator will read. A message that nobody checks
/// is a promise, and this suite has one claim that only a log can carry: that a failure names the custodian and
/// says whether waiting helps.
/// </summary>
internal sealed class RecordingLogger<T> : ILogger<T>
{
    private readonly List<(LogLevel Level, int EventId, string Message)> _entries = [];

    public IReadOnlyList<(LogLevel Level, int EventId, string Message)> Entries => _entries;

    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

    public bool IsEnabled(LogLevel logLevel) => true;

    public void Log<TState>(
        LogLevel logLevel,
        EventId eventId,
        TState state,
        Exception? exception,
        Func<TState, Exception?, string> formatter)
        => _entries.Add((logLevel, eventId.Id, formatter(state, exception)));
}
