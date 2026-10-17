// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Microsoft.Extensions.Logging;

namespace Abblix.Jwt.UnitTests;

/// <summary>
/// One record a <see cref="RecordingLogger{T}"/> received, with the values its message was formatted from.
/// </summary>
public sealed record Entry(LogLevel Level, int EventId, IReadOnlyList<KeyValuePair<string, object?>> State)
{
    public object? Value(string name) => State.Single(pair => pair.Key == name).Value;
}

/// <summary>
/// A logger that keeps what it was given, so a test asserts the event and its values rather than the message text.
/// </summary>
public sealed class RecordingLogger<T> : ILogger<T>
{
    private readonly List<Entry> _entries = [];

    public IReadOnlyList<Entry> Entries
    {
        get
        {
            lock (_entries)
                return [.. _entries];
        }
    }

    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

    public bool IsEnabled(LogLevel logLevel) => true;

    public void Log<TState>(
        LogLevel logLevel,
        EventId eventId,
        TState state,
        Exception? exception,
        Func<TState, Exception?, string> formatter)
    {
        var values = state as IReadOnlyList<KeyValuePair<string, object?>> ?? [];
        lock (_entries)
            _entries.Add(new Entry(logLevel, eventId.Id, values));
    }
}
