// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Collections;
using System.Collections.Concurrent;
using System.Diagnostics;
using Microsoft.Extensions.Logging;
using OpenTelemetry;
using OpenTelemetry.Logs;

namespace Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;

/// <summary>
/// Keeps the records logged under one trace with their event id, level and attributes, copied as each ends, since the
/// logging bridge reuses a record once its processors have seen it.
/// </summary>
/// <param name="trace">The trace whose records are kept.</param>
public sealed class OwnTraceEvents(ActivityTraceId trace) : BaseProcessor<LogRecord>
{
    private readonly ConcurrentQueue<Event> _events = new();

    /// <summary>
    /// A record as a sink receives it: its event id, its level, and each attribute as the text it is written as, the
    /// items of a list joined by a space; an attribute written as absent is null.
    /// </summary>
    public sealed record Event(int EventId, LogLevel Level, IReadOnlyDictionary<string, string?> Attributes);

    /// <summary>
    /// The records kept, in the order they ended.
    /// </summary>
    public IReadOnlyList<Event> Events => _events.ToArray();

    /// <summary>
    /// The records kept under <paramref name="eventId"/>.
    /// </summary>
    public Event[] Of(int eventId) => Events.Where(record => record.EventId == eventId).ToArray();

    /// <inheritdoc />
    public override void OnEnd(LogRecord data)
    {
        if (data.TraceId != trace)
            return;

        var attributes = (data.Attributes ?? []).ToDictionary(
            pair => pair.Key,
            pair => pair.Value is IEnumerable list and not string
                ? string.Join(' ', list.Cast<object?>().Select(item => item?.ToString()))
                : pair.Value?.ToString());

        _events.Enqueue(new Event(data.EventId.Id, data.LogLevel, attributes));
    }
}
