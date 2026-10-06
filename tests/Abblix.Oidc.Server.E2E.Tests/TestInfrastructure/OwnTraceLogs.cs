// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Collections.Concurrent;
using System.Diagnostics;
using OpenTelemetry;
using OpenTelemetry.Logs;

namespace Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;

/// <summary>
/// Keeps the records logged under one trace, each copied as it ends, since the logging bridge reuses a record once
/// its processors have seen it.
/// </summary>
/// <param name="trace">The trace whose records are kept.</param>
public sealed class OwnTraceLogs(ActivityTraceId trace) : BaseProcessor<LogRecord>
{
    private readonly ConcurrentQueue<(ActivitySpanId SpanId, KeyValuePair<string, object?>[] Attributes)> _records = new();

    /// <summary>
    /// The span each record was logged under, and its attributes.
    /// </summary>
    public IReadOnlyList<(ActivitySpanId SpanId, KeyValuePair<string, object?>[] Attributes)> Records => _records.ToArray();

    /// <inheritdoc />
    public override void OnEnd(LogRecord data)
    {
        if (data.TraceId == trace)
            _records.Enqueue((data.SpanId, data.Attributes?.ToArray() ?? []));
    }
}
