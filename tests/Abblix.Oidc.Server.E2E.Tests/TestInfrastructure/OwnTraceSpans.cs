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

namespace Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;

/// <summary>
/// Keeps the finished spans of one trace. A tracer provider listens to a source by name across the process, so the
/// spans of tests running alongside reach it too and are left out here.
/// </summary>
/// <param name="trace">The trace whose spans are kept.</param>
public sealed class OwnTraceSpans(ActivityTraceId trace) : BaseProcessor<Activity>
{
    private readonly ConcurrentQueue<Activity> _spans = new();

    /// <summary>
    /// The spans of the trace finished so far.
    /// </summary>
    public IReadOnlyList<Activity> Spans => _spans.ToArray();

    /// <inheritdoc />
    public override void OnEnd(Activity data)
    {
        if (data.TraceId == trace)
            _spans.Enqueue(data);
    }
}
