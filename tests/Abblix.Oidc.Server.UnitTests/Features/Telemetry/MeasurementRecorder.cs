// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics.Metrics;
using System.Linq;
using Abblix.Oidc.Server.Features.Telemetry;

namespace Abblix.Oidc.Server.UnitTests.Features.Telemetry;

/// <summary>
/// Records what the server's instruments measure, from the meters of one factory only, so tests running in
/// parallel do not see each other's measurements.
/// </summary>
internal sealed class MeasurementRecorder : IDisposable
{
    private readonly MeterListener _listener = new();
    private readonly ConcurrentQueue<(string Instrument, double Value, Dictionary<string, object?> Tags)> _recorded = new();

    public MeasurementRecorder(IMeterFactory factory)
    {
        _listener.InstrumentPublished = (instrument, listener) =>
        {
            if (instrument.Meter.Name == OidcTelemetry.SourceName && ReferenceEquals(instrument.Meter.Scope, factory))
                listener.EnableMeasurementEvents(instrument);
        };
        _listener.SetMeasurementEventCallback<double>((instrument, value, tags, _) => Add(instrument, value, tags));
        _listener.SetMeasurementEventCallback<long>((instrument, value, tags, _) => Add(instrument, value, tags));
        _listener.Start();
    }

    private void Add(Instrument instrument, double value, ReadOnlySpan<KeyValuePair<string, object?>> tags)
        => _recorded.Enqueue((instrument.Name, value, new Dictionary<string, object?>(tags.ToArray())));

    /// <summary>
    /// The attributes of each measurement <paramref name="instrument"/> recorded, in order.
    /// </summary>
    public IReadOnlyList<Dictionary<string, object?>> Of(string instrument)
        => _recorded.Where(m => m.Instrument == instrument).Select(m => m.Tags).ToList();

    /// <summary>
    /// The value of each measurement <paramref name="instrument"/> recorded, in order.
    /// </summary>
    public IReadOnlyList<double> ValuesOf(string instrument)
        => _recorded.Where(m => m.Instrument == instrument).Select(m => m.Value).ToList();

    /// <summary>
    /// Every attribute of every measurement recorded, with its instrument.
    /// </summary>
    public IEnumerable<(string Instrument, string Key, object? Value)> AllTags
        => _recorded.SelectMany(m => m.Tags.Select(tag => (m.Instrument, tag.Key, tag.Value)));

    public void Dispose() => _listener.Dispose();
}
