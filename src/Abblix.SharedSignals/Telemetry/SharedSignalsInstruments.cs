// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics;
using System.Diagnostics.Metrics;
using Abblix.SharedSignals.Transmitter;

namespace Abblix.SharedSignals.Telemetry;

/// <summary>
/// Records the measurements of <see cref="SharedSignalsMetrics"/> into the transmitter's meter, and closes its spans,
/// each naming the tenant the transmitter answers as.
/// </summary>
/// <remarks>
/// The meter comes from the host's <see cref="IMeterFactory"/>, so each container gets its own and a listener can
/// tell one host's measurements from another's in the same process.
/// </remarks>
public sealed class SharedSignalsInstruments
{
    /// <summary>
    /// Creates the transmitter's instruments in a meter named <see cref="SharedSignalsTelemetry.SourceName"/>.
    /// </summary>
    /// <param name="meterFactory">The host's factory of meters.</param>
    /// <param name="identity">Names the tenant the transmitter answers as when a measurement is taken.</param>
    public SharedSignalsInstruments(IMeterFactory meterFactory, ITransmitterIdentity identity)
    {
        _identity = identity;
        var meter = meterFactory.Create(SharedSignalsTelemetry.SourceName, SharedSignalsTelemetry.Version);

        _eventsTransmitted = meter.CreateCounter<long>(
            SharedSignalsMetrics.EventsTransmitted,
            "{event}",
            "The security events minted for a stream and put into its outbox.");

        _pushDeliveries = meter.CreateCounter<long>(
            SharedSignalsMetrics.PushDeliveries,
            "{token}",
            "The security event tokens posted to receivers.");

        _pushDeliveryDuration = meter.CreateHistogram<double>(
            SharedSignalsMetrics.PushDeliveryDuration,
            "s",
            "The time one push transmission of a security event token takes, from posting it until its answer is acted on.",
            advice: DurationAdvice);
    }

    /// <summary>
    /// Bucket boundaries in seconds, as the platform's own request-duration histograms use: the instrument's
    /// default boundaries are sized for milliseconds and would put every delivery into the first bucket.
    /// </summary>
    private static readonly InstrumentAdvice<double> DurationAdvice = new()
    {
        HistogramBucketBoundaries = [0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1, 2.5, 5, 7.5, 10],
    };

    private readonly ITransmitterIdentity _identity;
    private readonly Counter<long> _eventsTransmitted;
    private readonly Counter<long> _pushDeliveries;
    private readonly Histogram<double> _pushDeliveryDuration;

    /// <summary>
    /// The identifier of the tenant the transmitter answers as now, or null on a deployment answering as one issuer.
    /// </summary>
    internal string? Tenant => _identity.TenantId;

    /// <summary>
    /// Starts the span of <paramref name="name"/>, naming the tenant; null when nothing listens.
    /// </summary>
    internal Activity? StartSpan(string name, ActivityKind kind)
    {
        var span = SharedSignalsTelemetry.Source.StartActivity(name, kind);
        span?.SetTag(SharedSignalsTags.Tenant, Tenant);
        return span;
    }

    /// <summary>
    /// Closes a span with the exception it ended with, by the exception's type alone.
    /// </summary>
    internal static void Fail(Activity? span, Exception exception)
    {
        span?.SetTag(SharedSignalsTags.ErrorType, exception.GetType().FullName);
        span?.SetStatus(ActivityStatusCode.Error);
    }

    /// <summary>
    /// Counts one security event of <paramref name="eventType"/> put into a stream's outbox.
    /// </summary>
    internal void EventTransmitted(string eventType)
        => _eventsTransmitted.Add(1, TagsOf(SharedSignalsTags.EventType, eventType));

    /// <summary>
    /// Runs one push transmission in a span of its own, and records how the receiver answered it and how long the
    /// transmission took.
    /// </summary>
    /// <param name="transmit">Posts one security event token and acts on the answer, returning how the transmission
    /// ended.</param>
    /// <returns>Whether the pass may go on to the next item.</returns>
    /// <remarks>
    /// A transmission that throws is a failure whatever the receiver answered, since the token stays queued.
    /// </remarks>
    internal async Task<bool> ObservePushAsync(Func<Task<PushTransmission>> transmit)
    {
        // Internal rather than client: the span holds the outbox's acknowledgement too, and the host's HTTP client
        // instrumentation opens the client span of the request itself under it
        using var span = StartSpan(SharedSignalsTelemetry.PushSpan, ActivityKind.Internal);
        var started = Stopwatch.GetTimestamp();
        var outcome = PushDeliveryOutcomes.Failed;
        try
        {
            var transmission = await transmit();
            outcome = transmission.Outcome;
            if (transmission.TransportFailure is { } failure)
            {
                Fail(span, failure);
            }

            return transmission.Continues;
        }
        catch (Exception exception)
        {
            Fail(span, exception);
            throw;
        }
        finally
        {
            span?.SetTag(SharedSignalsTags.PushOutcome, outcome);
            if (outcome != PushDeliveryOutcomes.Delivered)
            {
                span?.SetStatus(ActivityStatusCode.Error);
            }

            var tags = TagsOf(SharedSignalsTags.PushOutcome, outcome);
            _pushDeliveries.Add(1, tags);
            _pushDeliveryDuration.Record(Stopwatch.GetElapsedTime(started).TotalSeconds, tags);
        }
    }

    /// <summary>
    /// The attribute of a measurement, with the tenant beside it where the transmitter answers as one.
    /// </summary>
    private TagList TagsOf(string key, string value)
    {
        var tags = new TagList { { key, value } };
        if (Tenant is { } tenant)
        {
            tags.Add(SharedSignalsTags.Tenant, tenant);
        }

        return tags;
    }
}
