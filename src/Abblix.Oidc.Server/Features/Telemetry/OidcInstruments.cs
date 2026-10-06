// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics;
using System.Diagnostics.Metrics;
using Abblix.Oidc.Server.Features.RateLimiting;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.Telemetry;

/// <summary>
/// Records the measurements of <see cref="OidcMetrics"/> into the server's meter, and logs each refused request with
/// the error code its span and its measurement name.
/// </summary>
/// <remarks>
/// The meter comes from the host's <see cref="IMeterFactory"/>, so each container gets its own and a listener can
/// tell one host's measurements from another's in the same process.
/// </remarks>
internal sealed partial class OidcInstruments
{
    /// <summary>
    /// Creates the server's instruments in a meter named <see cref="OidcTelemetry.SourceName"/>.
    /// </summary>
    /// <param name="logger">Logs each refused request.</param>
    /// <param name="meterFactory">The host's factory of meters.</param>
    public OidcInstruments(ILogger<OidcInstruments> logger, IMeterFactory meterFactory)
    {
        _logger = logger;
        var meter = meterFactory.Create(OidcTelemetry.SourceName, OidcTelemetry.Version);

        _requestDuration = meter.CreateHistogram(
            OidcMetrics.RequestDuration,
            Seconds,
            "The time the server takes to handle a request of an endpoint.",
            advice: DurationAdvice);

        _tokensIssued = meter.CreateCounter<long>(
            OidcMetrics.TokensIssued,
            "{token}",
            "The tokens the server hands out.");

        _tokenSigningDuration = meter.CreateHistogram(
            OidcMetrics.TokenSigningDuration,
            Seconds,
            "The time signing one token takes.",
            advice: DurationAdvice);

        _clientsRegistered = meter.CreateCounter<long>(
            OidcMetrics.ClientsRegistered,
            "{request}",
            "The dynamic client registration requests the server answers.");

        _licenseRefusals = meter.CreateCounter<long>(
            OidcMetrics.LicenseRefusals,
            "{request}",
            "The requests the license refused.");

        _rateLimitRefusals = meter.CreateCounter<long>(
            OidcMetrics.RateLimitRefusals,
            "{request}",
            "The requests refused for a spent budget.");
    }

    private const string Seconds = "s";

    /// <summary>
    /// Bucket boundaries in seconds, as the platform's own request-duration histograms use: the instrument's
    /// default boundaries are sized for milliseconds and would put every request into the first bucket.
    /// </summary>
    private static readonly InstrumentAdvice<double> DurationAdvice = new()
    {
        HistogramBucketBoundaries = [0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1, 2.5, 5, 7.5, 10],
    };

    private readonly ILogger _logger;
    private readonly Histogram<double> _requestDuration;
    private readonly Counter<long> _tokensIssued;
    private readonly Histogram<double> _tokenSigningDuration;
    private readonly Counter<long> _clientsRegistered;
    private readonly Counter<long> _licenseRefusals;
    private readonly Counter<long> _rateLimitRefusals;

    /// <summary>
    /// Records a request of <paramref name="endpoint"/> handled in <paramref name="duration"/>.
    /// </summary>
    public void RequestHandled(string endpoint, string outcome, string? error, string? tenant, TimeSpan duration)
    {
        var tags = new TagList { { TelemetryTags.Endpoint, endpoint }, { TelemetryTags.Outcome, outcome } };
        if (error is not null)
            tags.Add(TelemetryTags.Error, error);
        if (tenant is not null)
            tags.Add(TelemetryTags.Tenant, tenant);

        _requestDuration.Record(duration.TotalSeconds, tags);

        // The code logged is the one the span and the measurement carry, so a log record and a span of one refusal
        // agree, and a host's logging bridge ties the record to the span open around it
        if (error is not null)
            LogRequestRefused(endpoint, error);
    }

    /// <summary>
    /// Counts a token handed out in the response parameter <paramref name="tokenType"/>.
    /// </summary>
    public void TokenIssued(string tokenType, string? grantType, string? tenant)
    {
        var tags = new TagList { { TelemetryTags.TokenType, tokenType } };
        if (grantType is not null)
            tags.Add(TelemetryTags.GrantType, grantType);
        if (tenant is not null)
            tags.Add(TelemetryTags.Tenant, tenant);

        _tokensIssued.Add(1, tags);
    }

    /// <summary>
    /// Records a token signed with <paramref name="algorithm"/> in <paramref name="duration"/>.
    /// </summary>
    public void TokenSigned(string algorithm, TimeSpan duration)
        => _tokenSigningDuration.Record(
            duration.TotalSeconds,
            new KeyValuePair<string, object?>(TelemetryTags.SigningAlgorithm, algorithm));

    /// <summary>
    /// Counts a dynamic client registration request that ended with <paramref name="outcome"/>.
    /// </summary>
    public void ClientRegistration(string outcome)
        => _clientsRegistered.Add(1, new KeyValuePair<string, object?>(TelemetryTags.Outcome, outcome));

    /// <summary>
    /// Counts a request the license refused for <paramref name="reason"/>.
    /// </summary>
    public void LicenseRefused(string reason)
        => _licenseRefusals.Add(1, new KeyValuePair<string, object?>(TelemetryTags.LicenseRefusalReason, reason));

    /// <summary>
    /// Counts a request of <paramref name="endpoint"/> refused for the spent <paramref name="budget"/>, a budget
    /// not of the server's own counted as <see cref="TelemetryTags.Other"/>.
    /// </summary>
    public void RateLimitRefused(string endpoint, string budget)
        => _rateLimitRefusals.Add(
            1,
            new KeyValuePair<string, object?>(TelemetryTags.Endpoint, endpoint),
            new KeyValuePair<string, object?>(
                TelemetryTags.RateLimitBudget,
                KnownBudgets.Contains(budget) ? budget : TelemetryTags.Other));

    private static readonly HashSet<string> KnownBudgets = new(StringComparer.Ordinal)
    {
        CallerRateLimiters.Introspection,
        CallerRateLimiters.Revocation,
        CallerRateLimiters.AuthenticationFailures,
    };
}
