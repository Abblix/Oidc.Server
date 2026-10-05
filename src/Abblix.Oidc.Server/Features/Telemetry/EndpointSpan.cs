// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics;
using System.Reflection;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Features.ClientAuthentication;
using Abblix.Oidc.Server.Features.Licensing;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Utils;

// The tenant a span and a measurement name is read from the multi-tenancy feature where it is in use
#pragma warning disable ABXMT001

namespace Abblix.Oidc.Server.Features.Telemetry;

/// <summary>
/// Runs an endpoint's handling in a span named after the endpoint, closed with the status its outcome tells, and
/// records the request into the server's metrics.
/// </summary>
internal static class EndpointSpan
{
    /// <summary>
    /// Runs <paramref name="handle"/> in a span of <paramref name="endpoint"/> and records how long it took, how it
    /// ended, and the refusal it ended in: a spent budget, or a request the license does not cover.
    /// </summary>
    /// <param name="endpoint">The endpoint, one of <see cref="TelemetryEndpoints"/>.</param>
    /// <param name="instruments">Records the request into the server's metrics.</param>
    /// <param name="tenants">Tells the tenant serving the request, under multi-tenancy.</param>
    /// <param name="handle">The endpoint's handling.</param>
    /// <param name="errorOf">The error the outcome refuses the request with, or null when it does not.</param>
    /// <param name="tags">The request's attribute, from the closed set its tag documents; asked only when a span is
    /// started, so a source nobody listens to does not pay for reading it.</param>
    public static async Task<TResult> RunAsync<TResult>(
        string endpoint,
        OidcInstruments instruments,
        ITenantAccessor? tenants,
        Func<Task<TResult>> handle,
        Func<TResult, OidcError?> errorOf,
        Func<(string Key, string? Value)>? tags = null)
    {
        var tenant = TenantOf(tenants);
        using var span = StartSpan(endpoint, tenant, tags);
        var started = Stopwatch.GetTimestamp();
        (string Outcome, string? Error) ended = (TelemetryOutcomes.Failed, null);
        try
        {
            var result = await handle();
            ended = Close(span, endpoint, instruments, errorOf(result));
            return result;
        }
        catch (TooManyAuthenticationFailuresException exception)
        {
            // A refusal rather than a failure: the client authenticator can answer only with a client or with
            // nothing, so a spent budget leaves it as an exception, which the host turns into the same answer a
            // returned refusal gets.
            ended = Close(span, endpoint, instruments, exception.Refusal);
            throw;
        }
        catch (Exception exception)
        {
            Fail(span, instruments, exception);
            throw;
        }
        finally
        {
            instruments.RequestHandled(endpoint, ended.Outcome, ended.Error, tenant, Stopwatch.GetElapsedTime(started));
        }
    }

    /// <summary>
    /// Starts the span of <paramref name="endpoint"/>, or none when nobody listens to the source.
    /// </summary>
    private static Activity? StartSpan(
        string endpoint,
        string? tenant,
        Func<(string Key, string? Value)>? tags)
    {
        var span = OidcTelemetry.Source.StartActivity(endpoint);
        if (span is null)
            return null;

        span.SetTag(TelemetryTags.Endpoint, endpoint);
        if (tenant is not null)
            span.SetTag(TelemetryTags.Tenant, tenant);

        if (tags?.Invoke() is (var key, { } value))
            span.SetTag(key, value);

        return span;
    }

    /// <summary>
    /// Closes the span with the status <paramref name="error"/> tells, counts a refusal for a spent budget, and
    /// returns how the request ended with the error code a measurement may name.
    /// </summary>
    private static (string Outcome, string? Error) Close(
        Activity? span,
        string endpoint,
        OidcInstruments instruments,
        OidcError? error)
    {
        if (error is null)
        {
            span?.SetStatus(ActivityStatusCode.Ok);
            return (TelemetryOutcomes.Success, null);
        }

        var errorCode = KnownErrors.Contains(error.Error) ? error.Error : TelemetryTags.Other;
        span?.SetTag(TelemetryTags.Error, errorCode);
        span?.SetStatus(ActivityStatusCode.Error);

        if (error is TooManyRequestsError { Budget: var budget })
            instruments.RateLimitRefused(endpoint, budget);

        return (TelemetryOutcomes.Refused, errorCode);
    }

    /// <summary>
    /// Closes the span with the exception the handling failed with, and counts a request the license refused.
    /// </summary>
    private static void Fail(Activity? span, OidcInstruments instruments, Exception exception)
    {
        if (exception is LicenseViolationException { Reason: var reason })
            instruments.LicenseRefused(reason);

        span?.SetTag(TelemetryTags.ErrorType, exception.GetType().FullName);
        span?.SetStatus(ActivityStatusCode.Error);
    }

    /// <summary>
    /// The tenant serving the request under multi-tenancy, or null on a server without tenants.
    /// </summary>
    public static string? TenantOf(ITenantAccessor? tenants) => tenants?.Current?.Tenant.Id;

    /// <summary>
    /// The error of a refusal, or null for a success.
    /// </summary>
    public static OidcError? ErrorOf<TSuccess>(Result<TSuccess, OidcError> result)
        => result.TryGetFailure(out var error) ? error : null;

    /// <summary>
    /// The error an authorization response refuses the request with, or null for any other response, a redirect to
    /// a page the end user acts on included.
    /// </summary>
    public static OidcError? ErrorOf(AuthorizationResponse response)
        => response is AuthorizationError error ? new OidcError(error.Error, error.ErrorDescription) : null;

    /// <summary>
    /// An outcome that never refuses.
    /// </summary>
    public static OidcError? NoError<TResult>(TResult _) => null;

    /// <summary>
    /// The grant type of a request when it is one of <paramref name="supported"/>, compared exactly; null otherwise,
    /// so neither a client nor a host's differently spelled configuration puts a value of its own on a span or a
    /// measurement.
    /// </summary>
    public static string? GrantTypeOf(string? grantType, IEnumerable<string> supported)
        => grantType is not null && supported.Contains(grantType, StringComparer.Ordinal) ? grantType : null;

    /// <summary>
    /// The response type of a request, its values ordered and space-separated, when each value is one the protocol
    /// defines; null otherwise, so a client cannot put a value of its own on a span.
    /// </summary>
    public static string? ResponseTypeOf(string[]? responseType)
    {
        if (responseType is not { Length: > 0 } ||
            !responseType.All(value => KnownResponseTypes.Contains(value, StringComparer.Ordinal)))
        {
            return null;
        }

        return string.Join(' ', responseType.Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal));
    }

    /// <summary>
    /// The error codes of <see cref="Common.Constants.ErrorCodes"/>, the only ones a span names as they are.
    /// </summary>
    private static readonly HashSet<string> KnownErrors = typeof(Common.Constants.ErrorCodes)
        .GetFields(BindingFlags.Public | BindingFlags.Static)
        .Where(field => field is { IsLiteral: true } && field.FieldType == typeof(string))
        .Select(field => (string)field.GetRawConstantValue()!)
        .ToHashSet(StringComparer.Ordinal);

    private static readonly string[] KnownResponseTypes =
    [
        Common.Constants.ResponseTypes.Code,
        Common.Constants.ResponseTypes.Token,
        Common.Constants.ResponseTypes.IdToken,
        Common.Constants.ResponseTypes.None,
    ];
}
