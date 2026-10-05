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
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Utils;

// The tenant a span names is read from the multi-tenancy feature where it is in use
#pragma warning disable ABXMT001

namespace Abblix.Oidc.Server.Features.Telemetry;

/// <summary>
/// Runs an endpoint's handling in a span named after the endpoint, closed with the status its outcome tells.
/// </summary>
internal static class EndpointSpan
{
    /// <summary>
    /// Runs <paramref name="handle"/> in a span of <paramref name="endpoint"/>.
    /// </summary>
    /// <param name="endpoint">The endpoint, one of <see cref="TelemetryEndpoints"/>.</param>
    /// <param name="tenants">Tells the tenant serving the request, under multi-tenancy.</param>
    /// <param name="handle">The endpoint's handling.</param>
    /// <param name="errorOf">The error code the outcome refuses the request with, or null when it does not.</param>
    /// <param name="tags">Attributes of the request, each from the closed set its tag documents; asked only when a
    /// span is recorded, so a source nobody listens to costs their reading too.</param>
    public static async Task<TResult> RunAsync<TResult>(
        string endpoint,
        ITenantAccessor? tenants,
        Func<Task<TResult>> handle,
        Func<TResult, string?> errorOf,
        Func<(string Key, string? Value)>? tags = null)
    {
        using var span = OidcTelemetry.Source.StartActivity(endpoint);
        if (span is null)
            return await handle();

        span.SetTag(TelemetryTags.Endpoint, endpoint);
        if (tenants?.Current is { } current)
            span.SetTag(TelemetryTags.Tenant, current.Tenant.Id);

        if (tags?.Invoke() is (var key, { } value))
            span.SetTag(key, value);

        try
        {
            var result = await handle();
            if (errorOf(result) is { } error)
            {
                span.SetTag(TelemetryTags.Error, KnownErrors.Contains(error) ? error : TelemetryTags.UnknownError);
                span.SetStatus(ActivityStatusCode.Error);
            }
            else
            {
                span.SetStatus(ActivityStatusCode.Ok);
            }

            return result;
        }
        catch (Exception exception)
        {
            span.SetTag(TelemetryTags.ErrorType, exception.GetType().FullName);
            span.SetStatus(ActivityStatusCode.Error);
            throw;
        }
    }

    /// <summary>
    /// The error code of a refusal, or null for a success.
    /// </summary>
    public static string? ErrorOf<TSuccess>(Result<TSuccess, OidcError> result)
        => result.TryGetFailure(out var error) ? error.Error : null;

    /// <summary>
    /// The error code an authorization response refuses the request with, or null for any other response, a
    /// redirect to a page the end user acts on included.
    /// </summary>
    public static string? ErrorOf(AuthorizationResponse response)
        => response is AuthorizationError error ? error.Error : null;

    /// <summary>
    /// An outcome that never refuses.
    /// </summary>
    public static string? NoError<TResult>(TResult _) => null;

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
