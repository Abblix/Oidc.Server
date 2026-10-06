// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Features.Telemetry;

/// <summary>
/// Runs a stage of handling a request in a span of its own under the endpoint's span, closed with the status its
/// outcome tells.
/// </summary>
internal static class StageObservation
{
    /// <summary>
    /// Runs <paramref name="handle"/> in a span of <paramref name="stage"/>, when an endpoint span of the server is
    /// open around it.
    /// </summary>
    /// <remarks>
    /// A stage reached outside an endpoint's handling, as storage a background service reads, starts no span of its
    /// own, since a span without the request it serves would be a root nobody asked for.
    /// </remarks>
    /// <param name="stage">The stage, one of <see cref="TelemetryStages"/>.</param>
    /// <param name="handle">The stage's work.</param>
    /// <param name="refused">Whether the outcome refuses the request.</param>
    public static async Task<TResult> RunAsync<TResult>(
        string stage,
        Func<Task<TResult>> handle,
        Func<TResult, bool> refused)
    {
        using var span = Activity.Current?.Source == OidcTelemetry.Source
            ? OidcTelemetry.Source.StartActivity(stage)
            : null;
        if (span is null)
            return await handle();

        span.SetTag(TelemetryTags.Stage, stage);
        try
        {
            var result = await handle();
            span.SetStatus(refused(result) ? ActivityStatusCode.Error : ActivityStatusCode.Ok);
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
    /// Whether a result refuses: it carries a failure.
    /// </summary>
    public static bool Refused<TSuccess, TFailure>(Result<TSuccess, TFailure> result)
        => result.TryGetFailure(out _);

    /// <summary>
    /// Whether an authorization response refuses: it is an error delivered to the client.
    /// </summary>
    public static bool Refused(AuthorizationResponse response) => response is AuthorizationError;

    /// <summary>
    /// An outcome that never refuses.
    /// </summary>
    public static bool NeverRefused<TResult>(TResult _) => false;
}
