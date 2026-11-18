// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.SharedSignals.Transmitter;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.SharedSignals.MinimalApi;

/// <summary>
/// The refusals that come before anything else on the transmitter's surface: there is no transmitter for the
/// request, or the receiver's credentials belong to another one.
/// </summary>
internal static class TransmitterPresence
{
    /// <summary>
    /// Answers 404 where no transmitter serves the request, as a request reaching no tenant of a multi-tenant
    /// server: nothing is there to answer, and every other part of the surface would ask the identity for an
    /// issuer it does not have.
    /// </summary>
    internal static async ValueTask<object?> RefuseWhereNoneServesAsync(
        EndpointFilterInvocationContext context,
        EndpointFilterDelegate next)
        => context.HttpContext.RequestServices.GetRequiredService<ITransmitterIdentity>().Serves
            ? await next(context)
            : Results.NotFound();

    /// <summary>
    /// Answers 401 where the transmitter names the issuer its receivers come from and the receiver's credentials
    /// do not come from it, as one tenant's receiver presenting its credentials under another tenant's address.
    /// </summary>
    /// <remarks>
    /// A request that named no receiver is passed through, so the handler answers it with the bare challenge it
    /// already gives.
    /// </remarks>
    internal static async ValueTask<object?> RefuseForeignReceiverAsync(
        EndpointFilterInvocationContext context,
        EndpointFilterDelegate next)
    {
        var http = context.HttpContext;
        var options = http.RequestServices.GetService<SharedSignalsEndpointOptions>()
                      ?? SharedSignalsEndpointRouteBuilderExtensions.DefaultEndpointOptions;

        if (http.RequestServices.GetRequiredService<ITransmitterIdentity>().ReceiverIssuer is not { } required ||
            options.ReceiverIdSelector(http) is null ||
            string.Equals(options.ReceiverIssuerSelector(http), required, StringComparison.Ordinal))
        {
            return await next(context);
        }

        return BearerChallenges.ForeignIssuer(http);
    }
}
