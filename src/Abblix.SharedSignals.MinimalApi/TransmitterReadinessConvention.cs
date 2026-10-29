// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.SharedSignals.Transmitter;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.SharedSignals.MinimalApi;

/// <summary>
/// Makes each transmitter endpoint wait for the transmitter's readiness before it answers.
/// </summary>
/// <remarks>
/// It wraps the endpoint's request delegate rather than adding a filter, because Minimal API binds a handler's
/// parameters before its filters run, and the transmitter's parts it binds are picked for the request when they are
/// resolved.
/// </remarks>
internal static class TransmitterReadinessConvention
{
    /// <summary>
    /// Waits for the <see cref="ITransmitterReadiness"/> the host registered, if any, before each endpoint of
    /// <paramref name="builder"/> binds its parameters.
    /// </summary>
    /// <param name="builder">The endpoint or the group of endpoints to wait in front of.</param>
    internal static TBuilder WaitForTheTransmitter<TBuilder>(this TBuilder builder)
        where TBuilder : IEndpointConventionBuilder
    {
        builder.Finally(endpoint =>
        {
            var answer = endpoint.RequestDelegate ?? throw new InvalidOperationException(
                $"The endpoint '{endpoint.DisplayName}' has no request delegate to wait in front of.");

            endpoint.RequestDelegate = async context =>
            {
                if (context.RequestServices.GetService<ITransmitterReadiness>() is { } readiness)
                    await readiness.WaitAsync(context.RequestAborted);

                await answer(context);
            };
        });
        return builder;
    }
}
