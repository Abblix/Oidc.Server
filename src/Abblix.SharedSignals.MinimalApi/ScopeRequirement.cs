// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.SharedSignals.Transmitter;
using Abblix.Utils;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.SharedSignals.MinimalApi;

/// <summary>
/// The scope each management route requires (CAEP Interoperability Profile Section 2.7.3), recorded on
/// the route and enforced by one filter on the group.
/// </summary>
internal static class ScopeRequirement
{
    /// <summary>
    /// Records which scope a route requires, so the filter below can read it back off the endpoint.
    /// </summary>
    internal static TBuilder RequiresScope<TBuilder>(this TBuilder builder, string scope)
        where TBuilder : IEndpointConventionBuilder
    {
        builder.WithMetadata(new RequiredScope(scope));
        return builder;
    }

    private sealed record RequiredScope(string Scope);

    /// <summary>
    /// Refuses a request whose token was not granted the scope its route requires.
    /// </summary>
    /// <remarks>
    /// Returns immediately unless the host set
    /// <see cref="SharedSignalsEndpointOptions.GrantedScopesSelector"/>, because without it this package
    /// has no way to learn what was granted and guessing would refuse every caller. That check is FIRST
    /// deliberately: the clause after it calls a host-supplied delegate, and a deployment that never
    /// opted in should not pay for a check that cannot fire.
    /// <para>
    /// With it set, <see cref="SharedSignalsEndpointOptions.ReceiverIdSelector"/> is asked here and again
    /// in the handler. Twice rather than once, because the two answers are wanted at two different
    /// moments and threading the first through would put this package's state into the request. The
    /// handler's call happens on every request either way; only the extra one here is gated.
    /// </para>
    /// <para>
    /// RFC 6750 Section 3.1 names the answer: <c>insufficient_scope</c>, "The request requires higher
    /// privileges than provided by the access token", with 403. The <c>scope</c> attribute is the one
    /// that section says a resource server MAY include, and it is the only thing here that tells a
    /// receiver what to ask its authorization server for next.
    /// </para>
    /// </remarks>
    internal static async ValueTask<object?> EnforceScopeAsync(
        EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        var http = context.HttpContext;
        var options = http.RequestServices.GetService<SharedSignalsEndpointOptions>()
                      ?? SharedSignalsEndpointRouteBuilderExtensions.DefaultEndpointOptions;

        // An unidentified caller is NOT a scope problem, and this filter runs before the handler that
        // would say so. Left to itself it answers "insufficient_scope, scope=ssf.manage" to a request
        // that carried no token at all - which RFC 6750 Section 3.1 forbids, and which sends a receiver
        // whose token merely expired to fetch a scope it already has. Pass it through and let the
        // handler emit the bare 401.
        // A route carrying no RequiredScope is let through. That is fail-OPEN, and it is stated rather
        // than relied on: every route this class maps declares one, and a future route that forgets is
        // exempt with nothing to notice it. The alternative - refusing an endpoint whose metadata is
        // absent - would break any route a host adds to this group itself.
        if (options.GrantedScopesSelector is not { } selector ||
            options.ReceiverIdSelector(http) is null ||
            http.GetEndpoint()?.Metadata.GetMetadata<RequiredScope>() is not { } required ||
            SsfScopes.Satisfies(selector(http), required.Scope))
        {
            return await next(context);
        }

        var issuer = http.RequestServices.GetService<ITransmitterIdentity>()?.Issuer;
        return new ChallengeResult(
            StatusCodes.Status403Forbidden,
            WwwAuthenticate.Challenge(
                BearerChallenges.BearerScheme,
                ("realm", issuer),
                ("error", "insufficient_scope"),
                ("error_description", "The access token does not carry the scope this operation requires."),
                ("scope", required.Scope)));
    }
}
