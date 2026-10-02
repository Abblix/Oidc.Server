// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server


using System.Diagnostics.CodeAnalysis;
using Abblix.Oidc.Server.AspNetCore;
using Abblix.Oidc.Server.AspNetCore.MultiTenancy;
using Abblix.Oidc.Server.MinimalApi.Filters;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace Abblix.Oidc.Server.MinimalApi;

/// <summary>
/// The filters every OIDC endpoint passes through, in the order they wrap the handler.
/// </summary>
internal static class OidcEndpointFilters
{
    /// <summary>Adds the filters to the OIDC route group.</summary>
    public static RouteGroupBuilder AddOidcEndpointFilters(this RouteGroupBuilder oidcGroup)
    {
        // Gate every OIDC endpoint on HTTPS, the public discovery and JWKS metadata included. This mirrors the
        // [RequireHttps] carried by every MVC controller (DiscoveryController included): the credential- and
        // token-bearing endpoints must never serve secrets in cleartext (RFC 6749 section 3.2/section 10.1), and the metadata must
        // not be readable over plain HTTP either - a man-in-the-middle could rewrite the advertised endpoints or
        // jwks_uri and steer clients onto attacker infrastructure. A host that genuinely needs an ungated route -
        // a liveness/health probe - maps it outside MapOidcEndpoints; the library gates all of its own endpoints
        // without exception. See RequireHttpsAsync for the redirect/refuse behavior.
        oidcGroup.AddEndpointFilter(RequireHttpsAsync);

        // Under multi-tenancy, a request that names no tenant has no issuer, keys or clients of its own, and is
        // answered 404 here rather than halfway through an endpoint that has already stored something.
        oidcGroup.AddEndpointFilter(RequireTenantAsync);

        // Registered next, so it wraps every filter and handler below: a refusal the library decides for
        // itself, raised anywhere under the group, becomes a status the library chose rather than whatever the
        // host's environment makes of an unhandled exception. It sits inside the HTTPS gate on purpose - a
        // request refused for cleartext never reaches the keys, or anybody's budget, at all.
        oidcGroup.AddEndpointFilter(new LibraryRefusalFilter());

        // RFC 6749 section 5.1 no-store, applied group-wide so every OIDC response (token, PAR, CIBA, device, userinfo,
        // introspection, authorize, checksession, discovery, JWKS) carries it - matching the MVC controllers'
        // class-level ResponseCache. Registered before the validation filter so even a validation short-circuit
        // (400 invalid_request) still ships no-store.
        oidcGroup.WithNoCache();

        // Runs the declarative validation rules carried by the bound request models before each handler, shaping any
        // violation as the OAuth invalid_request response. Group-scoped, so it covers every OIDC endpoint at once and
        // cannot be clobbered by a host's own pipeline configuration.
        oidcGroup.AddEndpointFilter(new ValidationEndpointFilter());

        return oidcGroup;
    }

    /// <summary>
    /// Group endpoint filter mirroring the MVC controllers' <c>[RequireHttps]</c>: a non-HTTPS GET is redirected to
    /// the HTTPS URL and any other non-HTTPS method is refused, so client credentials and tokens are never served in
    /// cleartext (RFC 6749 section 3.2/section 10.1). Behind a TLS-terminating proxy the host must run <c>ForwardedHeaders</c> so
    /// <see cref="HttpRequest.IsHttps"/> reflects the edge, otherwise this filter blocks all traffic.
    /// </summary>
    private static async ValueTask<object?> RequireHttpsAsync(
        EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        var request = context.HttpContext.Request;
        if (request.IsHttps)
            return await next(context);

        if (HttpMethods.IsGet(request.Method))
        {
            var target = new UriBuilder(
                Uri.UriSchemeHttps, request.Host.Host, request.Host.Port ?? -1,
                request.PathBase + request.Path, request.QueryString.Value).Uri;
            return Results.Redirect(target.AbsoluteUri);
        }

        return Results.StatusCode(StatusCodes.Status403Forbidden);
    }

    /// <summary>
    /// Group endpoint filter answering 404 to a request that multi-tenancy left without a tenant.
    /// </summary>
    private static async ValueTask<object?> RequireTenantAsync(
        EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
#pragma warning disable ABXMT001 // A deployment without multi-tenancy is never refused here.
        return TenantRequirement.IsUnmet(context.HttpContext)
            ? Results.NotFound()
            : await next(context);
#pragma warning restore ABXMT001
    }

    /// <summary>
    /// Applies the no-store cache headers (RFC 6749 section 5.1) through an endpoint filter, so the no-cache behavior is a
    /// property of the endpoint rather than something each <see cref="IResult"/> opts into individually. Applied
    /// group-wide before the validation filter, so it covers every OIDC response - handler success, handler error, and
    /// a request short-circuited by validation - matching the MVC controllers' class-level ResponseCache.
    /// </summary>
    [SuppressMessage("SonarLint", "S3241:Methods should not return values that are never used",
        Justification = "Fluent endpoint convention like WithName/RequireCors: it returns the builder to stay " +
                        "chainable, so a call site need not place it last even though none currently consumes the result.")]
    private static TBuilder WithNoCache<TBuilder>(this TBuilder builder) where TBuilder : IEndpointConventionBuilder
        => builder.AddEndpointFilter(async (context, next) =>
        {
            context.HttpContext.Response.SetNoCacheHeaders();
            return await next(context);
        });
}
