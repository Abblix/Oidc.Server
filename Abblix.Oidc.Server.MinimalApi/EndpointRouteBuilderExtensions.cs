// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

using System.Diagnostics.CodeAnalysis;
using System.Net.Http.Headers;
using Abblix.Jwt;
using Abblix.Oidc.Server.AspNetCore;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Endpoints.CheckSession.Interfaces;
using Abblix.Oidc.Server.Endpoints.Configuration.Interfaces;
using Abblix.Oidc.Server.Endpoints.DeviceAuthorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Oidc.Server.Endpoints.EndSession;
using Abblix.Oidc.Server.Endpoints.Introspection.Interfaces;
using Abblix.Oidc.Server.Endpoints.PushedAuthorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.Revocation.Interfaces;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Endpoints.UserInfo.Interfaces;
using Abblix.Oidc.Server.MinimalApi.Filters;
using Abblix.Oidc.Server.MinimalApi.Formatters;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Abblix.Oidc.Server.MinimalApi.Model;
using Core = Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.MinimalApi;

/// <summary>
/// Maps the Abblix OpenID Connect server endpoints onto an ASP.NET Core Minimal API route builder.
/// </summary>
/// <remarks>
/// This is the Minimal API counterpart of the MVC integration's <c>app.MapControllers()</c>. Each endpoint is mapped
/// only when its <see cref="OidcEndpoints"/> flag is enabled in <see cref="OidcOptions.EnabledEndpoints"/>, reproducing
/// the MVC behavior where a disabled endpoint is never registered and therefore returns 404.
/// </remarks>
public static class EndpointRouteBuilderExtensions
{
    /// <summary>
    /// Maps the enabled OpenID Connect and OAuth 2.0 endpoints onto the route builder and returns it so the host can
    /// continue configuring its own routes.
    /// </summary>
    /// <param name="endpoints">The endpoint route builder to map the endpoints onto.</param>
    /// <param name="prefix">An optional route prefix to mount all OIDC endpoints under (default: none).</param>
    /// <returns>The <see cref="RouteGroupBuilder"/> the OIDC endpoints were mapped onto, so the host can apply
    /// cross-cutting conventions (rate limiting, host filtering, metadata) to all of them at once.</returns>
    public static RouteGroupBuilder MapOidcEndpoints(this IEndpointRouteBuilder endpoints, string prefix = "")
    {
        var options = endpoints.ServiceProvider.GetRequiredService<IOptions<OidcOptions>>().Value;
        var routes = endpoints.ServiceProvider.GetRequiredService<IOptions<OidcRouteOptions>>().Value;
        var oidcGroup = endpoints.MapGroup(prefix);

        // Gate every OIDC endpoint on HTTPS, the public discovery and JWKS metadata included. This mirrors the
        // [RequireHttps] carried by every MVC controller (DiscoveryController included): the credential- and
        // token-bearing endpoints must never serve secrets in cleartext (RFC 6749 §3.2/§10.1), and the metadata must
        // not be readable over plain HTTP either — a man-in-the-middle could rewrite the advertised endpoints or
        // jwks_uri and steer clients onto attacker infrastructure. A host that genuinely needs an ungated route —
        // a liveness/health probe — maps it outside MapOidcEndpoints; the library gates all of its own endpoints
        // without exception. See RequireHttpsAsync for the redirect/refuse behaviour.
        oidcGroup.AddEndpointFilter(RequireHttpsAsync);

        // RFC 6749 §5.1 no-store, applied group-wide so every OIDC response (token, PAR, CIBA, device, userinfo,
        // introspection, authorize, checksession, discovery, JWKS) carries it — matching the MVC controllers'
        // class-level ResponseCache. Registered before the validation filter so even a validation short-circuit
        // (400 invalid_request) still ships no-store.
        oidcGroup.WithNoCache();

        // Runs the declarative validation rules carried by the bound request models before each handler, shaping any
        // violation as the OAuth invalid_request response. Group-scoped, so it covers every OIDC endpoint at once and
        // cannot be clobbered by a host's own pipeline configuration.
        oidcGroup.AddEndpointFilter(new ValidationEndpointFilter());

        if (options.EnabledEndpoints.HasFlag(OidcEndpoints.Configuration))
        {
            oidcGroup
                .MapGet(routes.Configuration, ConfigurationAsync)
                .WithName(EndpointNames.Configuration)
                .RequireCors(OidcConstants.CorsPolicyName);

            // RFC 8414 §3: the same Authorization Server Metadata document, also served at the
            // oauth-authorization-server suffix so a client that queries only that suffix still resolves it.
            oidcGroup
                .MapGet(routes.OAuthAuthorizationServer, ConfigurationAsync)
                .WithName(EndpointNames.OAuthAuthorizationServer)
                .RequireCors(OidcConstants.CorsPolicyName);
        }

        if (options.EnabledEndpoints.HasFlag(OidcEndpoints.Keys))
        {
            oidcGroup
                .MapGet(routes.Keys, KeysAsync)
                .WithName(EndpointNames.Keys)
                .RequireCors(OidcConstants.CorsPolicyName);
        }

        if (options.EnabledEndpoints.HasFlag(OidcEndpoints.CheckSession))
        {
            oidcGroup
                .MapGet(routes.CheckSession, CheckSessionAsync)
                .WithName(EndpointNames.CheckSession)
                .RequireCors(OidcConstants.CorsPolicyName);
        }

        if (options.EnabledEndpoints.HasFlag(OidcEndpoints.Token))
        {
            oidcGroup
                .MapPost(routes.Token, TokenAsync)
                .WithName(EndpointNames.Token)
                .RequireCors(OidcConstants.CorsPolicyName);
        }

        if (options.EnabledEndpoints.HasFlag(OidcEndpoints.Revocation))
        {
            oidcGroup
                .MapPost(routes.Revocation, RevocationAsync)
                .WithName(EndpointNames.Revocation)
                .RequireCors(OidcConstants.CorsPolicyName);
        }

        if (options.EnabledEndpoints.HasFlag(OidcEndpoints.Introspection))
        {
            oidcGroup
                .MapPost(routes.Introspection, IntrospectionAsync)
                .WithName(EndpointNames.Introspection);
        }

        if (options.EnabledEndpoints.HasFlag(OidcEndpoints.PushedAuthorizationRequest))
        {
            oidcGroup
                .MapPost(routes.PushedAuthorizationRequest, PushedAuthorizationAsync)
                .WithName(EndpointNames.PushedAuthorizationRequest);
        }

        if (options.EnabledEndpoints.HasFlag(OidcEndpoints.BackChannelAuthentication))
        {
            oidcGroup
                .MapPost(routes.BackChannelAuthentication, BackChannelAuthenticationAsync)
                .WithName(EndpointNames.BackChannelAuthentication);
        }

        if (options.EnabledEndpoints.HasFlag(OidcEndpoints.DeviceAuthorization))
        {
            oidcGroup
                .MapPost(routes.DeviceAuthorization, DeviceAuthorizationAsync)
                .WithName(EndpointNames.DeviceAuthorization);
        }

        if (options.EnabledEndpoints.HasFlag(OidcEndpoints.UserInfo))
        {
            oidcGroup
                .MapMethods(routes.UserInfo, [HttpMethods.Get, HttpMethods.Post], UserInfoAsync)
                .WithName(EndpointNames.UserInfo)
                .RequireCors(OidcConstants.CorsPolicyName);
        }

        if (options.EnabledEndpoints.HasFlag(OidcEndpoints.EndSession))
        {
            oidcGroup
                .MapMethods(routes.EndSession, [HttpMethods.Get, HttpMethods.Post], EndSessionAsync)
                .WithName(EndpointNames.EndSession)
                .RequireCors(OidcConstants.CorsPolicyName);
        }

        if (options.EnabledEndpoints.HasFlag(OidcEndpoints.Authorize))
        {
            oidcGroup
                .MapMethods(routes.Authorize, [HttpMethods.Get, HttpMethods.Post], AuthorizeAsync)
                .WithName(EndpointNames.Authorize);
        }

        if (options.EnabledEndpoints.HasFlag(OidcEndpoints.RegisterClient))
        {
            oidcGroup
                .MapPost(routes.Register, RegisterClientAsync)
                .WithName(EndpointNames.Register);

            oidcGroup
                .MapGet(routes.RegisterClient, ReadClientAsync)
                .WithName(EndpointNames.RegisterClient);

            oidcGroup.MapPut(routes.RegisterClient, UpdateClientAsync);
            oidcGroup.MapDelete(routes.RegisterClient, RemoveClientAsync);
        }

        return oidcGroup;
    }

    /// <summary>
    /// Group endpoint filter mirroring the MVC controllers' <c>[RequireHttps]</c>: a non-HTTPS GET is redirected to
    /// the HTTPS URL and any other non-HTTPS method is refused, so client credentials and tokens are never served in
    /// cleartext (RFC 6749 §3.2/§10.1). Behind a TLS-terminating proxy the host must run <c>ForwardedHeaders</c> so
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
    /// Applies the no-store cache headers (RFC 6749 §5.1) through an endpoint filter, so the no-cache behavior is a
    /// property of the endpoint rather than something each <see cref="IResult"/> opts into individually. Applied
    /// group-wide before the validation filter, so it covers every OIDC response — handler success, handler error, and
    /// a request short-circuited by validation — matching the MVC controllers' class-level ResponseCache.
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

    /// <summary>
    /// Handles the authorization request (OpenID Connect Core 3.1). The request is bound from the query string or the
    /// posted form, and the response is delivered to the client's redirect URI or an interaction page.
    /// </summary>
    private static async Task<IResult> AuthorizeAsync(
        AuthorizationRequest authorizationRequest,
        IAuthorizationHandler handler,
        IAuthorizationResultFormatter formatter)
    {
        Core.AuthorizationRequest coreAuthorizationRequest = authorizationRequest;
        var response = await handler.HandleAsync(coreAuthorizationRequest);
        return await formatter.FormatResponseAsync(coreAuthorizationRequest, response);
    }

    /// <summary>
    /// Registers a new client dynamically (RFC 7591). The metadata is bound from the JSON body; the initial access
    /// token, the only value the body cannot carry, is merged from the Authorization header.
    /// </summary>
    private static async Task<IResult> RegisterClientAsync(
        Core.ClientRegistrationRequest request,
        HttpContext context,
        IRegisterClientHandler handler,
        IRegisterClientResultFormatter formatter)
    {
        var clientRegistrationRequest = request with { AuthorizationHeader = ParseAuthorizationHeader(context.Request) };
        var response = await handler.HandleAsync(clientRegistrationRequest);
        return await formatter.FormatResponseAsync(clientRegistrationRequest, response);
    }

    /// <summary>Reads a registered client's configuration (RFC 7592 §2.1).</summary>
    private static async Task<IResult> ReadClientAsync(
        ClientAuthorizationRequest authorizationRequest,
        IReadClientHandler handler,
        IReadClientResultFormatter formatter)
    {
        Core.ClientRequest coreClientRequest = authorizationRequest;
        var response = await handler.HandleAsync(coreClientRequest);
        return await formatter.FormatResponseAsync(coreClientRequest, response);
    }

    /// <summary>Updates a registered client's configuration (RFC 7592 §2.2).</summary>
    private static async Task<IResult> UpdateClientAsync(
        ClientAuthorizationRequest authorizationRequest,
        Core.ClientRegistrationRequest registrationRequest,
        IUpdateClientHandler handler,
        IUpdateClientResultFormatter formatter)
    {
        var updateRequest = new UpdateClientRequest(authorizationRequest, registrationRequest);
        var response = await handler.HandleAsync(updateRequest);
        return await formatter.FormatResponseAsync(updateRequest, response);
    }

    /// <summary>Removes a registered client (RFC 7592 §2.3).</summary>
    private static async Task<IResult> RemoveClientAsync(
        ClientAuthorizationRequest authorizationRequest,
        IRemoveClientHandler handler,
        IRemoveClientResultFormatter formatter)
    {
        Core.ClientRequest coreClientRequest = authorizationRequest;
        var response = await handler.HandleAsync(coreClientRequest);
        return await formatter.FormatResponseAsync(coreClientRequest, response);
    }

    private static AuthenticationHeaderValue? ParseAuthorizationHeader(HttpRequest request)
    {
        var rawAuthorization = request.Headers.Authorization.ToString();
        return !string.IsNullOrEmpty(rawAuthorization) && AuthenticationHeaderValue.TryParse(rawAuthorization, out var header)
            ? header
            : null;
    }

    /// <summary>
    /// Pushes an authorization request (RFC 9126). The authorization request and the client context are each bound
    /// from the posted form.
    /// </summary>
    private static async Task<IResult> PushedAuthorizationAsync(
        AuthorizationRequest authorizationRequest,
        ClientRequest clientRequest,
        IPushedAuthorizationHandler handler,
        IPushedAuthorizationResultFormatter formatter)
    {
        Core.AuthorizationRequest coreAuthorizationRequest = authorizationRequest;
        Core.ClientRequest coreClientRequest = clientRequest;
        var response = await handler.HandleAsync(coreAuthorizationRequest, coreClientRequest);
        return await formatter.FormatResponseAsync(coreAuthorizationRequest, response);
    }

    /// <summary>
    /// Initiates a CIBA backchannel authentication request (OpenID Connect CIBA §7). The request and the
    /// client-authentication context are each bound from the posted form.
    /// </summary>
    private static async Task<IResult> BackChannelAuthenticationAsync(
        BackChannelAuthenticationRequest authenticationRequest,
        ClientRequest clientRequest,
        IBackChannelAuthenticationHandler handler,
        IBackChannelAuthenticationResultFormatter formatter)
    {
        Core.BackChannelAuthenticationRequest coreAuthenticationRequest = authenticationRequest;
        Core.ClientRequest coreClientRequest = clientRequest;
        var response = await handler.HandleAsync(coreAuthenticationRequest, coreClientRequest);
        return await formatter.FormatResponseAsync(coreAuthenticationRequest, coreClientRequest, response);
    }

    /// <summary>
    /// Starts the device authorization grant (RFC 8628). The request and the client-authentication context are each
    /// bound from the posted form.
    /// </summary>
    private static async Task<IResult> DeviceAuthorizationAsync(
        DeviceAuthorizationRequest deviceAuthorizationRequest,
        ClientRequest clientRequest,
        IDeviceAuthorizationHandler handler,
        IDeviceAuthorizationResultFormatter formatter)
    {
        Core.DeviceAuthorizationRequest coreDeviceAuthorizationRequest = deviceAuthorizationRequest;
        Core.ClientRequest coreClientRequest = clientRequest;
        var response = await handler.HandleAsync(coreDeviceAuthorizationRequest, coreClientRequest);
        return await formatter.FormatResponseAsync(coreDeviceAuthorizationRequest, response);
    }

    /// <summary>
    /// Returns the authenticated end-user's claims (OpenID Connect Core 5.3). The request and the client context are
    /// bound from the query string or the posted form.
    /// </summary>
    private static async Task<IResult> UserInfoAsync(
        UserInfoRequest userInfoRequest,
        ClientRequest clientRequest,
        IUserInfoHandler handler,
        IUserInfoResultFormatter formatter)
    {
        Core.UserInfoRequest coreUserInfoRequest = userInfoRequest;
        Core.ClientRequest coreClientRequest = clientRequest;
        var response = await handler.HandleAsync(coreUserInfoRequest, coreClientRequest);
        return await formatter.FormatResponseAsync(coreUserInfoRequest, response);
    }

    /// <summary>
    /// Ends the user's session (OpenID Connect RP-Initiated Logout). The request is bound from the query string or the
    /// posted form.
    /// </summary>
    private static async Task<IResult> EndSessionAsync(
        EndSessionRequest endSessionRequest,
        IEndSessionHandler handler,
        IEndSessionResultFormatter formatter)
    {
        Core.EndSessionRequest coreEndSessionRequest = endSessionRequest;
        var response = await handler.HandleAsync(coreEndSessionRequest);
        return await formatter.FormatResponseAsync(coreEndSessionRequest, response);
    }

    /// <summary>
    /// Issues tokens (OpenID Connect Core 3.1.3, OAuth 2.0 RFC 6749 §3.2). The request and the client-authentication
    /// context are each bound from the posted form via their own <c>BindAsync</c>.
    /// </summary>
    private static async Task<IResult> TokenAsync(
        TokenRequest tokenRequest,
        ClientRequest clientRequest,
        ITokenHandler handler,
        ITokenResultFormatter formatter)
    {
        Core.TokenRequest coreTokenRequest = tokenRequest;
        Core.ClientRequest coreClientRequest = clientRequest;
        var response = await handler.HandleAsync(coreTokenRequest, coreClientRequest);
        return await formatter.FormatResponseAsync(coreTokenRequest, response);
    }

    /// <summary>Revokes a token (RFC 7009). Request and client context are each bound from the posted form.</summary>
    private static async Task<IResult> RevocationAsync(
        RevocationRequest revocationRequest,
        ClientRequest clientRequest,
        IRevocationHandler handler,
        IRevocationResultFormatter formatter)
    {
        Core.RevocationRequest coreRevocationRequest = revocationRequest;
        Core.ClientRequest coreClientRequest = clientRequest;
        var response = await handler.HandleAsync(coreRevocationRequest, coreClientRequest);
        return await formatter.FormatResponseAsync(coreRevocationRequest, response);
    }

    /// <summary>Introspects a token (RFC 7662). Request and client context are each bound from the posted form.</summary>
    private static async Task<IResult> IntrospectionAsync(
        IntrospectionRequest introspectionRequest,
        ClientRequest clientRequest,
        IIntrospectionHandler handler,
        IIntrospectionResultFormatter formatter)
    {
        Core.IntrospectionRequest coreIntrospectionRequest = introspectionRequest;
        Core.ClientRequest coreClientRequest = clientRequest;
        var response = await handler.HandleAsync(coreIntrospectionRequest, coreClientRequest);
        return await formatter.FormatResponseAsync(coreIntrospectionRequest, response);
    }

    /// <summary>
    /// Returns the session-management iframe document (OpenID Connect Session Management).
    /// </summary>
    private static async Task<IResult> CheckSessionAsync(
        ICheckSessionHandler handler, ICheckSessionResultFormatter formatter)
    {
        var response = await handler.HandleAsync();
        return await formatter.FormatResponseAsync(response);
    }

    /// <summary>
    /// Returns the OpenID Provider configuration document (discovery metadata) for the current request.
    /// </summary>
    private static async Task<IResult> ConfigurationAsync(
        IConfigurationHandler handler, IConfigurationResultFormatter formatter)
    {
        var response = await handler.HandleAsync();
        return await formatter.FormatResponseAsync(response);
    }

    /// <summary>
    /// Returns the JSON Web Key Set (JWKS) with the provider's public signing keys, used by clients to verify
    /// issued tokens.
    /// </summary>
    private static async Task<IResult> KeysAsync(IAuthServiceKeysProvider serviceKeysProvider)
    {
        var keys = await serviceKeysProvider.GetPublishedKeysAsync();
        return Results.Json(new JsonWebKeySet(keys));
    }
}
