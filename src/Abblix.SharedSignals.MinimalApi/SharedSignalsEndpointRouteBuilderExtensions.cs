// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.SecurityEvents.Delivery;
using Abblix.SharedSignals.Model;
using Abblix.SharedSignals.Model.Delivery;
using Abblix.SharedSignals.Receiver;
using Abblix.SharedSignals.Receiver.SecurityEvent;
using Abblix.SharedSignals.Transmitter;
using Abblix.Utils;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using System.Text.Json.Nodes;

namespace Abblix.SharedSignals.MinimalApi;

/// <summary>
/// Maps the Shared Signals endpoints as Minimal API route handlers: the whole transmitter
/// management surface in one call, its configuration document in another. The handlers translate
/// transport to the host-agnostic services and nothing else - authentication is the host's
/// middleware, and the receiver identity is read per <see cref="SharedSignalsEndpointOptions"/>.
/// <para>
/// Push delivery is not here. RFC 8935 carries any Security Event Token, not this framework's in
/// particular, so its intake belongs to the package that owns the token - a receiver maps it with
/// <c>MapPushDeliveryEndpoint</c> from <c>Abblix.SecurityEvents.MinimalApi</c>.
/// </para>
/// </summary>
public static partial class SharedSignalsEndpointRouteBuilderExtensions
{
    /// <summary>
    /// The route segments of the management surface, single-sourced because the configuration
    /// document must advertise exactly what is mapped.
    /// </summary>
    private static class Routes
    {
        public const string Stream = "/stream";
        public const string Status = "/status";
        public const string AddSubject = "/subjects:add";
        public const string RemoveSubject = "/subjects:remove";
        public const string Verify = "/verify";
        public const string Poll = "/poll";
    }

    private static readonly SharedSignalsEndpointOptions DefaultEndpointOptions = new();

    /// <summary>
    /// Maps the transmitter's endpoints: the Event Stream Management API under
    /// <see cref="SharedSignalsEndpointOptions.ManagementPrefix"/>, poll delivery beside it, and the
    /// configuration document at the well-known address the issuer resolves to
    /// (SSF 1.0 Section 7.2). Every route comes from <see cref="SharedSignalsEndpointOptions"/>, so one
    /// options object states the whole topology.
    /// </summary>
    /// <remarks>
    /// The returned group carries the management and poll endpoints - attach the host's
    /// authorization to it. The well-known endpoint is deliberately mapped OUTSIDE the group:
    /// discovery must answer before any receiver has credentials, so the group's authorization
    /// does not cover it.
    /// </remarks>
    /// <param name="endpoints">The route builder.</param>
    public static RouteGroupBuilder MapSharedSignalsTransmitterEndpoints(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        var endpointOptions = EndpointOptionsOf(endpoints);
        if (endpointOptions.MapWellKnownConfiguration)
        {
            endpoints.MapSharedSignalsConfigurationDocument();
        }

        var group = endpoints.MapGroup(endpointOptions.ManagementPrefix.Value ?? string.Empty);

        // Every management response travels uncacheable, as the specification's own examples
        // show (SSF 1.0 Section 8.1) - stream state answers are moments, not documents.
        group.AddEndpointFilter(async (context, next) =>
        {
            context.HttpContext.Response.Headers.CacheControl = "no-store";
            return await next(context);
        });

        // The scope each route requires (CAEP Interoperability Profile Section 2.7.3). The profile names
        // five of these eleven operations - Read Stream Configuration and Get Stream Status for
        // ssf.read, Create Stream, Delete Stream and Stream Verification for ssf.manage - and says
        // nothing about the other six.
        //
        // Those six are OUR reading, not the profile's, and they go the stricter way: everything that
        // CHANGES a stream requires ssf.manage, because refusing a caller who should have been allowed
        // is recoverable and the reverse is not. Poll is the exception and takes ssf.read: it delivers a
        // receiver its own events rather than managing anything, and a caller who may read a stream's
        // configuration may certainly read what that stream carries.
        group.AddEndpointFilter(EnforceScopeAsync);

        group.MapPost(Routes.Stream, CreateStreamAsync).RequiresScope(SsfScopes.Manage);
        group.MapGet(Routes.Stream, GetStreamsAsync).RequiresScope(SsfScopes.Read);
        group.MapPatch(Routes.Stream, UpdateStreamAsync).RequiresScope(SsfScopes.Manage);
        group.MapPut(Routes.Stream, ReplaceStreamAsync).RequiresScope(SsfScopes.Manage);
        group.MapDelete(Routes.Stream, DeleteStreamAsync).RequiresScope(SsfScopes.Manage);
        group.MapGet(Routes.Status, GetStatusAsync).RequiresScope(SsfScopes.Read);
        group.MapPost(Routes.Status, UpdateStatusAsync).RequiresScope(SsfScopes.Manage);
        group.MapPost(Routes.AddSubject, AddSubjectAsync).RequiresScope(SsfScopes.Manage);
        group.MapPost(Routes.RemoveSubject, RemoveSubjectAsync).RequiresScope(SsfScopes.Manage);
        group.MapPost(Routes.Verify, RequestVerificationAsync).RequiresScope(SsfScopes.Manage);
        group.MapPost($"{Routes.Poll}/{{streamId}}", PollAsync).RequiresScope(SsfScopes.Read);

        return group;
    }

    /// <summary>
    /// Maps the transmitter's configuration document (SSF 1.0 Section 7.2) on its own: at
    /// <see cref="SharedSignalsEndpointOptions.ConfigurationDocumentRoute"/>, or at the well-known
    /// address the issuer resolves to when that option is null.
    /// </summary>
    /// <remarks>
    /// <see cref="MapSharedSignalsTransmitterEndpoints"/> calls this by default, so a plain host never
    /// needs it. It exists for the deployment where the canonical address is answered by
    /// something in front of the application: a gateway or CDN serving a cached copy (set
    /// <see cref="SharedSignalsEndpointOptions.MapWellKnownConfiguration"/> to false and do not call
    /// this), or a reverse proxy rewriting paths, where the document must exist on an internal
    /// route the proxy maps the canonical address onto. The document advertises
    /// <see cref="SharedSignalsEndpointOptions.AdvertisedPrefix"/> - the prefix as the outside world
    /// reaches it. The EXTERNAL address never moves: receivers derive it from the issuer, not
    /// from configuration, so the route option is deployment plumbing, not a protocol choice.
    /// </remarks>
    /// <param name="endpoints">The route builder.</param>
    public static IEndpointConventionBuilder MapSharedSignalsConfigurationDocument(
        this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        var endpointOptions = EndpointOptionsOf(endpoints);
        var options = endpoints.ServiceProvider.GetRequiredService<SharedSignalsTransmitterOptions>();
        var issuer = new Uri(options.Issuer, UriKind.Absolute);

        WarnIfOutsideTheCaepProfile(endpoints.ServiceProvider, options);
        var advertisedPrefix = endpointOptions.AdvertisedPrefix.HasValue
            ? endpointOptions.AdvertisedPrefix
            : endpointOptions.ManagementPrefix;

        return endpoints.MapGet(
            endpointOptions.ConfigurationDocumentRoute.HasValue
                ? endpointOptions.ConfigurationDocumentRoute.Value
                : TransmitterConfiguration.WellKnownAddress(issuer).AbsolutePath,
            (SharedSignalsTransmitterOptions current) => Results.Json(ConfigurationDocumentOf(current, advertisedPrefix)));
    }

    /// <summary>
    /// The one scheme description the CAEP Interoperability Profile names.
    /// </summary>
    private static JsonObject OAuthAuthorizationScheme() => new()
    {
        [TransmitterConfiguration.ParameterNames.SpecUrn] =
            TransmitterConfiguration.AuthorizationSchemeUrns.OAuth2,
    };

    /// <summary>
    /// Says once, at startup, when the document is missing something the CAEP Interoperability Profile
    /// 1.0 requires and the host looks unaware of it. Neither case refuses the host, and the two are not
    /// equally optional elsewhere: SSF 1.0 requires jwks_uri of any transmitter that signs, which this one
    /// always does, while it attaches no condition to authorization_schemes.
    /// </summary>
    /// <remarks>
    /// It does NOT announce every profile-rejected document, and one configuration is deliberately left
    /// silent: an EMPTY <see cref="SharedSignalsTransmitterOptions.AuthorizationSchemes"/> omits the
    /// member, which Section 2.3.7 rejects, and says nothing - because the host wrote that empty list on
    /// purpose and a warning it cannot act on is one it learns to ignore. A conformance run failing 2.3.7
    /// against a clean startup log is therefore possible, and this is the configuration that does it.
    /// </remarks>
    private static void WarnIfOutsideTheCaepProfile(
        IServiceProvider services, SharedSignalsTransmitterOptions options)
    {
        var logger = services.GetService<ILoggerFactory>()
            ?.CreateLogger(typeof(SharedSignalsEndpointRouteBuilderExtensions));

        if (logger is null)
            return;

        if (options.JwksUri is null)
            LogNoJwksUriAdvertised(logger);

        // Only a host-supplied list can be short: the default IS the required entry. Asked positively -
        // does some scheme name OAuth 2.0 - so a list can carry anything else it likes without the check
        // needing to know what.
        if (options.AuthorizationSchemes is { Count: > 0 } schemes && !schemes.Any(IsOAuth))
            LogOAuthSchemeNotAdvertised(logger, schemes.Count);
    }

    private static bool IsOAuth(JsonObject scheme)
        => scheme.TryGetPropertyValue(TransmitterConfiguration.ParameterNames.SpecUrn, out var urn)
           && urn is JsonValue value
           && value.TryGetValue<string>(out var specUrn)
           && specUrn == TransmitterConfiguration.AuthorizationSchemeUrns.OAuth2;

    private static SharedSignalsEndpointOptions EndpointOptionsOf(IEndpointRouteBuilder endpoints)
        => endpoints.ServiceProvider.GetService<SharedSignalsEndpointOptions>() ?? DefaultEndpointOptions;

    private static async Task<IResult> CreateStreamAsync(
        HttpContext http,
        StreamManagementService service,
        CreateStreamRequest request,
        CancellationToken cancellationToken)
        => ReceiverIdOf(http) is { } receiverId
            ? Render(await service.CreateStreamAsync(receiverId, request, cancellationToken))
            : Unauthenticated(http);

    /// <summary>
    /// One route, two reads: with "stream_id" the single configuration, without it the list -
    /// where an empty list is a receiver with no streams, never an error
    /// (SSF 1.0 Section 8.1.1.2).
    /// </summary>
    private static async Task<IResult> GetStreamsAsync(
        HttpContext http,
        StreamManagementService service,
        [FromQuery(Name = StreamMemberNames.StreamId)] string? streamId,
        CancellationToken cancellationToken)
    {
        if (ReceiverIdOf(http) is not { } receiverId)
        {
            return Unauthenticated(http);
        }

        return streamId is null
            ? Render(await service.ListStreamsAsync(receiverId, cancellationToken))
            : Render(await service.GetStreamAsync(receiverId, streamId, cancellationToken));
    }

    private static async Task<IResult> UpdateStreamAsync(
        HttpContext http,
        StreamManagementService service,
        UpdateStreamRequest request,
        CancellationToken cancellationToken)
        => ReceiverIdOf(http) is { } receiverId
            ? Render(await service.UpdateStreamAsync(receiverId, request, cancellationToken))
            : Unauthenticated(http);

    private static async Task<IResult> ReplaceStreamAsync(
        HttpContext http,
        StreamManagementService service,
        UpdateStreamRequest request,
        CancellationToken cancellationToken)
        => ReceiverIdOf(http) is { } receiverId
            ? Render(await service.ReplaceStreamAsync(receiverId, request, cancellationToken))
            : Unauthenticated(http);

    private static async Task<IResult> DeleteStreamAsync(
        HttpContext http,
        StreamManagementService service,
        [FromQuery(Name = StreamMemberNames.StreamId)] string? streamId,
        CancellationToken cancellationToken)
    {
        if (ReceiverIdOf(http) is not { } receiverId)
        {
            return Unauthenticated(http);
        }

        // "The DELETE request MUST include the 'stream_id'" per SSF 1.0 Section 8.1.1.5 -
        // without it there is nothing to delete.
        return streamId is null
            ? Results.BadRequest()
            : Render(await service.DeleteStreamAsync(receiverId, streamId, cancellationToken));
    }

    private static async Task<IResult> GetStatusAsync(
        HttpContext http,
        StreamManagementService service,
        [FromQuery(Name = StreamMemberNames.StreamId)] string? streamId,
        CancellationToken cancellationToken)
    {
        if (ReceiverIdOf(http) is not { } receiverId)
        {
            return Unauthenticated(http);
        }

        // The status read has no list fallback: "stream_id" is its REQUIRED parameter
        // (SSF 1.0 Section 8.1.2.1).
        return streamId is null
            ? Results.BadRequest()
            : Render(await service.GetStreamStatusAsync(receiverId, streamId, cancellationToken));
    }

    private static async Task<IResult> UpdateStatusAsync(
        HttpContext http,
        StreamManagementService service,
        StreamStatus request,
        CancellationToken cancellationToken)
        => ReceiverIdOf(http) is { } receiverId
            ? Render(await service.UpdateStreamStatusAsync(receiverId, request, cancellationToken))
            : Unauthenticated(http);

    private static async Task<IResult> AddSubjectAsync(
        HttpContext http,
        StreamManagementService service,
        AddSubjectRequest request,
        CancellationToken cancellationToken)
        => ReceiverIdOf(http) is { } receiverId
            ? Render(await service.AddSubjectAsync(receiverId, request, cancellationToken))
            : Unauthenticated(http);

    private static async Task<IResult> RemoveSubjectAsync(
        HttpContext http,
        StreamManagementService service,
        RemoveSubjectRequest request,
        CancellationToken cancellationToken)
        => ReceiverIdOf(http) is { } receiverId
            ? Render(await service.RemoveSubjectAsync(receiverId, request, cancellationToken))
            : Unauthenticated(http);

    private static async Task<IResult> RequestVerificationAsync(
        HttpContext http,
        StreamManagementService service,
        VerificationRequest request,
        CancellationToken cancellationToken)
        => ReceiverIdOf(http) is { } receiverId
            ? Render(await service.RequestVerificationAsync(receiverId, request, cancellationToken))
            : Unauthenticated(http);

    private static async Task<IResult> PollAsync(
        HttpContext http,
        IStreamStore store,
        PollEndpointHandler handler,
        string streamId,
        PollRequest request,
        CancellationToken cancellationToken)
    {
        if (ReceiverIdOf(http) is not { } receiverId)
        {
            return Unauthenticated(http);
        }

        return await store.FindAsync(receiverId, streamId, cancellationToken) is { } stream
            ? Results.Json(await handler.HandleAsync(stream, request, cancellationToken))
            : Results.NotFound();
    }

    /// <summary>
    /// The configuration document (SSF 1.0 Section 7.1), composed from the deployment's options
    /// and the very routes this class maps - single-sourced, so the advertisement cannot drift
    /// from the mapping. Endpoint URLs live on the issuer's authority under the prefix.
    /// </summary>
    private static TransmitterConfiguration ConfigurationDocumentOf(
        SharedSignalsTransmitterOptions options,
        PathString prefix)
    {
        var authority = new Uri(new Uri(options.Issuer, UriKind.Absolute).GetLeftPart(UriPartial.Authority));
        Uri EndpointOf(string route) => new(authority, prefix.Add(route).Value!);

        var deliveryMethods = new List<string> { PushDeliveryMethod.MethodUri };
        if (options.PollEndpointFactory is not null)
        {
            deliveryMethods.Add(PollDeliveryMethod.MethodUri);
        }

        return new TransmitterConfiguration
        {
            SpecVersion = TransmitterConfiguration.SpecVersions.Final,
            Issuer = options.Issuer,
            JwksUri = options.JwksUri,
            DeliveryMethodsSupported = deliveryMethods,
            ConfigurationEndpoint = EndpointOf(Routes.Stream),
            StatusEndpoint = EndpointOf(Routes.Status),
            AddSubjectEndpoint = EndpointOf(Routes.AddSubject),
            RemoveSubjectEndpoint = EndpointOf(Routes.RemoveSubject),
            VerificationEndpoint = EndpointOf(Routes.Verify),
            AuthorizationSchemes = options.AuthorizationSchemes switch
            {
                null => [OAuthAuthorizationScheme()],

                // The host said "advertise none" explicitly. Publishing an empty array would advertise a
                // member with no schemes in it, which says less than omitting it.
                { Count: 0 } => null,

                var supplied => supplied,
            },
            DefaultSubjects = options.DefaultSubjectsValue,
        };
    }

    /// <summary>
    /// The answer to a management request that named no receiver: 401 with a bare Bearer challenge.
    /// </summary>
    /// <remarks>
    /// Bare, and deliberately so. Every refusal on this surface has the same cause - nothing identified
    /// the caller - which is what RFC 6750 Section 3.1 describes as a request that "lacks any
    /// authentication information", and for which it says the resource server "SHOULD NOT include an
    /// error code or other error information". A caller that presented nothing has nothing to correct.
    /// <para>
    /// The other two codes that section defines belong to whoever validates the token, which is the host:
    /// <c>invalid_token</c> when a presented token is expired or malformed, and <c>insufficient_scope</c>
    /// with 403 when it is valid but too narrow. This package never sees a token - it reads whatever
    /// identity the host's authentication left behind, through
    /// <see cref="SharedSignalsEndpointOptions.ReceiverIdSelector"/>.
    /// </para>
    /// <para>
    /// The realm is the transmitter's issuer, which is the one name a receiver already holds for this
    /// protection space and the one it used to find these endpoints.
    /// </para>
    /// </remarks>
    private static IResult Unauthenticated(HttpContext http)
    {
        var issuer = http.RequestServices.GetService<SharedSignalsTransmitterOptions>()?.Issuer;
        return new ChallengeResult(
            StatusCodes.Status401Unauthorized, WwwAuthenticate.Challenge(BearerScheme, issuer));
    }

    /// <summary>
    /// The scheme this surface advertises. Not a claim that the host authenticates with bearer tokens -
    /// it is what the CAEP Interoperability Profile Section 2.4.3 requires a receiver to use, so it is
    /// what a receiver reading the challenge is prepared to act on.
    /// </summary>
    private const string BearerScheme = "Bearer";

    /// <summary>
    /// Records which scope a route requires, so the filter below can read it back off the endpoint.
    /// </summary>
    private static void RequiresScope<TBuilder>(this TBuilder builder, string scope)
        where TBuilder : IEndpointConventionBuilder
        => builder.WithMetadata(new RequiredScope(scope));

    private sealed record RequiredScope(string Scope);

    /// <summary>
    /// Refuses a request whose token was not granted the scope its route requires.
    /// </summary>
    /// <remarks>
    /// Does nothing at all unless the host set
    /// <see cref="SharedSignalsEndpointOptions.GrantedScopesSelector"/>, because without it this package
    /// has no way to learn what was granted and guessing would refuse every caller.
    /// <para>
    /// RFC 6750 Section 3.1 names the answer: <c>insufficient_scope</c>, "The request requires higher
    /// privileges than provided by the access token", with 403. The <c>scope</c> attribute is the one
    /// that section says a resource server MAY include, and it is the only thing here that tells a
    /// receiver what to ask its authorization server for next.
    /// </para>
    /// </remarks>
    private static async ValueTask<object?> EnforceScopeAsync(
        EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        var http = context.HttpContext;
        var options = http.RequestServices.GetService<SharedSignalsEndpointOptions>() ?? DefaultEndpointOptions;

        if (options.GrantedScopesSelector is not { } selector ||
            http.GetEndpoint()?.Metadata.GetMetadata<RequiredScope>() is not { } required ||
            SsfScopes.Satisfies(selector(http), required.Scope))
        {
            return await next(context);
        }

        var issuer = http.RequestServices.GetService<SharedSignalsTransmitterOptions>()?.Issuer;
        return new ChallengeResult(
            StatusCodes.Status403Forbidden,
            $"{WwwAuthenticate.Challenge(BearerScheme, issuer, "insufficient_scope", "The access token " +
            $"does not carry the scope this operation requires.")}, scope=\"{required.Scope}\"");
    }

    /// <summary>
    /// A 401 carrying one <c>WWW-Authenticate</c> line and no body. Written by hand because
    /// <c>Results.Unauthorized()</c> emits no headers, and the header is the whole point.
    /// </summary>
    private sealed class ChallengeResult(int statusCode, string challenge) : IResult
    {
        public Task ExecuteAsync(HttpContext httpContext)
        {
            httpContext.Response.StatusCode = statusCode;
            httpContext.Response.Headers.WWWAuthenticate = challenge;
            return Task.CompletedTask;
        }
    }

    private static string? ReceiverIdOf(HttpContext context)
        => (context.RequestServices.GetService<SharedSignalsEndpointOptions>() ?? DefaultEndpointOptions)
            .ReceiverIdSelector(context);

    private static IResult Render<TBody>(ManagementResult<TBody> result)
        => result.Body is { } body
            ? Results.Json(body, statusCode: (int)result.StatusCode)
            : Results.StatusCode((int)result.StatusCode);
}
