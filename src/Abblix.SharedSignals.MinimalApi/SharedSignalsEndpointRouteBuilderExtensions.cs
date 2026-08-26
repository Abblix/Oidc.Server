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

        group.MapPost(Routes.Stream, CreateStreamAsync);
        group.MapGet(Routes.Stream, GetStreamsAsync);
        group.MapPatch(Routes.Stream, UpdateStreamAsync);
        group.MapPut(Routes.Stream, ReplaceStreamAsync);
        group.MapDelete(Routes.Stream, DeleteStreamAsync);
        group.MapGet(Routes.Status, GetStatusAsync);
        group.MapPost(Routes.Status, UpdateStatusAsync);
        group.MapPost(Routes.AddSubject, AddSubjectAsync);
        group.MapPost(Routes.RemoveSubject, RemoveSubjectAsync);
        group.MapPost(Routes.Verify, RequestVerificationAsync);
        group.MapPost($"{Routes.Poll}/{{streamId}}", PollAsync);

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
    /// Says once, at startup, what this deployment publishes that the CAEP Interoperability Profile 1.0
    /// rejects. Neither refuses the host, and the two are not equally optional elsewhere: SSF 1.0 requires
    /// jwks_uri of any transmitter that signs, which this one always does, while it attaches no condition
    /// to authorization_schemes. A conformance run measures against the profile, and a document that fails
    /// it should not do so silently.
    /// </summary>
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
            : Results.Unauthorized();

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
            return Results.Unauthorized();
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
            : Results.Unauthorized();

    private static async Task<IResult> ReplaceStreamAsync(
        HttpContext http,
        StreamManagementService service,
        UpdateStreamRequest request,
        CancellationToken cancellationToken)
        => ReceiverIdOf(http) is { } receiverId
            ? Render(await service.ReplaceStreamAsync(receiverId, request, cancellationToken))
            : Results.Unauthorized();

    private static async Task<IResult> DeleteStreamAsync(
        HttpContext http,
        StreamManagementService service,
        [FromQuery(Name = StreamMemberNames.StreamId)] string? streamId,
        CancellationToken cancellationToken)
    {
        if (ReceiverIdOf(http) is not { } receiverId)
        {
            return Results.Unauthorized();
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
            return Results.Unauthorized();
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
            : Results.Unauthorized();

    private static async Task<IResult> AddSubjectAsync(
        HttpContext http,
        StreamManagementService service,
        AddSubjectRequest request,
        CancellationToken cancellationToken)
        => ReceiverIdOf(http) is { } receiverId
            ? Render(await service.AddSubjectAsync(receiverId, request, cancellationToken))
            : Results.Unauthorized();

    private static async Task<IResult> RemoveSubjectAsync(
        HttpContext http,
        StreamManagementService service,
        RemoveSubjectRequest request,
        CancellationToken cancellationToken)
        => ReceiverIdOf(http) is { } receiverId
            ? Render(await service.RemoveSubjectAsync(receiverId, request, cancellationToken))
            : Results.Unauthorized();

    private static async Task<IResult> RequestVerificationAsync(
        HttpContext http,
        StreamManagementService service,
        VerificationRequest request,
        CancellationToken cancellationToken)
        => ReceiverIdOf(http) is { } receiverId
            ? Render(await service.RequestVerificationAsync(receiverId, request, cancellationToken))
            : Results.Unauthorized();

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
            return Results.Unauthorized();
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

    private static string? ReceiverIdOf(HttpContext context)
        => (context.RequestServices.GetService<SharedSignalsEndpointOptions>() ?? DefaultEndpointOptions)
            .ReceiverIdSelector(context);

    private static IResult Render<TBody>(ManagementResult<TBody> result)
        => result.Body is { } body
            ? Results.Json(body, statusCode: (int)result.StatusCode)
            : Results.StatusCode((int)result.StatusCode);
}
