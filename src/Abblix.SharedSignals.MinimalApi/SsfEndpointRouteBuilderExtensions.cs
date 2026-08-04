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

using Abblix.SecurityEvents.Delivery;
using Abblix.SharedSignals.Model;
using Abblix.SharedSignals.Model.Delivery;
using Abblix.SharedSignals.Receiver;
using Abblix.SharedSignals.Transmitter;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.SharedSignals.MinimalApi;

/// <summary>
/// Maps the Shared Signals endpoints as Minimal API route handlers: the whole transmitter
/// management surface in one call, and the receiver's push intake in another. The handlers
/// translate transport to the host-agnostic services and nothing else - authentication is the
/// host's middleware, and the receiver identity is read per <see cref="SsfEndpointOptions"/>.
/// </summary>
public static class SsfEndpointRouteBuilderExtensions
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

    private static readonly SsfEndpointOptions DefaultEndpointOptions = new();

    /// <summary>
    /// Maps the transmitter's endpoints: the Event Stream Management API under
    /// <paramref name="prefix"/>, poll delivery beside it, and the configuration document at
    /// the well-known address the issuer resolves to (SSF 1.0 Section 7.2).
    /// </summary>
    /// <remarks>
    /// The returned group carries the management and poll endpoints - attach the host's
    /// authorization to it. The well-known endpoint is deliberately mapped OUTSIDE the group:
    /// discovery must answer before any receiver has credentials, so the group's authorization
    /// does not cover it.
    /// </remarks>
    /// <param name="endpoints">The route builder.</param>
    /// <param name="prefix">The route prefix of the management surface.</param>
    /// <param name="mapWellKnownConfiguration">
    /// False leaves the well-known address unmapped - for a host whose gateway or CDN answers
    /// the canonical address itself. The address is fixed by SSF 1.0 Section 7.2 and receivers
    /// derive it from the issuer, so the flag only suppresses the route, never moves it; a host
    /// that must serve the document on another internal path - a reverse proxy rewriting paths
    /// in front of the transmitter - pairs this with
    /// <see cref="MapSsfConfigurationDocument"/>.</param>
    public static RouteGroupBuilder MapSsfTransmitterEndpoints(
        this IEndpointRouteBuilder endpoints,
        string prefix = "/ssf",
        bool mapWellKnownConfiguration = true)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        if (mapWellKnownConfiguration)
        {
            endpoints.MapSsfConfigurationDocument(prefix);
        }

        var group = endpoints.MapGroup(prefix);

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
        group.MapPost(Routes.Poll + "/{streamId}", PollAsync);

        return group;
    }

    /// <summary>
    /// Maps the transmitter's configuration document (SSF 1.0 Section 7.2) on its own: at the
    /// well-known address the issuer resolves to, or at a host-chosen internal route.
    /// </summary>
    /// <remarks>
    /// <see cref="MapSsfTransmitterEndpoints"/> calls this by default, so a plain host never
    /// needs it. It exists for the deployment where the canonical address is answered by
    /// something in front of the application: a gateway or CDN serving a cached copy (suppress
    /// the default mapping and do not call this), or a reverse proxy rewriting paths, where the
    /// document must exist on an internal route the proxy maps the canonical address onto. The
    /// EXTERNAL address never moves - receivers derive it from the issuer, not from
    /// configuration - so <paramref name="pattern"/> is deployment plumbing, not a protocol
    /// choice.
    /// </remarks>
    /// <param name="endpoints">The route builder.</param>
    /// <param name="advertisedPrefix">
    /// The management-surface prefix the document advertises, as the OUTSIDE world reaches it -
    /// behind a rewriting proxy that is the external prefix, whatever
    /// <see cref="MapSsfTransmitterEndpoints"/> mapped internally.</param>
    /// <param name="pattern">
    /// The route the document is served on; null takes the canonical well-known address derived
    /// from the issuer.</param>
    public static IEndpointConventionBuilder MapSsfConfigurationDocument(
        this IEndpointRouteBuilder endpoints,
        string advertisedPrefix = "/ssf",
        string? pattern = null)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        var options = endpoints.ServiceProvider.GetRequiredService<SsfTransmitterOptions>();
        var issuer = new Uri(options.Issuer, UriKind.Absolute);

        return endpoints.MapGet(
            pattern ?? TransmitterConfiguration.WellKnownAddress(issuer).AbsolutePath,
            (SsfTransmitterOptions current) => Results.Json(ConfigurationDocumentOf(current, advertisedPrefix)));
    }

    /// <summary>
    /// Maps the receiver's push intake (RFC 8935): the endpoint a transmitter POSTs SETs to,
    /// answering the empty 202 or the 400 whose body speaks the registry vocabulary.
    /// </summary>
    /// <param name="endpoints">The route builder.</param>
    /// <param name="pattern">The route the receiver advertised as its push endpoint URL.</param>
    public static IEndpointConventionBuilder MapSsfPushEndpoint(
        this IEndpointRouteBuilder endpoints,
        string pattern)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        return endpoints.MapPost(pattern, HandlePushAsync);
    }

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

    private static async Task<IResult> HandlePushAsync(
        HttpRequest request,
        PushDeliveryHandler handler,
        CancellationToken cancellationToken)
    {
        using var reader = new StreamReader(request.Body);
        var body = await reader.ReadToEndAsync(cancellationToken);

        var result = await handler.HandleAsync(request.ContentType, body, cancellationToken);
        return result.Error is { } error
            ? Results.Json(error, statusCode: (int)result.StatusCode)
            : Results.StatusCode((int)result.StatusCode);
    }

    /// <summary>
    /// The configuration document (SSF 1.0 Section 7.1), composed from the deployment's options
    /// and the very routes this class maps - single-sourced, so the advertisement cannot drift
    /// from the mapping. Endpoint URLs live on the issuer's authority under the prefix.
    /// </summary>
    private static TransmitterConfiguration ConfigurationDocumentOf(
        SsfTransmitterOptions options,
        string prefix)
    {
        var authority = new Uri(new Uri(options.Issuer, UriKind.Absolute).GetLeftPart(UriPartial.Authority));
        Uri EndpointOf(string route) => new(authority, prefix + route);

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
            AuthorizationSchemes = options.AuthorizationSchemes,
            DefaultSubjects = options.DefaultSubjectsValue,
        };
    }

    private static string? ReceiverIdOf(HttpContext context)
        => (context.RequestServices.GetService<SsfEndpointOptions>() ?? DefaultEndpointOptions)
            .ReceiverIdSelector(context);

    private static IResult Render<TBody>(ManagementResult<TBody> result)
        => result.Body is { } body
            ? Results.Json(body, statusCode: (int)result.StatusCode)
            : Results.StatusCode((int)result.StatusCode);
}
