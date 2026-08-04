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
    public static RouteGroupBuilder MapSsfTransmitterEndpoints(
        this IEndpointRouteBuilder endpoints,
        string prefix = "/ssf")
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        var options = endpoints.ServiceProvider.GetRequiredService<SsfTransmitterOptions>();
        var issuer = new Uri(options.Issuer, UriKind.Absolute);

        endpoints.MapGet(
            TransmitterConfiguration.WellKnownAddress(issuer).AbsolutePath,
            (SsfTransmitterOptions current) => Results.Json(ConfigurationDocumentOf(current, prefix)));

        var group = endpoints.MapGroup(prefix);

        // Every management response travels uncacheable, as the specification's own examples
        // show (SSF 1.0 Section 8.1) - stream state answers are moments, not documents.
        group.AddEndpointFilter(async (context, next) =>
        {
            context.HttpContext.Response.Headers.CacheControl = "no-store";
            return await next(context);
        });

        group.MapPost(Routes.Stream, async (
                HttpContext http,
                StreamManagementService service,
                CreateStreamRequest request,
                CancellationToken cancellationToken)
            => ReceiverIdOf(http) is { } receiverId
                ? Render(await service.CreateStreamAsync(receiverId, request, cancellationToken))
                : Results.Unauthorized());

        group.MapGet(Routes.Stream, async (
            HttpContext http,
            StreamManagementService service,
            [FromQuery(Name = StreamMemberNames.StreamId)] string? streamId,
            CancellationToken cancellationToken) =>
        {
            if (ReceiverIdOf(http) is not { } receiverId)
            {
                return Results.Unauthorized();
            }

            return streamId is null
                ? Render(await service.ListStreamsAsync(receiverId, cancellationToken))
                : Render(await service.GetStreamAsync(receiverId, streamId, cancellationToken));
        });

        group.MapPatch(Routes.Stream, async (
                HttpContext http,
                StreamManagementService service,
                UpdateStreamRequest request,
                CancellationToken cancellationToken)
            => ReceiverIdOf(http) is { } receiverId
                ? Render(await service.UpdateStreamAsync(receiverId, request, cancellationToken))
                : Results.Unauthorized());

        group.MapPut(Routes.Stream, async (
                HttpContext http,
                StreamManagementService service,
                UpdateStreamRequest request,
                CancellationToken cancellationToken)
            => ReceiverIdOf(http) is { } receiverId
                ? Render(await service.ReplaceStreamAsync(receiverId, request, cancellationToken))
                : Results.Unauthorized());

        group.MapDelete(Routes.Stream, async (
            HttpContext http,
            StreamManagementService service,
            [FromQuery(Name = StreamMemberNames.StreamId)] string? streamId,
            CancellationToken cancellationToken) =>
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
        });

        group.MapGet(Routes.Status, async (
            HttpContext http,
            StreamManagementService service,
            [FromQuery(Name = StreamMemberNames.StreamId)] string? streamId,
            CancellationToken cancellationToken) =>
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
        });

        group.MapPost(Routes.Status, async (
                HttpContext http,
                StreamManagementService service,
                StreamStatus request,
                CancellationToken cancellationToken)
            => ReceiverIdOf(http) is { } receiverId
                ? Render(await service.UpdateStreamStatusAsync(receiverId, request, cancellationToken))
                : Results.Unauthorized());

        group.MapPost(Routes.AddSubject, async (
                HttpContext http,
                StreamManagementService service,
                AddSubjectRequest request,
                CancellationToken cancellationToken)
            => ReceiverIdOf(http) is { } receiverId
                ? Render(await service.AddSubjectAsync(receiverId, request, cancellationToken))
                : Results.Unauthorized());

        group.MapPost(Routes.RemoveSubject, async (
                HttpContext http,
                StreamManagementService service,
                RemoveSubjectRequest request,
                CancellationToken cancellationToken)
            => ReceiverIdOf(http) is { } receiverId
                ? Render(await service.RemoveSubjectAsync(receiverId, request, cancellationToken))
                : Results.Unauthorized());

        group.MapPost(Routes.Verify, async (
                HttpContext http,
                StreamManagementService service,
                VerificationRequest request,
                CancellationToken cancellationToken)
            => ReceiverIdOf(http) is { } receiverId
                ? Render(await service.RequestVerificationAsync(receiverId, request, cancellationToken))
                : Results.Unauthorized());

        group.MapPost(Routes.Poll + "/{streamId}", async (
            HttpContext http,
            IStreamStore store,
            PollEndpointHandler handler,
            string streamId,
            Abblix.SecurityEvents.Delivery.PollRequest request,
            CancellationToken cancellationToken) =>
        {
            if (ReceiverIdOf(http) is not { } receiverId)
            {
                return Results.Unauthorized();
            }

            return await store.FindAsync(receiverId, streamId, cancellationToken) is { } stream
                ? Results.Json(await handler.HandleAsync(stream, request, cancellationToken))
                : Results.NotFound();
        });

        return group;
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

        return endpoints.MapPost(pattern, async (
            HttpRequest request,
            PushDeliveryHandler handler,
            CancellationToken cancellationToken) =>
        {
            using var reader = new StreamReader(request.Body);
            var body = await reader.ReadToEndAsync(cancellationToken);

            var result = await handler.HandleAsync(request.ContentType, body, cancellationToken);
            return result.Error is { } error
                ? Results.Json(error, statusCode: (int)result.StatusCode)
                : Results.StatusCode((int)result.StatusCode);
        });
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
