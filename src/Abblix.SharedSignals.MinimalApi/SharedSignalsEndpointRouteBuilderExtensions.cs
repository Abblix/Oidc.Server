// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.SecurityEvents.Delivery;
using Abblix.SharedSignals.Model;
using Abblix.SharedSignals.Transmitter;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

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
public static class SharedSignalsEndpointRouteBuilderExtensions
{
    internal static readonly SharedSignalsEndpointOptions DefaultEndpointOptions = new();

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
    /// <para>
    /// A route the HOST adds to this group is not scope-checked, and that is worth knowing before
    /// adding one. The filter is attached to the GROUP, so it is in that route's pipeline - but it
    /// judges a route by the requirement the route declares, and only the routes mapped here declare
    /// one. A route with none is let through. So a host route beside them is admitted for any caller the
    /// host's own authorization admits, in a deployment where every neighbouring route answers 403 to
    /// that same caller.
    /// </para>
    /// <para>
    /// The scope requirement is deliberately not something a host can declare: making it so would put
    /// the metadata type into this package's public surface for a need nobody has stated. The scopes
    /// themselves are already public - <c>SsfScopes</c> carries their names and the profile's inclusion
    /// rule - so a host that wants its route scoped reads the granted scopes and asks
    /// <c>SsfScopes.Satisfies</c>, rather than needing a requirement this package would then have to
    /// honour forever.
    /// </para>
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

        var transmitter = endpoints.ServiceProvider.GetRequiredService<SharedSignalsTransmitterOptions>();
        CaepProfileWarnings.WarnIfTheManagementApiIsOutsideTheCaepProfile(
            endpoints.ServiceProvider, transmitter, endpointOptions);

        // The group is assembled in steps (Builder): what every route shares first, then each area's
        // routes, then the addresses the mapped routes are published under.
        var group = endpoints.MapGroup(endpointOptions.ManagementPrefix.Value ?? string.Empty);
        ApplyGroupConventions(group);
        MapStreamConfigurationRoutes(group);
        MapStreamStatusRoutes(group);
        MapSubjectRoutes(group);
        MapVerificationRoute(group);
        MapPollRoute(group);
        PublishServedAddresses(endpoints, endpointOptions);

        return group;
    }

    /// <summary>
    /// What every management route shares: an uncacheable response, the scope filter, and the
    /// refusals that belong to the group rather than to any handler.
    /// </summary>
    private static void ApplyGroupConventions(RouteGroupBuilder group)
    {
        // Every management response travels uncacheable, as the specification's own examples
        // show (SSF 1.0 Section 8.1) - stream state answers are moments, not documents. First, so the
        // refusals below carry it too.
        group.AddEndpointFilter(async (context, next) =>
        {
            context.HttpContext.Response.Headers.CacheControl = "no-store";
            return await next(context);
        });

        // Before the scope filter and the handlers, which ask the transmitter's identity for its issuer.
        group.AddEndpointFilter(TransmitterPresence.RefuseWhereNoneServesAsync);
        group.AddEndpointFilter(TransmitterPresence.RefuseForeignReceiverAsync);

        // The scope each route requires (CAEP Interoperability Profile Section 2.7.3). The profile names
        // five of these eleven operations - Read Stream Configuration and Get Stream Status for
        // ssf.read, Create Stream, Delete Stream and Stream Verification for ssf.manage - and says
        // nothing about the other six.
        //
        // Those six are OUR reading, not the profile's, and they go the stricter way: everything that
        // CHANGES a stream requires ssf.manage, because refusing a caller who should have been allowed
        // is recoverable and the reverse is not.
        //
        // Poll is the exception and takes ssf.read, at a price worth naming. It is not a pure read: a
        // poll acknowledges, and IEventOutbox.AcknowledgeAsync removes what was acknowledged -
        // RFC 8936 Section 2.2's acknowledge-only poll is that half by itself. So a token carrying only
        // ssf.read can empty its own queue. The alternative is worse: requiring ssf.manage for poll makes
        // every polling receiver hold the scope that also lets it delete streams, which is the whole
        // split gone.
        //
        // What was supposed to bound the damage is ownership: the handler looks the stream up BY the
        // caller's identity. That bound holds only while stream identifiers are unique ACROSS receivers,
        // which the dynamic path guarantees by minting a GUID and the declared path does not - the
        // outbox is keyed by stream id alone while a stream is keyed by the pair, so two receivers
        // naming one stream share one queue and either can acknowledge the other's events. That is
        // issue 462 and it is not this scope's doing; it is named here because the sentence that used to
        // stand in this place asserted the bound without its condition.
        group.AddEndpointFilter(ScopeRequirement.EnforceScopeAsync);

        // The refusals that belong to the GROUP rather than to any handler: 401 where nothing named the
        // caller or its credentials do not come from the issuer the transmitter takes its receivers from, 403
        // where the caller was named and its token carries neither scope the route needs, and 404 where no
        // transmitter serves the request. Declared once here, so a route added later inherits them instead
        // of restating them.
        group.Answers(StatusCodes.Status401Unauthorized, StatusCodes.Status403Forbidden, StatusCodes.Status404NotFound);
    }

    /// <summary>
    /// The stream configuration routes (SSF 1.0 Section 8.1.1).
    /// </summary>
    private static void MapStreamConfigurationRoutes(RouteGroupBuilder group)
    {
        group.MapPost(ManagementRoutes.Stream, StreamManagementHandlers.CreateStreamAsync)
            .RequiresScope(SsfScopes.Manage)
            .AnswersWithBody<StreamConfiguration>(StatusCodes.Status201Created)
            .Answers(
                StatusCodes.Status400BadRequest,
                StatusCodes.Status409Conflict,
                StatusCodes.Status415UnsupportedMediaType);

        // The read is the one route whose success carries two shapes: the configuration when
        // "stream_id" names a stream, an array of them when it names none (SSF 1.0 Section 8.1.1.2).
        // A response type is one type, so this declares the status without one rather than picking
        // the half that would make a generated client wrong on the other.
        group.MapGet(ManagementRoutes.Stream, StreamManagementHandlers.GetStreamsAsync)
            .RequiresScope(SsfScopes.Read)
            .Answers(StatusCodes.Status200OK, StatusCodes.Status404NotFound);

        group.MapPatch(ManagementRoutes.Stream, StreamManagementHandlers.UpdateStreamAsync)
            .RequiresScope(SsfScopes.Manage)
            .AnswersWithBody<StreamConfiguration>(StatusCodes.Status200OK)
            .Answers(
                StatusCodes.Status202Accepted,
                StatusCodes.Status400BadRequest,
                StatusCodes.Status404NotFound,
                StatusCodes.Status415UnsupportedMediaType);

        group.MapPut(ManagementRoutes.Stream, StreamManagementHandlers.ReplaceStreamAsync)
            .RequiresScope(SsfScopes.Manage)
            .AnswersWithBody<StreamConfiguration>(StatusCodes.Status200OK)
            .Answers(
                StatusCodes.Status202Accepted,
                StatusCodes.Status400BadRequest,
                StatusCodes.Status404NotFound,
                StatusCodes.Status415UnsupportedMediaType);

        group.MapDelete(ManagementRoutes.Stream, StreamManagementHandlers.DeleteStreamAsync)
            .RequiresScope(SsfScopes.Manage)
            .Answers(
                StatusCodes.Status204NoContent,
                StatusCodes.Status400BadRequest,
                StatusCodes.Status404NotFound);
    }

    /// <summary>
    /// The stream status routes (SSF 1.0 Section 8.1.2).
    /// </summary>
    private static void MapStreamStatusRoutes(RouteGroupBuilder group)
    {
        group.MapGet(ManagementRoutes.Status, StreamManagementHandlers.GetStatusAsync)
            .RequiresScope(SsfScopes.Read)
            .AnswersWithBody<StreamStatus>(StatusCodes.Status200OK)
            .Answers(StatusCodes.Status400BadRequest, StatusCodes.Status404NotFound);

        group.MapPost(ManagementRoutes.Status, StreamManagementHandlers.UpdateStatusAsync)
            .RequiresScope(SsfScopes.Manage)
            .AnswersWithBody<StreamStatus>(StatusCodes.Status200OK)
            .Answers(
                StatusCodes.Status202Accepted,
                StatusCodes.Status400BadRequest,
                StatusCodes.Status404NotFound,
                StatusCodes.Status415UnsupportedMediaType);
    }

    /// <summary>
    /// The subject routes (SSF 1.0 Section 8.1.3).
    /// </summary>
    private static void MapSubjectRoutes(RouteGroupBuilder group)
    {
        // Adding a subject answers 200 with no body (SSF 1.0 Section 8.1.3.2), so the success is
        // declared as a status rather than as a shape.
        group.MapPost(ManagementRoutes.AddSubject, StreamManagementHandlers.AddSubjectAsync)
            .RequiresScope(SsfScopes.Manage)
            .Answers(
                StatusCodes.Status200OK,
                StatusCodes.Status400BadRequest,
                StatusCodes.Status404NotFound,
                StatusCodes.Status409Conflict,
                StatusCodes.Status415UnsupportedMediaType);

        group.MapPost(ManagementRoutes.RemoveSubject, StreamManagementHandlers.RemoveSubjectAsync)
            .RequiresScope(SsfScopes.Manage)
            .Answers(
                StatusCodes.Status204NoContent,
                StatusCodes.Status400BadRequest,
                StatusCodes.Status404NotFound,
                StatusCodes.Status409Conflict,
                StatusCodes.Status415UnsupportedMediaType);
    }

    /// <summary>
    /// The verification route (SSF 1.0 Section 8.1.4.2).
    /// </summary>
    private static void MapVerificationRoute(RouteGroupBuilder group)
    {
        group.MapPost(ManagementRoutes.Verify, StreamManagementHandlers.RequestVerificationAsync)
            .RequiresScope(SsfScopes.Manage)
            .Answers(
                StatusCodes.Status204NoContent,
                StatusCodes.Status400BadRequest,
                StatusCodes.Status404NotFound,
                StatusCodes.Status409Conflict,
                StatusCodes.Status415UnsupportedMediaType,
                StatusCodes.Status429TooManyRequests);
    }

    /// <summary>
    /// The poll delivery route (RFC 8936).
    /// </summary>
    private static void MapPollRoute(RouteGroupBuilder group)
    {
        group.MapPost($"{ManagementRoutes.Poll}/{{streamId}}", StreamManagementHandlers.PollAsync)
            .RequiresScope(SsfScopes.Read)
            .AnswersWithBody<PollResponse>(StatusCodes.Status200OK)
            .Answers(
                StatusCodes.Status400BadRequest,
                StatusCodes.Status404NotFound,
                StatusCodes.Status415UnsupportedMediaType);
    }

    /// <summary>
    /// Declares where the routes just mapped are served, for the stream records and the
    /// configuration document that name them.
    /// </summary>
    private static void PublishServedAddresses(
        IEndpointRouteBuilder endpoints,
        SharedSignalsEndpointOptions endpointOptions)
    {
        // Said out loud because a stream STORES its poll address: the transmitter mints it at create time
        // and a receiver polls it for as long as the stream lives, so an address that does not lead back
        // to this route is a 404 arriving long after the create that succeeded. Single-sourced from the
        // poll route for the same reason the configuration document is single-sourced from the five it
        // advertises, and from the ADVERTISED prefix, because that is the one the outside world uses.
        // How an identifier is carried into that address, and why one that cannot be carried is refused
        // here rather than met by a receiver later, is on PollEndpointAddresses.PollEndpointOf.
        var identity = endpoints.ServiceProvider.GetRequiredService<ITransmitterIdentity>();
        var advertisedPrefix = PollEndpointAddresses.AdvertisedPrefixOf(endpointOptions);
        var pollLogger = endpoints.ServiceProvider.GetRequiredService<ILoggerFactory>()
            .CreateLogger(typeof(SharedSignalsEndpointRouteBuilderExtensions));
        endpoints.ServiceProvider.GetRequiredService<PollEndpointLocator>().ServedAt(streamId =>
        {
            var (authority, prefix) = PollEndpointAddresses.ReachedAt(identity, advertisedPrefix);
            return PollEndpointAddresses.PollEndpointOf(pollLogger, authority, prefix, streamId);
        });

        // And the same declaration for the management routes just mapped, which is what lets the
        // configuration document name them. Without it the document has no way to tell this
        // deployment from one that maps the document alone and serves no management API.
        endpoints.ServiceProvider.GetRequiredService<ManagementEndpointLocator>().ServedAt(route =>
        {
            var (authority, prefix) = PollEndpointAddresses.ReachedAt(identity, advertisedPrefix);
            return new Uri(authority, prefix.Add(route).Value!);
        });
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

        CaepProfileWarnings.WarnIfTheDocumentIsOutsideTheCaepProfile(endpoints.ServiceProvider, options);

        // Answers 200: it takes no parameter to get wrong and no credentials to lack - discovery has to
        // work before a receiver has any - and 404 only where no transmitter serves the request. Declared,
        // because an undeclared status is INFERRED into the document rather than left out, and an
        // inference that happens to be right is indistinguishable from one that is not.
        var document = endpoints.MapGet(
            endpointOptions.ConfigurationDocumentRoute.HasValue
                ? endpointOptions.ConfigurationDocumentRoute.Value
                : TransmitterConfiguration.WellKnownAddress(issuer).AbsolutePath,
            (SharedSignalsTransmitterOptions current,
             ITransmitterIdentity identity,
             PollEndpointLocator pollEndpoints,
             ManagementEndpointLocator managementEndpoints) =>
                Results.Json(TransmitterConfigurationDocument.ConfigurationDocumentOf(
                    current, identity, pollEndpoints, managementEndpoints)));

        document.AddEndpointFilter(TransmitterPresence.RefuseWhereNoneServesAsync);
        document.AnswersWithBody<TransmitterConfiguration>(StatusCodes.Status200OK);
        document.Answers(StatusCodes.Status404NotFound);
        return document;
    }

    private static SharedSignalsEndpointOptions EndpointOptionsOf(IEndpointRouteBuilder endpoints)
        => endpoints.ServiceProvider.GetService<SharedSignalsEndpointOptions>() ?? DefaultEndpointOptions;
}
