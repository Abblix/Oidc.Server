// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
using System.Net.Mime;
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
        group.AddEndpointFilter(EnforceScopeAsync);

        // The two refusals that belong to the GROUP rather than to any handler: 401 where nothing named
        // the caller, 403 where the caller was named and its token carries neither scope the route
        // needs. Declared once here, so a route added later inherits them instead of restating them.
        group.Answers(StatusCodes.Status401Unauthorized, StatusCodes.Status403Forbidden);

        group.MapPost(Routes.Stream, CreateStreamAsync)
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
        group.MapGet(Routes.Stream, GetStreamsAsync)
            .RequiresScope(SsfScopes.Read)
            .Answers(StatusCodes.Status200OK, StatusCodes.Status404NotFound);

        group.MapPatch(Routes.Stream, UpdateStreamAsync)
            .RequiresScope(SsfScopes.Manage)
            .AnswersWithBody<StreamConfiguration>(StatusCodes.Status200OK)
            .Answers(
                StatusCodes.Status202Accepted,
                StatusCodes.Status400BadRequest,
                StatusCodes.Status404NotFound,
                StatusCodes.Status415UnsupportedMediaType);

        group.MapPut(Routes.Stream, ReplaceStreamAsync)
            .RequiresScope(SsfScopes.Manage)
            .AnswersWithBody<StreamConfiguration>(StatusCodes.Status200OK)
            .Answers(
                StatusCodes.Status202Accepted,
                StatusCodes.Status400BadRequest,
                StatusCodes.Status404NotFound,
                StatusCodes.Status415UnsupportedMediaType);

        group.MapDelete(Routes.Stream, DeleteStreamAsync)
            .RequiresScope(SsfScopes.Manage)
            .Answers(
                StatusCodes.Status204NoContent,
                StatusCodes.Status400BadRequest,
                StatusCodes.Status404NotFound);

        group.MapGet(Routes.Status, GetStatusAsync)
            .RequiresScope(SsfScopes.Read)
            .AnswersWithBody<StreamStatus>(StatusCodes.Status200OK)
            .Answers(StatusCodes.Status400BadRequest, StatusCodes.Status404NotFound);

        group.MapPost(Routes.Status, UpdateStatusAsync)
            .RequiresScope(SsfScopes.Manage)
            .AnswersWithBody<StreamStatus>(StatusCodes.Status200OK)
            .Answers(
                StatusCodes.Status202Accepted,
                StatusCodes.Status400BadRequest,
                StatusCodes.Status404NotFound,
                StatusCodes.Status415UnsupportedMediaType);

        // Adding a subject answers 200 with no body (SSF 1.0 Section 8.1.3.2), so the success is
        // declared as a status rather than as a shape.
        group.MapPost(Routes.AddSubject, AddSubjectAsync)
            .RequiresScope(SsfScopes.Manage)
            .Answers(
                StatusCodes.Status200OK,
                StatusCodes.Status400BadRequest,
                StatusCodes.Status404NotFound,
                StatusCodes.Status409Conflict,
                StatusCodes.Status415UnsupportedMediaType);

        group.MapPost(Routes.RemoveSubject, RemoveSubjectAsync)
            .RequiresScope(SsfScopes.Manage)
            .Answers(
                StatusCodes.Status204NoContent,
                StatusCodes.Status400BadRequest,
                StatusCodes.Status404NotFound,
                StatusCodes.Status409Conflict,
                StatusCodes.Status415UnsupportedMediaType);

        group.MapPost(Routes.Verify, RequestVerificationAsync)
            .RequiresScope(SsfScopes.Manage)
            .Answers(
                StatusCodes.Status204NoContent,
                StatusCodes.Status400BadRequest,
                StatusCodes.Status404NotFound,
                StatusCodes.Status409Conflict,
                StatusCodes.Status415UnsupportedMediaType,
                StatusCodes.Status429TooManyRequests);

        group.MapPost($"{Routes.Poll}/{{streamId}}", PollAsync)
            .RequiresScope(SsfScopes.Read)
            .AnswersWithBody<PollResponse>(StatusCodes.Status200OK)
            .Answers(
                StatusCodes.Status400BadRequest,
                StatusCodes.Status404NotFound,
                StatusCodes.Status415UnsupportedMediaType);

        // Said out loud because a stream STORES its poll address: the transmitter mints it at create time
        // and a receiver polls it for as long as the stream lives, so an address that does not lead back
        // to this route is a 404 arriving long after the create that succeeded. Single-sourced from the
        // route above for the same reason the configuration document is single-sourced from the five it
        // advertises, and from the ADVERTISED prefix, because that is the one the outside world uses.
        // How an identifier is carried into that address, and why one that cannot be carried is refused
        // here rather than met by a receiver later, is on PollEndpointOf.
        var transmitter = endpoints.ServiceProvider.GetRequiredService<SharedSignalsTransmitterOptions>();
        var pollAuthority = AuthorityOf(transmitter);
        var pollPrefix = AdvertisedPrefixOf(endpointOptions);
        var pollLogger = endpoints.ServiceProvider.GetRequiredService<ILoggerFactory>()
            .CreateLogger(typeof(SharedSignalsEndpointRouteBuilderExtensions));
        endpoints.ServiceProvider.GetRequiredService<PollEndpointLocator>().ServedAt(
            streamId => PollEndpointOf(pollLogger, pollAuthority, pollPrefix, streamId));

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
        var advertisedPrefix = AdvertisedPrefixOf(endpointOptions);

        return endpoints.MapGet(
            endpointOptions.ConfigurationDocumentRoute.HasValue
                ? endpointOptions.ConfigurationDocumentRoute.Value
                : TransmitterConfiguration.WellKnownAddress(issuer).AbsolutePath,
            (SharedSignalsTransmitterOptions current, PollEndpointLocator pollEndpoints) =>
                Results.Json(ConfigurationDocumentOf(current, pollEndpoints, advertisedPrefix)));
    }

    /// <summary>
    /// The prefix the outside world reaches this deployment on: the advertised one where a proxy rewrites
    /// paths, the mapped one otherwise.
    /// </summary>
    private static PathString AdvertisedPrefixOf(SharedSignalsEndpointOptions endpointOptions)
        => endpointOptions.AdvertisedPrefix.HasValue
            ? endpointOptions.AdvertisedPrefix
            : endpointOptions.ManagementPrefix;

    /// <summary>
    /// The authority every endpoint this deployment publishes lives on - the issuer's, which is what a
    /// receiver holding nothing else already has.
    /// </summary>
    private static Uri AuthorityOf(SharedSignalsTransmitterOptions options)
        => new(new Uri(options.Issuer, UriKind.Absolute).GetLeftPart(UriPartial.Authority));

    /// <summary>
    /// Where the poll endpoint of a stream is served, refused when that address would not lead back to
    /// the stream it names.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The identifier is escaped so that one an operator spelled out survives into the URL whole, and the
    /// escaped text is handed over as a <see cref="PathString"/> rather than as a string. The distinction
    /// is load-bearing: PathString's implicit conversion FROM a string decodes - it runs the text back
    /// through UrlDecoder, keeping only %2F - so passing the interpolated string would undo the escaping
    /// one call later, and a '?' would reach <see cref="Uri"/> as a query delimiter. The address would
    /// then be that of a DIFFERENT stream, well-formed and served: "alerts?eu" minting the poll endpoint
    /// of "alerts". Composing by hand avoids the decode and loses the other thing
    /// <see cref="PathString.Add(PathString)"/> does, which is to trim a duplicated separator - a prefix
    /// ending in '/' would mint "/ssf//poll/{id}", which the route does not match.
    /// </para>
    /// <para>
    /// Escaping is not the same as being addressable, so the address is walked back before it is handed
    /// out: what the mapping mints is asked what a request to it would deliver to the handler, and an
    /// identifier that does not come back is refused. That check is a ROUND TRIP rather than a list of
    /// forbidden characters, because the list is never finished. Measuring it through a real host found
    /// two unrelated ways to fail and only one of them is about a character: '/' escapes to %2F, which is
    /// the single escape the path decoder preserves, so the handler receives "alerts%2Feu" and the lookup
    /// misses; while "." and ".." are not escaped at all, and the URI normalizer removes the segment
    /// before the request is sent, so no route matches. The same measurement cleared characters a
    /// blocklist would have caught by association - '\', '?', '#', '%' and non-ASCII all survive intact -
    /// so refusing them would cost an operator names that work.
    /// </para>
    /// <para>
    /// The expected side is built with the <see cref="PathString"/> CONSTRUCTOR, which stores the text as
    /// it is. Only the implicit conversion FROM a string decodes, and that is what the left side uses on
    /// purpose - it is how the ASP.NET decoder gets applied to the minted path. Writing the expected side
    /// the idiomatic way instead, <c>prefix.Add($"...")</c>, compiles identically and decodes it too, and
    /// then an identifier spelled <c>%2E%2E</c> reads as <c>..</c> and is refused although this host
    /// serves it. Dropping the two <c>.Value</c>s and comparing the PathStrings changes nothing today,
    /// so the constructor is the token to keep, not the comparison.
    /// </para>
    /// <para>
    /// Answering null rather than throwing, because both callers can act on it and neither wants a
    /// fault. A DECLARED stream is materialized when <see cref="ConfigurationStreamStore"/> is
    /// constructed - the delivery scheduler takes that store as a hosted service, so the host builds it
    /// while starting - and that store turns the null into a refusal at startup. A RECEIVER asking to
    /// move an existing stream to poll delivery reaches the same code through the management API, which
    /// is how a declared PUSH stream named something unaddressable gets here at request time: it is
    /// admitted at startup, quite rightly, since a push stream needs no address of ours, and then
    /// CAEP 2.3.8.1 obliges this transmitter to entertain a switch to poll. There the null becomes the
    /// refusal the management service already returns for a delivery method it cannot serve, which is
    /// something the receiver can read.
    /// </para>
    /// <para>
    /// A dynamically created stream is named by a GUID and never fails the round trip. A host that names
    /// its own address through <see cref="SharedSignalsTransmitterOptions.PollEndpointFactory"/> never
    /// reaches this code, which is right: what an identifier has to survive there is that host's
    /// routing, not this one's.
    /// </para>
    /// </remarks>
    /// <param name="logger">Where the reason goes, since the value is only a null.</param>
    /// <param name="authority">The transmitter's authority, as its issuer states it.</param>
    /// <param name="prefix">The prefix the outside world reaches the endpoints through.</param>
    /// <param name="streamId">The stream whose queue is served there.</param>
    private static Uri? PollEndpointOf(ILogger logger, Uri authority, PathString prefix, string streamId)
    {
        var route = prefix.Add(new PathString($"{Routes.Poll}/{Uri.EscapeDataString(streamId)}"));
        var address = new Uri(authority, route.Value!);

        PathString delivered = address.AbsolutePath;
        if (delivered.Value == prefix.Add(new PathString($"{Routes.Poll}/{streamId}")).Value)
        {
            return address;
        }

        logger.LogWarning(
            "No poll address can be composed for the stream identifier {StreamId}: a request to "
            + "{Address} reaches this transmitter naming something else, or nothing at all. Name the "
            + "stream something a URL path carries unchanged, or give it push delivery, which needs no "
            + "address of ours.",
            streamId,
            address);

        return null;
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
    /// Says once, at startup, where this deployment falls outside the CAEP Interoperability Profile 1.0
    /// and the host looks unaware of it. Nothing here refuses the host: each of these is a working
    /// deployment, and each is a choice the host is entitled to make knowingly.
    /// <para>
    /// No count is given, because a count over a list that grows is the one thing in a comment guaranteed
    /// to rot. What each warning says, and how optional the member it names really is elsewhere, lives on
    /// that warning's own message.
    /// </para>
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

        if ((services.GetService<SharedSignalsEndpointOptions>() ?? DefaultEndpointOptions)
            .GrantedScopesSelector is null)
            LogScopeCheckingDisabled(logger);

        if (options.DefaultSubjectsMode is StreamSubjectsMode.None)
            LogNoSubjectsIncludedByDefault(logger);
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

        // Same reading of "named" as the two refusal routes below, so the three do not disagree
        // about one word. Here an unnamed stream is an ANSWER rather than an error, so
        // "?stream_id=" lists every stream instead of looking one up under the empty name and
        // reporting it missing.
        return string.IsNullOrEmpty(streamId)
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
        // without it there is nothing to delete. The condition asks whether a stream was
        // NAMED, not whether the parameter was absent: "?stream_id=" is present and names
        // nothing, and RFC 6750 Section 3.1 puts an unusable value in the same
        // invalid_request bucket as a missing one.
        return string.IsNullOrEmpty(streamId)
            ? MissingRequiredParameter(http, StreamMemberNames.StreamId)
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
        // (SSF 1.0 Section 8.1.2.1). Named rather than merely present, for the reason the
        // delete route states.
        return string.IsNullOrEmpty(streamId)
            ? MissingRequiredParameter(http, StreamMemberNames.StreamId)
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
        PollEndpointLocator pollEndpoints,
        PathString prefix)
    {
        var authority = AuthorityOf(options);
        Uri EndpointOf(string route) => new(authority, prefix.Add(route).Value!);

        var deliveryMethods = new List<string> { PushDeliveryMethod.MethodUri };
        if (pollEndpoints.IsOffered)
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
    /// A required parameter names nothing, so the request cannot be acted on. That covers a parameter
    /// left out and one sent empty alike, and RFC 6750 Section 3.1 puts both in the same bucket:
    /// <c>invalid_request</c> is "The request is missing a required parameter, includes an unsupported
    /// parameter or parameter value ... The resource server SHOULD respond with the HTTP 400 (Bad
    /// Request) status code."
    /// </summary>
    /// <remarks>
    /// The header is a MAY here, unlike the 401 below. Section 3 makes <c>WWW-Authenticate</c> mandatory
    /// when the request "does not include authentication credentials or does not contain an access token
    /// that enables access", and adds that a server "MAY include it in response to other conditions as
    /// well". This is one of those others: the receiver was identified and its token is not in question,
    /// only a protocol parameter names nothing. The header carries it anyway, because that is where Section
    /// 3.1's vocabulary lives and it is what the 401 and 403 on these same routes already use, so a
    /// receiver has one place to read a refusal from.
    /// <para>
    /// This answers only where the parameter is REQUIRED. <see cref="GetStreamsAsync"/> takes the same
    /// query parameter and lists every stream when it names nothing, so an unnamed stream there is an
    /// answer rather than an error. Both routes read "named" the same way; they differ in what it means.
    /// </para>
    /// </remarks>
    private static IResult MissingRequiredParameter(HttpContext http, string parameterName)
    {
        var issuer = http.RequestServices.GetService<SharedSignalsTransmitterOptions>()?.Issuer;
        return new ChallengeResult(
            StatusCodes.Status400BadRequest,
            WwwAuthenticate.Challenge(
                BearerScheme,
                ("realm", issuer),
                ("error", "invalid_request"),
                // Says the parameter NAMES NOTHING rather than that it is missing, because the empty
                // value reaches here too and the receiver sent it - a developer told the parameter is
                // missing goes looking for where their client drops it, and it does not drop it.
                ("error_description",
                    $"The required parameter {parameterName} names nothing.")));
    }

    /// <summary>
    /// The answer to a management request that named no receiver: 401 with a bare Bearer challenge.
    /// </summary>
    /// <remarks>
    /// Bare, and deliberately so. This refusal has one cause - nothing identified the caller - which is
    /// what RFC 6750 Section 3.1 describes as a request that "lacks any authentication information", and
    /// for which it says the resource server "SHOULD NOT include an error code or other error
    /// information". A caller that presented nothing has nothing to correct. It is not the only refusal
    /// on this surface: a caller that IS identified but lacks the scope gets 403 from
    /// <see cref="EnforceScopeAsync"/>, which runs first, and that ordering is deliberate.
    /// <para>
    /// That section defines three codes and this method answers none of them. <c>invalid_token</c>
    /// belongs to whoever validates the token, which is the host: this package never sees one, it reads
    /// whatever identity the host's authentication left behind, through
    /// <see cref="SharedSignalsEndpointOptions.ReceiverIdSelector"/>. <c>insufficient_scope</c> IS
    /// emitted by this package, from <see cref="EnforceScopeAsync"/>, once the host supplies the granted
    /// scopes.
    /// </para>
    /// <para>
    /// The third, <c>invalid_request</c> with 400, is also decided here rather than by the host, and is
    /// emitted by <see cref="MissingRequiredParameter"/>.
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
    /// The scheme this surface advertises. Not a claim about how the host authenticates - it is what the
    /// CAEP Interoperability Profile Section 2.7.2 obliges a transmitter to accept: "MUST accept access
    /// tokens in the HTTP header as in Section 2.1 of OAuth 2.0 Bearer Token Usage [RFC6750]". So it is
    /// the scheme a receiver reading this challenge is prepared to act on.
    /// <para>
    /// Section 2.4.3 is the neighbouring requirement and does NOT carry this: it says a receiver "MUST
    /// use OAuth 2.0 [RFC6749]", which is the framework and fixes no token type.
    /// </para>
    /// </summary>
    private const string BearerScheme = "Bearer";

    /// <summary>
    /// Records which scope a route requires, so the filter below can read it back off the endpoint.
    /// </summary>
    private static TBuilder RequiresScope<TBuilder>(this TBuilder builder, string scope)
        where TBuilder : IEndpointConventionBuilder
    {
        builder.WithMetadata(new RequiredScope(scope));
        return builder;
    }

    /// <summary>
    /// Records the statuses a route answers, so a client generated from this surface has a branch for
    /// every answer it can meet and none for an answer it cannot.
    /// </summary>
    /// <remarks>
    /// Bodiless on purpose: the Stream Management API defines no error body - SSF 1.0 Section 8.1 gives
    /// its outcomes as status codes and nothing else. <see cref="AnswersWithBody{TBody}"/> is for the
    /// successes that do carry one.
    /// <para>
    /// Only THREE of the refusals say anything beyond their status. 400, 401 and 403 are built as a
    /// challenge and carry a <c>WWW-Authenticate</c> line naming the reason; 202, 404, 409 and 429 go
    /// through <see cref="Render{TBody}"/> as a bare status, and the description their
    /// <c>ManagementResult</c> carried is dropped there - it exists for the operator's logs, not for
    /// the wire. So a receiver diagnosing one of those four has the status and nothing else.
    /// </para>
    /// </remarks>
    private static void Answers<TBuilder>(this TBuilder builder, params int[] statusCodes)
        where TBuilder : IEndpointConventionBuilder
    {
        foreach (var statusCode in statusCodes)
        {
            // typeof(void), not the parameterless form. A response type whose Type is null is
            // DISCARDED by the API description pipeline every OpenAPI generator reads, and the
            // operation then falls back to an inferred 200 - so the declaration reaches the endpoint,
            // reads correct at the call site, and publishes nothing. void is how the framework's own
            // Produces(int) says "this status carries no body".
            builder.WithMetadata(new ProducesResponseTypeMetadata(statusCode, typeof(void)));
        }
    }

    /// <summary>
    /// Records a status whose response carries a body, and the type of that body.
    /// </summary>
    private static RouteHandlerBuilder AnswersWithBody<TBody>(
        this RouteHandlerBuilder builder, int statusCode)
    {
        builder.WithMetadata(new ProducesResponseTypeMetadata(
            statusCode, typeof(TBody), [MediaTypeNames.Application.Json]));
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
    private static async ValueTask<object?> EnforceScopeAsync(
        EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        var http = context.HttpContext;
        var options = http.RequestServices.GetService<SharedSignalsEndpointOptions>() ?? DefaultEndpointOptions;

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

        var issuer = http.RequestServices.GetService<SharedSignalsTransmitterOptions>()?.Issuer;
        return new ChallengeResult(
            StatusCodes.Status403Forbidden,
            WwwAuthenticate.Challenge(
                BearerScheme,
                ("realm", issuer),
                ("error", "insufficient_scope"),
                ("error_description", "The access token does not carry the scope this operation requires."),
                ("scope", required.Scope)));
    }

    /// <summary>
    /// A status and one <c>WWW-Authenticate</c> line, with no body. The status is the caller's, not
    /// this type's: any refusal whose explanation belongs in the challenge rather than in a payload
    /// builds one of these, and the callers in this file are what say which statuses those are.
    /// Written by hand because <c>Results.Unauthorized()</c> emits no headers, and the header is the
    /// whole point.
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
