// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Text.Json.Nodes;
using Abblix.SharedSignals.Model;

namespace Abblix.SharedSignals.Transmitter;

/// <summary>
/// What a transmitter deployment decides once: its identity, its event vocabulary, and the
/// policies SSF 1.0 leaves to the implementation - how many streams a receiver may hold
/// (Section 8.1.1.1), what a new stream covers by default (Section 7.1), and how often
/// verification may be asked for (Section 8.1.1).
/// </summary>
public sealed record SharedSignalsTransmitterOptions
{
    /// <summary>
    /// The transmitter's issuer identifier: the "iss" of every SET and of every stream
    /// configuration, identical to what the configuration metadata asserts
    /// (SSF 1.0 Sections 7.1, 4.1.6).
    /// </summary>
    public required string Issuer { get; init; }

    /// <summary>
    /// The event types this transmitter can emit, advertised in each stream's
    /// "events_supported"; what a stream actually carries is the intersection with the
    /// receiver's request (SSF 1.0 Section 8.1.1).
    /// </summary>
    public IReadOnlyList<string> EventsSupported { get; init; } = [];

    /// <summary>
    /// What a newly created stream covers by default (SSF 1.0 Section 7.1). The conservative
    /// default is <see cref="StreamSubjectsMode.None"/>: nothing flows until the receiver names
    /// its subjects, so a misconfigured stream leaks nothing.
    /// </summary>
    /// <remarks>
    /// A deployment targeting the CAEP Interoperability Profile 1.0 sets this to
    /// <see cref="StreamSubjectsMode.All"/>. Its Section 2.4.4 tells a receiver to "assume that all
    /// subjects are implicitly included in a Stream, without any Add Subject method invocations", so a
    /// conformant receiver adds none - and against a transmitter covering nothing by default it receives
    /// nothing, with no error on either side to say why. The profile binds only the receiver, so the
    /// default is left where it is and said out loud at startup instead.
    /// <para>
    /// Changing it reaches only streams created afterwards. A stream takes its mode at creation, as
    /// <see cref="StreamSubjectsMode"/> says, so a deployment that has already stored streams under
    /// <see cref="StreamSubjectsMode.None"/> has to delete and recreate them - and the startup warning
    /// stops the moment this option changes, whether or not that was done.
    /// </para>
    /// </remarks>
    public StreamSubjectsMode DefaultSubjectsMode { get; init; } = StreamSubjectsMode.None;

    /// <summary>
    /// Whether one receiver may hold several streams. When false - the default - a second
    /// create answers "409 Conflict", and the receiver's move is to read and update the stream
    /// it has (SSF 1.0 Section 8.1.1.1).
    /// </summary>
    public bool AllowMultipleStreamsPerReceiver { get; init; }

    /// <summary>
    /// Where the outside world reaches this transmitter's poll endpoint for a stream
    /// (SSF 1.0 Section 6.1.2). Unset takes the address the poll route was mapped on, so a host that
    /// maps the transmitter's endpoints offers poll delivery without naming anything.
    /// </summary>
    /// <remarks>
    /// Set it when the poll address is not this deployment's advertised prefix plus the poll route on the
    /// issuer's authority - a separate host name for delivery, say, or a path the route shape cannot
    /// express. A proxy that merely REWRITES paths needs nothing here: <c>AdvertisedPrefix</c> is what the
    /// mapping declares, so the poll address follows it along with the five management addresses. It wins
    /// over the mapped address wherever both exist.
    /// <para>
    /// It is also how a host that maps its own routes - on some other web framework, or by hand - offers
    /// poll at all, since nothing else then knows the address. With neither source the transmitter offers
    /// no poll delivery: the configuration document omits the method, and a create asking for poll, or
    /// omitting delivery, which Section 8.1.1.1 reads as poll, is refused with "400 Bad Request".
    /// </para>
    /// </remarks>
    public Func<string, Uri>? PollEndpointFactory { get; init; }

    /// <summary>
    /// Derives the "aud" of a receiver's streams from the receiver's identity. The default
    /// uses the identity itself: "Values that uniquely identify the Receiver to the
    /// Transmitter MAY be used" (SSF 1.0 Section 4.1.8).
    /// </summary>
    public Func<string, IReadOnlyList<string>>? AudiencesFactory { get; init; }

    /// <summary>
    /// The least time between verification requests, advertised as
    /// "min_verification_interval" and enforced with "429 Too Many Requests"
    /// (SSF 1.0 Sections 8.1.1, 8.1.4.2); null advertises no bound and throttles nothing.
    /// </summary>
    public TimeSpan? MinVerificationInterval { get; init; }

    /// <summary>
    /// Where this transmitter publishes the JWK Set its SETs verify against, advertised as "jwks_uri"
    /// (SSF 1.0 Section 7.1). Required in practice AND on paper: that section says "This value MUST be
    /// specified if the Transmitter intends to generate signed JWTs", and this transmitter signs every
    /// event it sends. Left null, no receiver can obtain a key and the deployment is told so at startup.
    /// </summary>
    public Uri? JwksUri { get; init; }

    /// <summary>
    /// The authorization scheme descriptions the configuration metadata advertises
    /// (SSF 1.0 Section 7.1.1), kept as raw JSON because their shape is scheme-specific and
    /// authorization itself is the host's, not this package's.
    /// </summary>
    /// <remarks>
    /// Three settings, and the first of them makes an assertion on the deployment's behalf.
    /// <list type="bullet">
    ///   <item>Left unset, the document advertises OAuth 2.0 - the value the CAEP Interoperability
    ///   Profile 1.0 Section 2.3.7 requires and Section 2.4.3 requires receivers to use. That is a claim
    ///   about how this deployment authorizes its Stream Management API, made by this package because the
    ///   profile demands it and most deployments do exactly that. A deployment authorizing by something
    ///   else must not leave it unset.</item>
    ///   <item>Set to a list, the member is that list verbatim. The host owns it, including whether the
    ///   OAuth entry is in it, and is told once at startup if it is not.</item>
    ///   <item>Set to an EMPTY list, the member is omitted entirely. That is how a deployment says it
    ///   advertises no scheme at all, and nothing warns about it, because it is a decision rather than an
    ///   oversight.</item>
    /// </list>
    /// </remarks>
    public IReadOnlyList<JsonObject>? AuthorizationSchemes { get; init; }

    /// <summary>
    /// The receiver origins this deployment may deliver to whatever their address, matched by scheme, host and
    /// port. Empty leaves every receiver to the ordinary rules: HTTPS, and an address outside the deployment's
    /// own network.
    /// </summary>
    /// <remarks>
    /// A receiver names its own delivery endpoint, so the address arrives from outside and is refused when it
    /// points inside the network. That refusal is wrong for exactly one deployment shape: a receiver of the
    /// operator's own, reached at a private address. Naming it here is how an operator says so, and it is
    /// deliberately an origin rather than a switch, so permitting one receiver does not permit the rest.
    /// </remarks>
    public IReadOnlyList<Uri> AllowedReceiverAddresses { get; init; } = [];

    /// <summary>
    /// How often the transmitter sweeps its push streams and delivers what is queued; null leaves
    /// the sweeping to the host.
    /// </summary>
    /// <remarks>
    /// Push delivery is the transmitter reaching out, so something has to decide when. A default
    /// rather than an opt-in because the alternative fails silently: every part works, none of
    /// them is called, and a host sees streams created and events queued with nothing delivered
    /// and nothing logged. Null is for a host that drives passes itself - from its own scheduler,
    /// or one pass per business event.
    /// </remarks>
    public TimeSpan? PushDeliveryInterval { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// How long one instance's claim on a stream's delivery holds, and therefore the longest a
    /// single pass over that stream may run.
    /// </summary>
    /// <remarks>
    /// The claim keeps concurrent instances off one another's streams, and it expires because
    /// expiry is the only release an instance that died mid-pass can perform. That makes this one
    /// value two limits at once, erring in opposite directions and both of them safe: too short
    /// cuts a legitimate pass off at the deadline and its remainder goes out on the next one, too
    /// long parks a stream for the rest of the claim after the instance holding it dies. The
    /// default is comfortably longer than a pass over a responsive receiver and well short of an
    /// outage anybody would sit through.
    /// </remarks>
    public TimeSpan PushDeliveryLeaseDuration { get; init; } = TimeSpan.FromMinutes(1);

    /// <summary>
    /// The "default_subjects" value the mode advertises, kept beside the enum so the wire word
    /// and the behavior cannot drift apart.
    /// </summary>
    public string DefaultSubjectsValue => DefaultSubjectsMode switch
    {
        StreamSubjectsMode.All => TransmitterConfiguration.DefaultSubjectBehaviors.All,
        StreamSubjectsMode.None => TransmitterConfiguration.DefaultSubjectBehaviors.None,
        _ => throw new InvalidOperationException(
            $"Unknown {nameof(StreamSubjectsMode)}: {DefaultSubjectsMode}."),
    };
}
