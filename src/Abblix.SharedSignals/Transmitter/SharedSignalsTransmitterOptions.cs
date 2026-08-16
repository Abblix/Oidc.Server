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
    public StreamSubjectsMode DefaultSubjectsMode { get; init; } = StreamSubjectsMode.None;

    /// <summary>
    /// Whether one receiver may hold several streams. When false - the default - a second
    /// create answers "409 Conflict", and the receiver's move is to read and update the stream
    /// it has (SSF 1.0 Section 8.1.1.1).
    /// </summary>
    public bool AllowMultipleStreamsPerReceiver { get; init; }

    /// <summary>
    /// Derives the transmitter-supplied poll endpoint URL for a stream
    /// (SSF 1.0 Section 6.1.2). Null means this transmitter does not offer poll delivery: a
    /// create that asks for poll - or omits delivery, which Section 8.1.1.1 reads as poll - is
    /// then refused with "400 Bad Request".
    /// </summary>
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
    /// Where this transmitter publishes the JWK Set its SETs verify against, advertised as
    /// "jwks_uri" (SSF 1.0 Section 7.1); null publishes no key location, leaving key
    /// distribution to some out-of-band agreement.
    /// </summary>
    public Uri? JwksUri { get; init; }

    /// <summary>
    /// The authorization scheme descriptions the configuration metadata advertises
    /// (SSF 1.0 Section 7.1.1), kept as raw JSON because their shape is scheme-specific and
    /// authorization itself is the host's, not this package's.
    /// </summary>
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
