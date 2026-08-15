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

namespace Abblix.SharedSignals.Transmitter;

/// <summary>
/// One stream as a closed deployment declares it: the shape a first-party transmitter binds
/// from configuration when its receivers are its own products, known at deploy time and
/// provisioned by the same operator on both sides. The members are deliberately
/// binder-friendly - strings, arrays, a URL - so the whole stream set can live in the host's
/// configuration.
/// </summary>
public sealed record ConfiguredStream
{
    /// <summary>
    /// The receiver identity the stream belongs to, matching what the host's authentication
    /// yields for that receiver's management and poll calls.
    /// </summary>
    /// <remarks>
    /// <c>required</c> binds the host that writes these in code and nothing else: the
    /// configuration binder does not honour it, so a settings file omitting this member produces
    /// null here without complaint. The guarantee is restored where the declarations are read -
    /// <see cref="ConfigurationStreamStore"/> refuses a stream missing either identifier - and the
    /// marker is kept because it still catches the code-first half at compile time.
    /// </remarks>
    public required string ReceiverId { get; init; }

    /// <summary>
    /// The stream's identifier. Fixed by configuration rather than generated, so both sides of
    /// a first-party pair can name it in their own settings.
    /// </summary>
    public required string StreamId { get; init; }

    /// <summary>
    /// The "aud" of the stream's SETs; empty uses the receiver identity itself, the default the
    /// dynamic path also takes (SSF 1.0 Section 4.1.8).
    /// </summary>
    public string[] Audiences { get; init; } = [];

    /// <summary>
    /// The event types the receiver wants; what the stream carries is the intersection with the
    /// transmitter's supported set (SSF 1.0 Section 8.1.1).
    /// </summary>
    public string[] EventsRequested { get; init; } = [];

    /// <summary>
    /// The receiver's push endpoint; set makes the stream push-delivered, absent makes it poll
    /// over the transmitter's own endpoint (SSF 1.0 Section 6.1).
    /// </summary>
    public Uri? PushEndpointUrl { get; init; }

    /// <summary>
    /// The whole Authorization header line the transmitter sends with every push
    /// (SSF 1.0 Section 6.1.1). A secret: in a deployment it arrives through the host's secret
    /// mechanism - an environment variable mounted from a secret store - never as plaintext in
    /// a settings file.
    /// </summary>
    public string? PushAuthorizationHeader { get; init; }

    /// <summary>
    /// Which subjects the stream covers. The default here is <see cref="StreamSubjectsMode.All"/>,
    /// the opposite of the dynamic path's conservative NONE - a first-party receiver is
    /// provisioned to hear everything, and per-subject bookkeeping is exactly what a static
    /// deployment does without.
    /// </summary>
    public StreamSubjectsMode SubjectsMode { get; init; } = StreamSubjectsMode.All;

    /// <summary>
    /// A human-readable description of the stream (SSF 1.0 Section 8.1.1).
    /// </summary>
    public string? Description { get; init; }
}
