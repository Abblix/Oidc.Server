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

using System.Text.Json;
using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.SecurityEvents.Abstractions;
using Abblix.SecurityEvents.Events;
using Abblix.SecurityEvents.Subjects;

namespace Abblix.SecurityEvents;

/// <summary>
/// Builds a SET whose envelope satisfies RFC 8417 by construction: the required claims are
/// enforced, the "typ" header is fixed, and the one claim the profile forbids cannot be written.
/// </summary>
/// <remarks>
/// The builder is reusable: <see cref="Build"/> materializes an independent token each time, so a
/// transmitter may keep one builder per event shape and vary a claim between builds without the
/// tokens sharing state.
/// </remarks>
/// <param name="clock">
/// Supplies "iat" when <see cref="WithIssuedAt"/> is not called. Defaults to the system clock; a
/// test hands in a fake to build tokens at a chosen instant.</param>
public sealed class SecurityEventTokenBuilder(TimeProvider? clock = null)
{
    /// <summary>
    /// The envelope claims a dedicated builder method manages, kept so <see cref="WithClaim"/> can
    /// refuse to write them: two doors to one claim would make the last write win silently, and
    /// which door wrote last is exactly the thing a reader of fluent code cannot see.
    /// </summary>
    private static readonly IReadOnlyDictionary<string, string> ManagedClaims =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            [JwtClaimTypes.Issuer] = nameof(WithIssuer),
            [JwtClaimTypes.Audience] = nameof(WithAudience),
            [JwtClaimTypes.JwtId] = nameof(WithJwtId),
            [JwtClaimTypes.IssuedAt] = nameof(WithIssuedAt),
            [JwtClaimTypes.Subject] = nameof(WithSubject),
            [JwtClaimTypes.Events] = nameof(WithEvent),
            [IanaClaimTypes.Txn] = nameof(WithTransactionId),
            [IanaClaimTypes.Toe] = nameof(WithTimeOfEvent),
            [IanaClaimTypes.SubId] = nameof(WithSubjectId),
        };

    private readonly TimeProvider _clock = clock ?? TimeProvider.System;
    private readonly List<string> _audiences = [];
    private readonly EventsCollection _events = new();
    private readonly List<KeyValuePair<string, JsonNode?>> _extraClaims = [];

    private string? _issuer;
    private string? _jwtId;
    private string? _subject;
    private SubjectIdentifier? _subjectId;
    private string? _transactionId;
    private DateTimeOffset? _issuedAt;
    private DateTimeOffset? _timeOfEvent;

    /// <summary>
    /// Sets the "iss" claim: the service provider publishing the SET. REQUIRED
    /// (RFC 8417 Section 2.2).
    /// </summary>
    /// <param name="issuer">The issuer identifier.</param>
    public SecurityEventTokenBuilder WithIssuer(string issuer)
    {
        ArgumentException.ThrowIfNullOrEmpty(issuer);

        _issuer = issuer;
        return this;
    }

    /// <summary>
    /// Adds audiences to the "aud" claim. RECOMMENDED (RFC 8417 Section 2.2); calling more than
    /// once accumulates.
    /// </summary>
    /// <param name="audiences">The audience identifiers to add.</param>
    public SecurityEventTokenBuilder WithAudience(params string[] audiences)
    {
        ArgumentNullException.ThrowIfNull(audiences);

        foreach (var audience in audiences)
        {
            if (string.IsNullOrEmpty(audience))
            {
                throw new ArgumentException(
                    "An audience identifier must be neither null nor empty.",
                    nameof(audiences));
            }

            _audiences.Add(audience);
        }

        return this;
    }

    /// <summary>
    /// Sets the "jti" claim: the SET's unique identifier within its event feed, by which a
    /// recipient tells a redelivery from a new event. REQUIRED (RFC 8417 Section 2.2).
    /// </summary>
    /// <param name="jwtId">The token identifier.</param>
    public SecurityEventTokenBuilder WithJwtId(string jwtId)
    {
        ArgumentException.ThrowIfNullOrEmpty(jwtId);

        _jwtId = jwtId;
        return this;
    }

    /// <summary>
    /// Sets the "iat" claim explicitly instead of taking the clock's reading at build time.
    /// </summary>
    /// <param name="issuedAt">When the SET is issued.</param>
    public SecurityEventTokenBuilder WithIssuedAt(DateTimeOffset issuedAt)
    {
        _issuedAt = issuedAt;
        return this;
    }

    /// <summary>
    /// Sets the "sub" claim: the principal the SET is about. OPTIONAL (RFC 8417 Section 2.2), and
    /// many profiles identify the subject inside the event payload instead - Section 3 recommends
    /// against "sub" when the subject is not globally unique and has a different issuer than the
    /// SET.
    /// </summary>
    /// <param name="subject">The subject value, in whatever form the profile defines.</param>
    public SecurityEventTokenBuilder WithSubject(string subject)
    {
        ArgumentException.ThrowIfNullOrEmpty(subject);

        _subject = subject;
        return this;
    }

    /// <summary>
    /// Sets the "sub_id" claim: the Subject Identifier of the principal the SET is about
    /// (RFC 9493 Section 4.2).
    /// </summary>
    /// <remarks>
    /// Serialization happens at <see cref="Build"/> under the identifier's runtime type, so a
    /// profile-specific subtype travels correctly without this builder knowing its format - the
    /// custom-formats registration matters only to the reader.
    /// </remarks>
    /// <param name="subjectId">The Subject Identifier, in any Identifier Format.</param>
    public SecurityEventTokenBuilder WithSubjectId(SubjectIdentifier subjectId)
    {
        ArgumentNullException.ThrowIfNull(subjectId);

        _subjectId = subjectId;
        return this;
    }

    /// <summary>
    /// Sets the "txn" claim: a transaction identifier correlating this SET with other JWTs issued
    /// for the same transaction. OPTIONAL (RFC 8417 Section 2.2).
    /// </summary>
    /// <param name="transactionId">The transaction identifier.</param>
    public SecurityEventTokenBuilder WithTransactionId(string transactionId)
    {
        ArgumentException.ThrowIfNullOrEmpty(transactionId);

        _transactionId = transactionId;
        return this;
    }

    /// <summary>
    /// Sets the "toe" claim: when the event itself occurred. OPTIONAL (RFC 8417 Section 2.2) -
    /// omitting it is the issuer's way of not sharing an event time.
    /// </summary>
    /// <param name="timeOfEvent">When the event occurred; a profile may allow it to be approximate.
    /// </param>
    public SecurityEventTokenBuilder WithTimeOfEvent(DateTimeOffset timeOfEvent)
    {
        _timeOfEvent = timeOfEvent;
        return this;
    }

    /// <summary>
    /// Adds an event statement to the "events" claim. At least one is required for the build to
    /// succeed; several express aspects of the same state transition (RFC 8417 Section 2), such
    /// as an extension accompanying a primary event.
    /// </summary>
    /// <param name="eventType">The event identifier URI.</param>
    /// <param name="payload">
    /// The event's payload; null stands for an event with no payload claims and is written as the
    /// empty JSON object (RFC 8417 Section 2).</param>
    /// <exception cref="ArgumentException">
    /// A statement with the same event identifier was already added (RFC 8417 Section 2.2).
    /// </exception>
    public SecurityEventTokenBuilder WithEvent(string eventType, JsonObject? payload = null)
    {
        _events.Add(eventType, payload);
        return this;
    }

    /// <summary>
    /// Adds an event statement whose payload is a typed model, serialized here so the caller
    /// works in terms of the profiling specification's type rather than raw JSON.
    /// </summary>
    /// <typeparam name="TPayload">The type modelling the event's payload.</typeparam>
    /// <param name="eventType">The event identifier URI.</param>
    /// <param name="payload">The payload value.</param>
    /// <param name="serializerOptions">
    /// Options for payload serialization; null takes the serializer's defaults. A receiver reads
    /// the payload back with the options its <see cref="EventTypeRegistry"/> holds, so a
    /// transmitter and receiver sharing a dictionary package agree by construction.</param>
    /// <exception cref="ArgumentException">
    /// A statement with the same event identifier was already added, or the payload serialized
    /// into something other than a JSON object, which RFC 8417 Section 2.2 requires the value to
    /// be.</exception>
    public SecurityEventTokenBuilder WithEvent<TPayload>(
        string eventType,
        TPayload payload,
        JsonSerializerOptions? serializerOptions = null)
        where TPayload : IEventPayload
    {
        ArgumentNullException.ThrowIfNull(payload);

        // A passthrough payload re-transmits what arrived, not a serialization of the wrapper:
        // the wrapper is this package's shape, while its Json is the event's.
        var node = payload is UnknownEventPayload unknown
            ? unknown.Json.DeepClone()
            : JsonSerializer.SerializeToNode(payload, payload.GetType(), serializerOptions);

        if (node is not JsonObject payloadObject)
        {
            throw new ArgumentException(
                $"The payload of event '{eventType}' serialized into {node?.GetValueKind().ToString() ?? "null"}, "
                + "but an event payload must be a JSON object (RFC 8417 Section 2.2).",
                nameof(payload));
        }

        _events.Add(eventType, payloadObject);
        return this;
    }

    /// <summary>
    /// Adds a profile-specific envelope claim, which RFC 8417 Section 2 explicitly leaves room
    /// for.
    /// </summary>
    /// <param name="name">The claim name.</param>
    /// <param name="value">The claim value.</param>
    /// <exception cref="ArgumentException">
    /// The name is "exp", a claim a dedicated builder method manages, or a name already written
    /// through this method - every claim has exactly one writer. "exp" is rejected
    /// outright: RFC 8417 Section 2.2 already advises against it for a token that records
    /// history, and Sections 4.1 and 4.2 make its ABSENCE the wall between a SET and the ID and
    /// access tokens an attacker would like to pass one off as - this builder takes that defence
    /// as its own profile rule rather than leaving it to every caller.</exception>
    public SecurityEventTokenBuilder WithClaim(string name, JsonNode? value)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);

        if (name == JwtClaimTypes.ExpiresAt)
        {
            throw new ArgumentException(
                $"A SET built here never carries '{JwtClaimTypes.ExpiresAt}': its absence is what stops the "
                + "token doubling as an ID or access token (RFC 8417 Sections 4.1 and 4.2).",
                nameof(name));
        }

        if (ManagedClaims.TryGetValue(name, out var method))
        {
            throw new ArgumentException(
                $"The '{name}' claim is managed by {method}; writing it here too would leave two doors to "
                + "one claim.",
                nameof(name));
        }

        if (_extraClaims.Any(claim => claim.Key == name))
        {
            throw new ArgumentException(
                $"The '{name}' claim was already written; accepting a second value would let the last "
                + $"write win silently at {nameof(Build)} - the same two-doors problem the managed "
                + "claims refuse.",
                nameof(name));
        }

        _extraClaims.Add(new KeyValuePair<string, JsonNode?>(name, value));
        return this;
    }

    /// <summary>
    /// Materializes the SET, verifying the claims RFC 8417 Section 2.2 requires are in place.
    /// </summary>
    /// <returns>An independent token; later builder changes do not reach it.</returns>
    /// <exception cref="InvalidOperationException">
    /// The issuer or the token identifier is missing, or no event statement was added.</exception>
    public SecurityEventToken Build()
    {
        if (_issuer is null)
        {
            throw new InvalidOperationException(
                $"A SET requires the '{JwtClaimTypes.Issuer}' claim (RFC 8417 Section 2.2); call "
                + $"{nameof(WithIssuer)} before {nameof(Build)}.");
        }

        if (_jwtId is null)
        {
            throw new InvalidOperationException(
                $"A SET requires the '{JwtClaimTypes.JwtId}' claim (RFC 8417 Section 2.2); call "
                + $"{nameof(WithJwtId)} before {nameof(Build)}.");
        }

        if (_events.Count == 0)
        {
            throw new InvalidOperationException(
                $"A SET requires at least one event statement in '{JwtClaimTypes.Events}' "
                + $"(RFC 8417 Section 2); call {nameof(WithEvent)} before {nameof(Build)}.");
        }

        var token = new JsonWebToken
        {
            Header = { Type = SecurityEventToken.TokenType },
            Payload =
            {
                Issuer = _issuer,
                // The claim is REQUIRED (RFC 8417 Section 2.2), so absence of an explicit value
                // means "now", never "no iat".
                IssuedAt = _issuedAt ?? _clock.GetUtcNow(),
                JwtId = _jwtId,
                Subject = _subject,
            },
        };

        var payload = token.Payload.Json;

        // Only a present claim is written: an empty "aud" is not a claim about audiences, and a
        // null "txn" is not a transaction.
        if (_audiences.Count > 0)
        {
            token.Payload.Audiences = _audiences;
        }

        if (_subjectId is not null)
        {
            // Serialized fresh per Build under the runtime type, so each token owns its node and
            // the polymorphic dispatch never needs the reader-side format registration.
            payload.SetProperty(
                IanaClaimTypes.SubId,
                JsonSerializer.SerializeToNode<SubjectIdentifier>(_subjectId));
        }

        if (_transactionId is not null)
        {
            payload.SetProperty(IanaClaimTypes.Txn, _transactionId);
        }

        if (_timeOfEvent is not null)
        {
            payload.SetUnixTimeSeconds(IanaClaimTypes.Toe, _timeOfEvent);
        }

        foreach (var (name, value) in _extraClaims)
        {
            // DeepClone, because a JsonNode belongs to one document: without the copy the second
            // Build would steal the node from the first token, and the builder's reusability
            // promise would break exactly one call too late to notice.
            payload.SetProperty(name, value?.DeepClone());
        }

        payload.SetProperty(JwtClaimTypes.Events, _events.Json.DeepClone());

        return new SecurityEventToken(token);
    }

    /// <summary>
    /// Materializes the SET and hands it to the signer, returning the compact serialization a
    /// transmitter delivers.
    /// </summary>
    /// <param name="signer">The signer owning key and algorithm choice.</param>
    /// <param name="cancellationToken">Cancels the signing operation mid-flight.</param>
    public Task<string> SignAsync(ISecurityEventTokenSigner signer, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(signer);

        return signer.SignAsync(Build(), cancellationToken);
    }
}
