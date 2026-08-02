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
using Abblix.Jwt;

namespace Abblix.SecurityEvents;

/// <summary>
/// A Security Event Token (SET): a JWT whose claims describe one or more aspects of a security
/// event that occurred to a subject (RFC 8417 Section 2). This type is a typed view over the
/// underlying <see cref="JsonWebToken"/>, naming the claims the SET profile gives meaning to.
/// </summary>
/// <remarks>
/// The view asserts nothing about conformance. Whether a given token IS a valid SET - carries the
/// right "typ", a non-empty "events" claim, no "exp" - is the validation pipeline's verdict, not
/// a property of this wrapper: a token read off the wire keeps whatever shape it arrived in until
/// validated. <see cref="SecurityEventTokenBuilder"/> produces conformant instances by
/// construction.
/// </remarks>
/// <param name="token">The token to view. Its claims are read in place, never copied.</param>
public sealed class SecurityEventToken(JsonWebToken token)
{
    /// <summary>
    /// The "typ" header value declaring a JWT to be a SET. RFC 8417 Section 2.3 registers the
    /// "application/secevent+jwt" media type and, per RFC 7515 Section 4.1.9, recommends omitting
    /// the "application/" prefix in the header, so the value used SHOULD be "secevent+jwt".
    /// An alias into the core's shared registry, kept here because the value is a property of
    /// THIS token type and reads that way at call sites.
    /// </summary>
    public const string TokenType = JsonWebTokenTypes.SecurityEvent;

    /// <summary>
    /// The underlying JWT, for everything the SET profile does not name: header parameters,
    /// profile-specific envelope claims, serialization.
    /// </summary>
    public JsonWebToken Token { get; } = token;

    /// <summary>
    /// The "iss" claim: the service provider publishing the SET. REQUIRED (RFC 8417 Section 2.2),
    /// and not necessarily the issuer of the security subject - the two coincide only when a
    /// profile says so.
    /// </summary>
    public string? Issuer => Token.Payload.Issuer;

    /// <summary>
    /// The "iat" claim: when the SET was issued. REQUIRED (RFC 8417 Section 2.2).
    /// </summary>
    public DateTimeOffset? IssuedAt => Token.Payload.IssuedAt;

    /// <summary>
    /// The "jti" claim: the SET's unique identifier, unique within a particular event feed, by
    /// which a recipient can tell a redelivery from a new event. REQUIRED (RFC 8417 Section 2.2).
    /// </summary>
    public string? JwtId => Token.Payload.JwtId;

    /// <summary>
    /// The "aud" claim: the audiences the SET is intended for. RECOMMENDED (RFC 8417 Section 2.2).
    /// </summary>
    public IEnumerable<string> Audiences => Token.Payload.Audiences;

    /// <summary>
    /// The "sub" claim: the principal the SET is about. OPTIONAL (RFC 8417 Section 2.2) - many
    /// profiles identify the subject inside the event payload instead, which is where the Subject
    /// Identifiers of RFC 9493 live.
    /// </summary>
    public string? Subject => Token.Payload.Subject;

    /// <summary>
    /// The "txn" claim: a transaction identifier correlating this SET with other JWTs issued for
    /// the same transaction. OPTIONAL (RFC 8417 Section 2.2).
    /// </summary>
    public string? TransactionId => Token.Payload.Json.GetProperty<string>(IanaClaimTypes.Txn);

    /// <summary>
    /// The "toe" claim: when the event itself occurred, as opposed to when the SET about it was
    /// issued. OPTIONAL (RFC 8417 Section 2.2): by omitting it, the issuer declines to share an
    /// event time, and the value may be approximate where a profile says so.
    /// </summary>
    public DateTimeOffset? TimeOfEvent => Token.Payload.Json.GetUnixTimeSeconds(IanaClaimTypes.Toe);

    private EventsCollection? _eventsView;

    /// <summary>
    /// The "events" claim: the event statements this SET expresses, keyed by event identifier URI.
    /// Null when the claim is absent or is not a JSON object - a shape for the validation pipeline
    /// to reject, not for this view to repair.
    /// </summary>
    /// <remarks>
    /// The view is a read-through wrapper cached per underlying node, so repeated reads cost
    /// nothing and a claim replaced wholesale still yields a fresh view over the new node.
    /// </remarks>
    public EventsCollection? Events
    {
        get
        {
            if (Token.Payload.Json[IanaClaimTypes.Events] is not JsonObject events)
            {
                return null;
            }

            if (_eventsView is null || !ReferenceEquals(_eventsView.Json, events))
            {
                _eventsView = new EventsCollection(events);
            }

            return _eventsView;
        }
    }
}
