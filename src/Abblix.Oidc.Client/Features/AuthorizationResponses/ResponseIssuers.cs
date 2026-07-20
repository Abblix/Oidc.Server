// Abblix OIDC Client Library
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

namespace Abblix.Oidc.Client.Features.AuthorizationResponses;

/// <summary>
/// Every issuer identifier one authorization response has to offer, and the one it should have been.
/// </summary>
/// <remarks>
/// A response can name its issuer more than once - once in the <c>iss</c> parameter, and again in the
/// <c>iss</c> claim of an ID Token returned from the authorization endpoint. RFC 9207 section 4 turns
/// that into an obligation: "if a client receives an authorization response that contains multiple
/// issuer identifiers, the client MUST reject the response if these issuer identifiers do not match".
/// Gathering them into one record is what makes that check expressible; checked one at a time against
/// the expected value, two identifiers that disagree with each other could both pass.
/// </remarks>
public sealed record ResponseIssuers
{
    /// <summary>
    /// The issuer this client sent the authorization request to, recorded at request time.
    /// </summary>
    /// <remarks>
    /// Taken from the state stored for this login rather than read fresh, because the question is which
    /// server this response was supposed to come from. A provider whose metadata changed between the
    /// request and the response would otherwise validate a mix-up as a match.
    /// </remarks>
    public required string Expected { get; init; }

    /// <summary>
    /// The <c>iss</c> parameter of the response, already form-urldecoded, or <see langword="null"/>
    /// when the response carried none.
    /// </summary>
    /// <remarks>
    /// RFC 9207 section 2.4 requires the decode before the comparison: "Clients MUST then decode the
    /// value from its 'application/x-www-form-urlencoded' form according to Appendix B of [RFC6749]".
    /// It is done by whoever parsed the response, since that is where the encoded form still exists.
    /// </remarks>
    public string? Parameter { get; init; }

    /// <summary>
    /// The <c>iss</c> claim of an ID Token that came back from the authorization endpoint, or
    /// <see langword="null"/> when no ID Token arrived there.
    /// </summary>
    /// <remarks>
    /// Only from the AUTHORIZATION endpoint. An ID Token collected later from the token endpoint is not
    /// part of the authorization response and says nothing about which server sent this one - by then
    /// the authorization code has already been handed over, which is the moment a mix-up steals it.
    /// </remarks>
    public string? IdentityTokenClaim { get; init; }
}
