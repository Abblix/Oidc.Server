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

namespace Abblix.Oidc.Client.Features.Authorization.Responses;

/// <summary>
/// What kind of answer came back from the authorization endpoint.
/// </summary>
public enum AuthorizationResponseKind
{
    /// <summary>
    /// Nothing this client can act on: no code, no token, no error.
    /// </summary>
    /// <remarks>
    /// Kept as its own case rather than folded into the error one, because it means something different
    /// to whoever has to answer for it. An error is the provider saying no, in a vocabulary defined for
    /// saying no; this is a request that reached the callback address without being an authorization
    /// response at all - a stray link, a scanner, a misconfigured route. It is also what a token-returning
    /// response looks like when it was delivered by fragment and the fragment never reached the server.
    /// </remarks>
    Unrecognized = 0,

    /// <summary>
    /// A successful response, carrying whichever artifacts its flow returns: an authorization code
    /// (RFC 6749 section 4.1.2), an ID Token, an access token, or a combination of them.
    /// </summary>
    /// <remarks>
    /// Which artifacts arrived is not the same question as whether they were the ones asked for; the
    /// handler decides that against the configured flow, so that a response carrying more than was
    /// requested is refused rather than partly used.
    /// </remarks>
    Success,

    /// <summary>
    /// The provider refused, and said why (RFC 6749 section 4.1.2.1).
    /// </summary>
    Error,

    /// <summary>
    /// Success parameters and an error arrived together, which no specification defines.
    /// </summary>
    /// <remarks>
    /// Named rather than resolved. Picking either reading invents behaviour the specifications do not
    /// describe, and the safe-looking choice is the dangerous one: treating it as an error discards real
    /// artifacts, while treating it as a success acts on artifacts the provider paired with a refusal.
    /// A response nobody wrote down the meaning of is not one to guess at.
    /// </remarks>
    Contradictory,
}
