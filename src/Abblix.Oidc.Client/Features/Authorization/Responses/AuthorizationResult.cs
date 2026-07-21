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

using Abblix.Jwt;
using Abblix.Oidc.Client.Features.Authorization.Context;

namespace Abblix.Oidc.Client.Features.Authorization.Responses;

/// <summary>
/// An authorization response that has passed every check, carrying whichever artifacts its flow returns.
/// </summary>
/// <remarks>
/// That this exists at all means the response survived the whole pipeline: the issuer matched, the login
/// was held and is now spent, the artifacts are the ones the configured flow asks for, and any ID Token
/// among them has been validated. There is no partially-validated variant.
/// The context comes back alongside, because the work that follows needs what the request put aside and
/// the response does not carry: the code verifier and the exact redirect address to redeem a code with,
/// and the address to return the user to.
/// It holds a secret in doing so - the PKCE code verifier - which is why this record renders itself
/// without it. A caller should reach for the members it wants rather than serialize the whole thing.
/// </remarks>
/// <param name="Context">
/// What the request put aside, carried through for the work that follows: redeeming a code needs the
/// verifier and the exact redirect address, and returning the user needs the address they were heading to.
/// </param>
public sealed record AuthorizationResult(AuthorizationContext Context)
{
    /// <summary>
    /// The authorization code, when the flow returns one. It still has to be redeemed at the token
    /// endpoint, with the verifier the context holds.
    /// </summary>
    public string? Code { get; init; }

    /// <summary>
    /// The ID Token returned from the authorization endpoint, already validated, when the flow returns one.
    /// </summary>
    /// <remarks>
    /// Validated here rather than left to the caller, because the checks that bind it to this response -
    /// its nonce, and the <c>c_hash</c> and <c>at_hash</c> that tie it to the code and access token beside
    /// it - can only be made while those neighbours are in hand. A caller handed the raw token afterwards
    /// would have nothing left to check them against.
    /// </remarks>
    public JsonWebToken? IdToken { get; init; }

    /// <summary>
    /// The same ID Token as it arrived, before it was parsed.
    /// </summary>
    /// <remarks>
    /// Kept because logging out needs the token verbatim: RP-Initiated Logout 1.0 section 2 sends it as
    /// <c>id_token_hint</c>, and a token re-serialized from its parsed parts is a different string with a
    /// signature that no longer verifies.
    /// </remarks>
    public string? EncodedIdToken { get; init; }

    /// <summary>
    /// The access token returned from the authorization endpoint, when the flow returns one.
    /// </summary>
    /// <remarks>
    /// Bound to the ID Token beside it by <c>at_hash</c> where one was returned. In a flow that returns an
    /// access token with no ID Token there is nothing to bind it, which is part of why such flows are the
    /// ones a host has to ask for deliberately.
    /// </remarks>
    public string? AccessToken { get; init; }

    /// <summary>
    /// The type of <see cref="AccessToken"/>, as the provider stated it.
    /// </summary>
    public string? TokenType { get; init; }

    /// <summary>
    /// The lifetime of <see cref="AccessToken"/>, when the provider stated one that reads as a number of
    /// seconds.
    /// </summary>
    public TimeSpan? ExpiresIn { get; init; }

    /// <summary>
    /// The scope the provider granted, when it said so and it differs from what was asked.
    /// </summary>
    public string? Scope { get; init; }

    /// <summary>
    /// Where to send the user now that the login is finished, relative to this application.
    /// </summary>
    /// <remarks>
    /// Surfaced directly because it is the one member of the context a caller reaches for on every login,
    /// and it is safe to redirect to only because it was refused unless relative when the request was
    /// built.
    /// </remarks>
    public string ReturnUri => Context.ReturnUri;

    /// <summary>
    /// Renders the result without its context, so a log line cannot carry the code verifier.
    /// </summary>
    /// <remarks>
    /// The generated record ToString prints every member, and one of the context's is a secret. Naming the
    /// members here keeps an ordinary log statement from becoming a disclosure.
    /// </remarks>
    public override string ToString()
        => $"{nameof(AuthorizationResult)} {{ "
           + $"{nameof(Code)} = {(Code is null ? "none" : "present")}, "
           + $"{nameof(IdToken)} = {(IdToken is null ? "none" : "present")}, "
           + $"{nameof(AccessToken)} = {(AccessToken is null ? "none" : "present")}, "
           + $"{nameof(TokenType)} = {TokenType}, "
           + $"{nameof(ExpiresIn)} = {ExpiresIn}, "
           + $"{nameof(Scope)} = {Scope} }}";
}
