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

namespace Abblix.Oidc.Client.Features.Tokens;

/// <summary>
/// What one RFC 8693 token exchange asks for.
/// </summary>
/// <remarks>
/// A per-call object rather than configuration, because every member of it belongs to the exchange being
/// made: the token being presented, who is acting, and what the result is to be good for. Two exchanges in
/// the same application routinely differ in all of them.
///
/// Only the two the specification marks REQUIRED are <c>required</c> here. The rest are OPTIONAL in section
/// 2.1, and leaving one unset means the provider decides, which is not the same as asking for nothing.
/// </remarks>
public sealed record TokenExchangeParameters
{
    /// <summary>
    /// The token being presented: whoever it represents is the party the exchange is made on behalf of.
    /// </summary>
    public required string SubjectToken { get; init; }

    /// <summary>
    /// What kind of token <see cref="SubjectToken"/> is, named by one of the identifiers in
    /// <see cref="TokenExchangeTokenTypes"/> or by one the provider defines.
    /// </summary>
    /// <remarks>
    /// REQUIRED alongside the token, and not derivable from it: the same string can be a valid access token
    /// and a valid JWT of another profile, and it is the presenter who knows which one is being offered.
    /// </remarks>
    public required string SubjectTokenType { get; init; }

    /// <summary>
    /// The token of the party doing the acting, when the exchange is a delegation rather than an
    /// impersonation. Leave unset to ask the provider to act as the subject.
    /// </summary>
    public string? ActorToken { get; init; }

    /// <summary>
    /// What kind of token <see cref="ActorToken"/> is. Required by RFC 8693 section 2.1 when an actor token
    /// is present, and forbidden when it is not.
    /// </summary>
    public string? ActorTokenType { get; init; }

    /// <summary>
    /// The kind of token being asked for. Unset leaves the choice to the provider, which section 2.1 allows.
    /// </summary>
    public string? RequestedTokenType { get; init; }

    /// <summary>
    /// The scope being asked of the issued token. The provider may issue less, and says so in the response.
    /// </summary>
    public IReadOnlyCollection<string> Scopes { get; init; } = [];

    /// <summary>
    /// The services the issued token is to be used at, by address (RFC 8693 section 2.1, RFC 8707).
    /// </summary>
    /// <remarks>
    /// Absolute URIs, and the specification says a fragment must not be present. More than one may be
    /// named, and each is sent as its own <c>resource</c> parameter rather than joined.
    /// </remarks>
    public IReadOnlyCollection<Uri> Resources { get; init; } = [];

    /// <summary>
    /// The services the issued token is to be used at, by logical name rather than by address.
    /// </summary>
    public IReadOnlyCollection<string> Audiences { get; init; } = [];
}
