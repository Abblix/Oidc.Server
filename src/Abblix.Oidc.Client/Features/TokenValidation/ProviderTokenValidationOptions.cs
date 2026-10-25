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

namespace Abblix.Oidc.Client.Features.TokenValidation;

/// <summary>
/// What this client will accept from any token the provider signed for it.
/// </summary>
/// <remarks>
/// One policy rather than one per kind of token. There is no reason to accept an algorithm or a clock skew
/// for an ID Token and refuse it for a Logout Token: both are signed by the same issuer with the same keys,
/// and two settings would only make it possible to tighten one and forget the other.
/// </remarks>
public sealed class ProviderTokenValidationOptions
{
    /// <summary>
    /// The signing algorithms this client accepts.
    /// </summary>
    /// <remarks>
    /// An allow-list rather than whatever the token names, because the alternative is letting the token
    /// choose how it is verified. RFC 8725 section 3.1 puts it as an attack: a recipient that trusts the
    /// <c>alg</c> header can be handed a token signed with an algorithm it never intended to accept.
    /// </remarks>
    public IReadOnlyCollection<string> AllowedSigningAlgorithms { get; set; } = [SigningAlgorithms.RS256];

    /// <summary>
    /// How far the provider's clock may differ from this one before a token is refused as expired or
    /// not-yet-valid.
    /// </summary>
    public TimeSpan ClockSkew { get; set; } = TimeSpan.FromMinutes(2);
}
