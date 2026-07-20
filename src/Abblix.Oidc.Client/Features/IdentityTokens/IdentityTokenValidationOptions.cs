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

namespace Abblix.Oidc.Client.Features.IdentityTokens;

/// <summary>
/// Policy for accepting an ID Token, where the specification leaves a choice.
/// </summary>
public sealed class IdentityTokenValidationOptions
{
    /// <summary>
    /// The signature algorithms this client accepts, defaulting to RS256 alone.
    /// </summary>
    /// <remarks>
    /// This is the client's own registered <c>id_token_signed_response_alg</c>, which OpenID Connect
    /// Core 1.0 section 3.1.3.7 step 7 names as what the <c>alg</c> should be, defaulting to RS256.
    /// It must NOT be taken from the provider's advertised
    /// <c>id_token_signing_alg_values_supported</c>: that list says what the provider is willing to
    /// sign with, so deriving acceptance from it lets a provider pick any algorithm on it - which is
    /// the whole shape of an algorithm-substitution attack. What this client registered for is what
    /// this client accepts, and a token signed with anything else is refused however capable the
    /// provider claims to be.
    /// </remarks>
    public IReadOnlyCollection<string> AllowedSigningAlgorithms { get; set; } = [SigningAlgorithms.RS256];

    /// <summary>
    /// Tolerance applied to the time comparisons, for clocks that disagree.
    /// </summary>
    public TimeSpan ClockSkew { get; set; } = TimeSpan.FromMinutes(2);

    /// <summary>
    /// The oldest <c>iat</c> this client will accept, or <see langword="null"/> to not judge issuance age.
    /// </summary>
    /// <remarks>
    /// Null is the default because OpenID Connect Core 1.0 section 3.1.3.7 step 10 is an explicit MAY -
    /// "The iat Claim can be used to reject tokens that were issued too far away from the current time,
    /// limiting the amount of time that nonces need to be stored" - and it says the acceptable range is
    /// client-specific. Profiles tighten it (FAPI requires rejecting an ID Token issued more than 60
    /// minutes ago), so this is a knob rather than a fixed window, and turning it on is a deployment's
    /// decision rather than a default that would surprise a client talking to a slow provider.
    /// </remarks>
    public TimeSpan? MaximumIssuedAtAge { get; set; }
}
