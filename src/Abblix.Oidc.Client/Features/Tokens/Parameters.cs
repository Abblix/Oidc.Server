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
/// The names of the token request parameters, as they appear on the wire.
/// </summary>
/// <remarks>
/// Named constants rather than literals for the same reason claim names are: a typo in a literal produces a
/// request the provider rejects for a reason that reads like anything but a typo. Grouping them here also
/// makes the set visible, so the next grant added can be checked against what is already sent rather than
/// spelled out again from the specification.
/// </remarks>
public static class Parameters
{
    /// <summary>Which grant is being presented.</summary>
    public const string GrantType = "grant_type";

    /// <summary>The authorization code being redeemed.</summary>
    public const string Code = "code";

    /// <summary>The secret half of the PKCE pair, proving this client made the request.</summary>
    public const string CodeVerifier = "code_verifier";

    /// <summary>The redirect address of the original request, which the provider compares against its record.</summary>
    public const string RedirectUri = "redirect_uri";

    /// <summary>The refresh token being traded in.</summary>
    public const string RefreshToken = "refresh_token";

    /// <summary>What the issued token is to be good for.</summary>
    public const string Scope = "scope";

    /// <summary>The token being presented for exchange (RFC 8693 section 2.1).</summary>
    public const string SubjectToken = "subject_token";

    /// <summary>What kind of token <see cref="SubjectToken"/> is.</summary>
    public const string SubjectTokenType = "subject_token_type";

    /// <summary>The token of the party doing the acting, in a delegation.</summary>
    public const string ActorToken = "actor_token";

    /// <summary>What kind of token <see cref="ActorToken"/> is.</summary>
    public const string ActorTokenType = "actor_token_type";

    /// <summary>What kind of token the exchange asks to be given.</summary>
    public const string RequestedTokenType = "requested_token_type";

    /// <summary>A service the issued token is to be used at, by address. May repeat.</summary>
    public const string Resource = "resource";

    /// <summary>A service the issued token is to be used at, by logical name. May repeat.</summary>
    public const string Audience = "audience";

    /// <summary>The code a device keeps while its user authorizes it elsewhere (RFC 8628 section 3.4).</summary>
    public const string DeviceCode = "device_code";

    /// <summary>What identifies a backchannel authentication request (CIBA section 10.1).</summary>
    public const string AuthenticationRequestId = "auth_req_id";
}
