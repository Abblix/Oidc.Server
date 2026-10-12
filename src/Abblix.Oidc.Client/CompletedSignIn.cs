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

using System.Security.Claims;
using Abblix.Jwt;

namespace Abblix.Oidc.Client;

/// <summary>
/// What a finished login leaves the host holding.
/// </summary>
/// <remarks>
/// Named for a fact rather than an outcome: this type exists only where the login succeeded. A login that
/// failed does not arrive as a value with a flag on it - the client throws, so a host cannot carry on with a
/// principal it never checked.
/// </remarks>
/// <param name="Principal">The signed-in user, built from the validated ID Token.</param>
/// <param name="IdentityToken">The validated ID Token, for a host that needs its claims or wants to keep it.</param>
/// <param name="EncodedIdentityToken">
/// The ID Token as it arrived. Kept because logging out needs it: RP-Initiated Logout 1.0 section 2 sends it
/// as <c>id_token_hint</c>, and a token re-serialized from its parts is not the one the provider signed.
/// </param>
/// <param name="AccessToken">The access token, for calling the provider's UserInfo endpoint and APIs.</param>
/// <param name="TokenType">
/// How the access token is presented, from the token response (RFC 6749 section 5.1 makes it REQUIRED).
/// Carried rather than assumed, because it says whether a bearer header is enough or a proof is needed.
/// </param>
/// <param name="RefreshToken">
/// The refresh token, when the provider issued one. Present only if the login asked for <c>offline_access</c>
/// and the provider allowed it.
/// </param>
/// <param name="ExpiresIn">How long the access token is good for, when the provider said.</param>
/// <param name="ReturnUri">
/// Where the user was heading when the login started, relative to this application.
/// </param>
/// <param name="SessionState">
/// The end-user's login state at the provider, when it sent one. Opaque, and what a page watching for the
/// session ending elsewhere polls with.
/// </param>
public sealed record CompletedSignIn(
    ClaimsPrincipal Principal,
    JsonWebToken IdentityToken,
    string EncodedIdentityToken,
    string? AccessToken,
    string? TokenType,
    string? RefreshToken,
    TimeSpan? ExpiresIn,
    string ReturnUri,
    string? SessionState = null);
