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

namespace Abblix.Oidc.Client.Features.Authorization.Requests;

/// <summary>
/// The OpenID Connect flow a client runs, named by the <c>response_type</c> it sends.
/// </summary>
/// <remarks>
/// A closed set rather than a free <c>response_type</c> string, so every per-flow difference is decided by
/// an exhaustive switch the compiler checks, and a host cannot ask for a combination that is not one of
/// the seven the specifications define. The members are ordered by what they return, code-first, and the
/// on-the-wire value spells the atoms in the canonical order OAuth 2.0 Multiple Response Type Encoding
/// Practices registers - <c>code id_token token</c>.
/// Only <see cref="Code"/> returns nothing usable through the browser; the rest put a token in the front
/// channel and are enabled only when the host opts in.
/// </remarks>
public enum AuthorizationFlow
{
    /// <summary>
    /// <c>code</c>. The authorization code flow, and the safe default: the code comes back through the
    /// browser but is redeemed over a back channel with PKCE.
    /// </summary>
    Code,

    /// <summary>
    /// <c>id_token</c>. An ID Token from the authorization endpoint and nothing else - the implicit flow
    /// used for authentication only, with no access token.
    /// </summary>
    IdToken,

    /// <summary>
    /// <c>id_token token</c>. The implicit flow returning both an ID Token and an access token in the
    /// front channel.
    /// </summary>
    IdTokenToken,

    /// <summary>
    /// <c>code id_token</c>. The hybrid flow OAuth 2.0 Security BCP (RFC 9700 section 2.1.2) names as the
    /// one to recommend when a front-channel ID Token is wanted: the ID Token authenticates the response
    /// and its <c>c_hash</c> binds the code, while the code is still redeemed over the back channel.
    /// </summary>
    CodeIdToken,

    /// <summary>
    /// <c>code token</c>. A hybrid flow returning a code and a front-channel access token, with no ID
    /// Token to bind the access token by <c>at_hash</c>.
    /// </summary>
    CodeToken,

    /// <summary>
    /// <c>code id_token token</c>. The hybrid flow returning a code, an ID Token and an access token.
    /// </summary>
    CodeIdTokenToken,
}

/// <summary>
/// The per-flow facts the request builder decides from, each an exhaustive switch over
/// <see cref="AuthorizationFlow"/>.
/// </summary>
public static class AuthorizationFlows
{
    /// <summary>
    /// The <c>response_type</c> wire value for the flow, atoms in the canonical order <c>code id_token
    /// token</c> (OAuth 2.0 Multiple Response Type Encoding Practices).
    /// </summary>
    public static string ToResponseType(this AuthorizationFlow flow) => flow switch
    {
        AuthorizationFlow.Code => ResponseTypes.Code,
        AuthorizationFlow.IdToken => ResponseTypes.IdToken,
        AuthorizationFlow.IdTokenToken => $"{ResponseTypes.IdToken} {ResponseTypes.Token}",
        AuthorizationFlow.CodeIdToken => $"{ResponseTypes.Code} {ResponseTypes.IdToken}",
        AuthorizationFlow.CodeToken => $"{ResponseTypes.Code} {ResponseTypes.Token}",
        AuthorizationFlow.CodeIdTokenToken => $"{ResponseTypes.Code} {ResponseTypes.IdToken} {ResponseTypes.Token}",
        _ => throw new ArgumentOutOfRangeException(nameof(flow), flow, "Unknown authorization flow."),
    };

    /// <summary>
    /// Whether the flow returns a token (an ID Token or an access token) from the authorization endpoint,
    /// in the front channel. True for every flow but <see cref="AuthorizationFlow.Code"/>.
    /// </summary>
    /// <remarks>
    /// This is the discriminator behind both the opt-in gate and the response-mode requirement: a
    /// front-channel token is the risk a host must accept, and it is what a server-side callback cannot
    /// receive by the default fragment mode.
    /// </remarks>
    public static bool ReturnsFrontChannelTokens(this AuthorizationFlow flow) => flow switch
    {
        AuthorizationFlow.Code => false,
        AuthorizationFlow.IdToken => true,
        AuthorizationFlow.IdTokenToken => true,
        AuthorizationFlow.CodeIdToken => true,
        AuthorizationFlow.CodeToken => true,
        AuthorizationFlow.CodeIdTokenToken => true,
        _ => throw new ArgumentOutOfRangeException(nameof(flow), flow, "Unknown authorization flow."),
    };

    /// <summary>
    /// Whether the flow returns an authorization code, and so needs PKCE. False only for the pure implicit
    /// flows, which have no code to protect.
    /// </summary>
    public static bool IncludesAuthorizationCode(this AuthorizationFlow flow) => flow switch
    {
        AuthorizationFlow.Code => true,
        AuthorizationFlow.CodeIdToken => true,
        AuthorizationFlow.CodeToken => true,
        AuthorizationFlow.CodeIdTokenToken => true,
        AuthorizationFlow.IdToken => false,
        AuthorizationFlow.IdTokenToken => false,
        _ => throw new ArgumentOutOfRangeException(nameof(flow), flow, "Unknown authorization flow."),
    };
}
