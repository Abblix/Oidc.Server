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
/// The names of the authorization request parameters, as they appear on the wire.
/// </summary>
/// <remarks>
/// Named constants rather than literals for the same reason claim names are: a typo in a literal produces a
/// request the provider rejects for a reason that reads like anything but a typo.
/// </remarks>
public static class Parameters
{
    /// <summary>
    /// Whether the provider may interact with the end-user while answering.
    /// </summary>
    public const string Prompt = "prompt";

    /// <summary>What kind of response the client is asking for.</summary>
    public const string ResponseType = "response_type";

    /// <summary>
    /// How the client is asking the provider to return the response (query, fragment, or form_post).
    /// Omitted for the code flow, where the provider's default of query is already correct.
    /// </summary>
    public const string ResponseMode = "response_mode";

    /// <summary>Identifies the client to the provider.</summary>
    public const string ClientId = "client_id";

    /// <summary>Where the provider returns the user.</summary>
    public const string RedirectUri = "redirect_uri";

    /// <summary>What the client is asking to be allowed to do.</summary>
    public const string Scope = "scope";

    /// <summary>Ties the response back to the request that caused it.</summary>
    public const string State = "state";

    /// <summary>Ties the issued token back to the request that caused it.</summary>
    public const string Nonce = "nonce";

    /// <summary>The public half of the PKCE pair.</summary>
    public const string CodeChallenge = "code_challenge";

    /// <summary>How the challenge was derived from the verifier.</summary>
    public const string CodeChallengeMethod = "code_challenge_method";

    /// <summary>Which resource the issued access token is meant for (RFC 8707). May repeat.</summary>
    public const string Resource = "resource";

    /// <summary>
    /// How old the end-user's authentication may be, in seconds. Sending it obliges the provider to state
    /// <c>auth_time</c> in the ID Token, which is what makes the answer checkable.
    /// </summary>
    public const string MaxAge = "max_age";

    /// <summary>Which authentication context classes the client will accept, space-separated.</summary>
    public const string AcrValues = "acr_values";

    /// <summary>Which login identifier the end-user is expected to use, if the provider needs to ask.</summary>
    public const string LoginHint = "login_hint";

    /// <summary>How the provider should present its pages.</summary>
    public const string Display = "display";

    /// <summary>Which claims this login requests, as the JSON object of OIDC Core 1.0 section 5.5.</summary>
    public const string Claims = "claims";
}
