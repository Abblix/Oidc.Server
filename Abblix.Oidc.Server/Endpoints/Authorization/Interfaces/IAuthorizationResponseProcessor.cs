// Abblix OIDC Server Library
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

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;

/// <summary>
/// Contributes one response-type component to the authorization endpoint's success response.
/// Each implementation owns a single value of the OAuth 2.0 / OIDC <c>response_type</c> parameter
/// (for example <c>code</c>, <c>token</c>, or <c>id_token</c>) and populates the corresponding
/// field on the running <see cref="SuccessfullyAuthenticated"/> result.
/// </summary>
/// <remarks>
/// The processor (<see cref="IAuthorizationRequestProcessor"/>) is a composite over the registered
/// processors: the orchestration logic (auth-session selection, consent, scope checks) lives in the
/// processor; per-response-type generation lives here. Implicit Flow / Hybrid Flow support is
/// expressed by registering <c>token</c> and <c>id_token</c> processors. Without those registrations
/// the corresponding response types simply do not exist in the DI graph — Implicit Flow does not
/// run, matching OAuth 2.1 §1.4 default-off semantics.
/// </remarks>
public interface IAuthorizationResponseProcessor
{
    /// <summary>
    /// The single OAuth 2.0 / OIDC response-type value this processor is responsible for, matched
    /// case-sensitively against parts of the request's <c>response_type</c>.
    /// </summary>
    string ResponseType { get; }

    /// <summary>
    /// Populates the relevant field on <paramref name="result"/> for this processor's response type.
    /// Implementations mutate <paramref name="result"/> in place and may read fields populated by
    /// processors that ran earlier in the canonical iteration order
    /// (<c>code</c> before <c>token</c> before <c>id_token</c>).
    /// </summary>
    Task BuildAsync(
        ValidAuthorizationRequest request,
        AuthorizedGrant authorizedGrant,
        SuccessfullyAuthenticated result);
}
