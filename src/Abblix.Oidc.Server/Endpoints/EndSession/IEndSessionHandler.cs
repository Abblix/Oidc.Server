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
using Abblix.Utils;
using Abblix.Oidc.Server.Endpoints.EndSession.Interfaces;

namespace Abblix.Oidc.Server.Endpoints.EndSession;

/// <summary>
/// Top-level entry point for the OpenID Connect RP-Initiated Logout endpoint.
/// Validates the incoming request and, on success, performs sign-out and produces
/// the post-logout redirect target plus any front-channel logout URIs to be invoked
/// by the relying party.
/// </summary>
public interface IEndSessionHandler
{
    /// <summary>
    /// Handles a single RP-initiated logout request end to end.
    /// </summary>
    /// <param name="endSessionRequest">The parsed wire-level end-session request.</param>
    /// <returns>
    /// An <see cref="EndSessionSuccess"/> on success, or an <see cref="OidcError"/>
    /// describing why the request was rejected.
    /// </returns>
    Task<Result<EndSessionSuccess, OidcError>> HandleAsync(Model.EndSessionRequest endSessionRequest);
}
