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

using Abblix.Oidc.Server.Features.Consents;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Model;


namespace Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;

/// <summary>
/// Outcome signalling that the user is authenticated but has not yet granted every scope or
/// resource the client is asking for, so the host must show its consent UI for the deltas in
/// <see cref="RequiredUserConsents"/>. Maps to OpenID Connect Core 1.0 §3.1.2.6
/// <c>consent_required</c> when <c>prompt=none</c>.
/// </summary>
/// <param name="Model">The authorization request that produced the pending-consent state.</param>
/// <param name="AuthSession">The user's current authenticated session.</param>
/// <param name="RequiredUserConsents">The scopes and resources that are still missing
/// approval; everything not listed here is already granted.</param>
public record ConsentRequired(AuthorizationRequest Model, AuthSession AuthSession, ConsentDefinition RequiredUserConsents)
    : AuthorizationResponse(Model);
