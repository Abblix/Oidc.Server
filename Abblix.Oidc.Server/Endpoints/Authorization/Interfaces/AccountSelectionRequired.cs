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

using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Model;


namespace Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;

/// <summary>
/// Outcome signalling that more than one active end-user session matches the request and the
/// host UI must let the user pick one before authorization can continue. Maps to OpenID Connect
/// Core 1.0 §3.1.2.6 <c>account_selection_required</c> when <c>prompt=none</c>; otherwise the
/// host renders an account picker over the supplied <see cref="Users"/> set.
/// </summary>
/// <param name="Model">The authorization request that triggered the multi-account branch.</param>
/// <param name="Users">All authenticated sessions that satisfy the request's filters
/// (e.g. <c>max_age</c>, <c>acr_values</c>) and are eligible for selection.</param>
public record AccountSelectionRequired(AuthorizationRequest Model, AuthSession[] Users)
    : AuthorizationResponse(Model);
