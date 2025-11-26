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
/// Represents a state where the user is authenticated but requires consent for further authorization.
/// This record is used to encapsulate the details needed to prompt the user for consent.
/// </summary>
/// <param name="Model">The model of the authorization request prompting the need for user consent.</param>
/// <param name="AuthSession">The authentication session associated with the user, detailing their authenticated state.
/// </param>
/// <param name="RequiredUserConsents">
/// Defines the consents that are pending and require user approval.
/// This includes the specific scopes and resources that need user consent before proceeding with the authorization
/// process. </param>
public record ConsentRequired(AuthorizationRequest Model, AuthSession AuthSession, ConsentDefinition RequiredUserConsents)
    : AuthorizationResponse(Model);
