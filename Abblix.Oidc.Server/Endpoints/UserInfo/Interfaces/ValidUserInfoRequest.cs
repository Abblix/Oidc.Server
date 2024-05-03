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
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Model;


namespace Abblix.Oidc.Server.Endpoints.UserInfo.Interfaces;

/// <summary>
/// Represents a valid user info request with associated authentication and authorization details.
/// </summary>
/// <param name="Model">The user info request model.</param>
/// <param name="AuthSession">The authentication session associated with the request.</param>
/// <param name="AuthContext">The authorization context of the request.</param>
/// <param name="ClientInfo">The client information for the request.</param>
public record ValidUserInfoRequest(
	UserInfoRequest Model,
	AuthSession AuthSession,
	AuthorizationContext AuthContext,
	ClientInfo ClientInfo) : UserInfoRequestValidationResult;
