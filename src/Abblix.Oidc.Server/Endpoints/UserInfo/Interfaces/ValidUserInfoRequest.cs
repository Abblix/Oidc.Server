// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
	ClientInfo ClientInfo);
