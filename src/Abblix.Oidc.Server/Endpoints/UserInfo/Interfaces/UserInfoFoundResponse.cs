// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Features.ClientInformation;


namespace Abblix.Oidc.Server.Endpoints.UserInfo.Interfaces;

/// <summary>
/// Represents a successful response containing the found user information.
/// </summary>
/// <param name="User">The collection of JWT claims associated with the user.</param>
/// <param name="ClientInfo">Information about the client making the request.</param>
/// <param name="Issuer">The issuer identifier.</param>
public record UserInfoFoundResponse(JsonObject User, ClientInfo ClientInfo, string Issuer);
