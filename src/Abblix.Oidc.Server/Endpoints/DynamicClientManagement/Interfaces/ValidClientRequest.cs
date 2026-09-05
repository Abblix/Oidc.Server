// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;

/// <summary>
/// A client configuration endpoint request (RFC 7592) that has been authenticated via the
/// registration access token, paired with the resolved <see cref="ClientInfo"/> from storage.
/// </summary>
/// <param name="Model">The original request.</param>
/// <param name="ClientInfo">The currently stored configuration of the addressed client.</param>
public record ValidClientRequest(ClientRequest Model, ClientInfo ClientInfo);
