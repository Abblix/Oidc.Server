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
/// Represents a validated request to update a client's configuration per RFC 7592.
/// Contains the original request, validated client info, and registration request.
/// </summary>
/// <param name="Model">The original update request.</param>
/// <param name="ClientInfo">The validated client information from the data store.</param>
/// <param name="RegistrationRequest">The validated registration request with updated metadata.</param>
public record ValidUpdateClientRequest(
    UpdateClientRequest Model,
    ClientInfo ClientInfo,
    ClientRegistrationRequest RegistrationRequest);
