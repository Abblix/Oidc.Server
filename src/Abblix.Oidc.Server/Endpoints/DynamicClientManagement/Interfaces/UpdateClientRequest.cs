// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;

/// <summary>
/// Represents a request to update an existing client's configuration per RFC 7592 Section 2.2.
/// Combines client authentication (ClientRequest) with updated metadata (ClientRegistrationRequest).
/// </summary>
/// <param name="ClientRequest">The client authentication information including registration_access_token.</param>
/// <param name="RegistrationRequest">The updated client metadata to apply.</param>
public record UpdateClientRequest(
    ClientRequest ClientRequest,
    ClientRegistrationRequest RegistrationRequest);
