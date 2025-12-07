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
