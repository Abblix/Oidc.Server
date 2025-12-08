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
