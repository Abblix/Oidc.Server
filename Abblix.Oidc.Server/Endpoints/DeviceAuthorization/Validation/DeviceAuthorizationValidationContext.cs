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

using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.DeviceAuthorization.Validation;

/// <summary>
/// Represents the context for validating a device authorization request.
/// </summary>
/// <param name="Request">The device authorization request being validated.</param>
/// <param name="ClientRequest">The client request with authentication information.</param>
public record DeviceAuthorizationValidationContext(
    DeviceAuthorizationRequest Request,
    ClientRequest ClientRequest)
{
    private ClientInfo? _clientInfo;

    /// <summary>
    /// The authenticated client information.
    /// </summary>
    public ClientInfo ClientInfo { get => _clientInfo.NotNull(nameof(ClientInfo)); set => _clientInfo = value; }

    /// <summary>
    /// The validated scope definitions for the request.
    /// </summary>
    public ScopeDefinition[] Scope { get; set; } = [];

    /// <summary>
    /// The validated resource definitions for the request.
    /// </summary>
    public ResourceDefinition[] Resources { get; set; } = [];
}
