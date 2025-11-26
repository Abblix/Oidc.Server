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

using Abblix.Oidc.Server.Endpoints.DeviceAuthorization.Validation;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Endpoints.DeviceAuthorization.Interfaces;

/// <summary>
/// Represents a validated device authorization request with resolved client information.
/// </summary>
public record ValidDeviceAuthorizationRequest
{
    public ValidDeviceAuthorizationRequest(DeviceAuthorizationValidationContext context)
    {
        Model = context.Request;
        ClientInfo = context.ClientInfo;
        Scope = context.Scope.Select(s => s.Scope).ToArray();
        Resources = context.Resources.Select(r => r.Resource).ToArray();
    }

    /// <summary>
    /// The original device authorization request model.
    /// </summary>
    public DeviceAuthorizationRequest Model { get; }

    /// <summary>
    /// The authenticated client information.
    /// </summary>
    public ClientInfo ClientInfo { get; }

    /// <summary>
    /// The validated and resolved scopes for the request.
    /// </summary>
    public string[] Scope { get; }

    /// <summary>
    /// The validated and resolved resources for the request.
    /// </summary>
    public Uri[]? Resources { get; }
}
