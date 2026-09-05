// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Endpoints.DeviceAuthorization.Validation;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Endpoints.DeviceAuthorization.Interfaces;

/// <summary>
/// A device authorization request (RFC 8628 §3.1) that has passed all validators, paired with the
/// authenticated client and the scope/resource sets resolved against the provider's catalog.
/// </summary>
public record ValidDeviceAuthorizationRequest
{
    /// <summary>
    /// Builds the validated request snapshot from a populated <see cref="DeviceAuthorizationValidationContext"/>,
    /// flattening scope and resource definitions to their wire-form identifiers.
    /// </summary>
    public ValidDeviceAuthorizationRequest(DeviceAuthorizationValidationContext context)
    {
        Model = context.Request;
        ClientInfo = context.ClientInfo;
        Scope = context.Scope.Select(s => s.Scope).ToArray();
        Resources = context.Resources.Select(r => r.Resource).ToArray();
        AuthorizationDetails = context.AuthorizationDetails;
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

    /// <summary>
    /// RFC 9396 §3 Rich Authorization Requests array (post-validation), which the downstream
    /// processor stashes on the persisted <c>DeviceAuthorizationRequest</c> so the
    /// user-verification step can carry it onto the eventual <c>AuthorizedGrant</c>.
    /// </summary>
    public JsonArray? AuthorizationDetails { get; }
}
