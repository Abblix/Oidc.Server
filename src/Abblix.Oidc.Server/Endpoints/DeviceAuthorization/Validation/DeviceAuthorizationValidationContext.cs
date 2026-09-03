// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Nodes;
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

    /// <summary>
    /// RFC 9396 section 3 Rich Authorization Requests array, populated after per-client allowlist
    /// and per-type validator dispatch by <see cref="DeviceAuthorizationDetailsValidator"/>.
    /// <c>null</c> when the request did not include <c>authorization_details</c>.
    /// </summary>
    public JsonArray? AuthorizationDetails { get; set; }
}
