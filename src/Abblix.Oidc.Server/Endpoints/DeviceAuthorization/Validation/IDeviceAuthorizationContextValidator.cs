// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Features.MultiTenancy;

namespace Abblix.Oidc.Server.Endpoints.DeviceAuthorization.Validation;

/// <summary>
/// Defines the contract for validating device authorization request contexts.
/// </summary>
public interface IDeviceAuthorizationContextValidator
{
    /// <summary>
    /// Validates the device authorization request context.
    /// </summary>
    /// <param name="tenant">The tenant the request is served at.</param>
    /// <param name="context">The validation context containing the request and client information.</param>
    /// <returns>An OIDC error if validation fails, or null if validation succeeds.</returns>
    Task<OidcError?> ValidateAsync(TenantDefinition tenant, DeviceAuthorizationValidationContext context);
}
