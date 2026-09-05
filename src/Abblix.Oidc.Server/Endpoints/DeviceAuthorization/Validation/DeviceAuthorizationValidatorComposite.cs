// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.DeviceAuthorization.Validation;

/// <summary>
/// Composes multiple device authorization context validators into a single validator.
/// Executes validators in sequence until one returns an error or all pass.
/// </summary>
/// <param name="validators">The collection of validators to execute.</param>
public class DeviceAuthorizationValidatorComposite(
    IEnumerable<IDeviceAuthorizationContextValidator> validators) : IDeviceAuthorizationContextValidator
{
    /// <inheritdoc />
    public Task<OidcError?> ValidateAsync(DeviceAuthorizationValidationContext context)
        => validators.FirstOrDefaultAsync(v => v.ValidateAsync(context));
}
