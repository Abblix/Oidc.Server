// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.ClientInformation;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Common.Configuration;

/// <summary>
/// Refuses, while the host is still starting, an offline access for new clients that the enumeration does not define.
/// </summary>
/// <remarks>
/// Configuration binds a number to an enumeration whatever its value, and every client registering after startup
/// takes this one, so a mistyped value would fail each registration and each authorization request of those clients
/// with an error that names neither the setting nor the value.
/// </remarks>
public sealed class NewClientOfflineAccessValidator : IValidateOptions<OidcOptions>
{
    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, OidcOptions options)
    {
        var offlineAccess = options.NewClientOptions.OfflineAccess;
        return Enum.IsDefined(offlineAccess)
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail(
                $"{nameof(OidcOptions.NewClientOptions)}.{nameof(NewClientOptions.OfflineAccess)} is " +
                $"'{offlineAccess}', which is none of {string.Join(", ", Enum.GetNames<OfflineAccess>())}.");
    }
}
