// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Common.Configuration;

/// <summary>
/// Refuses a configured clock skew below zero while the host is still starting; the bound a tenant's security
/// profile puts on it is judged per tenant by <see cref="ClockSkewCeilingCheck"/>.
/// </summary>
/// <remarks>
/// A negative window refuses an assertion valid at the instant its request arrives, which no profile asks for.
/// </remarks>
public sealed class ClockSkewValidator : IValidateOptions<OidcOptions>
{
    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, OidcOptions options)
        => options.JwtBearer.ClockSkew is { } skew && skew < TimeSpan.Zero
            ? ValidateOptionsResult.Fail(
                $"{nameof(OidcOptions.JwtBearer)}.{nameof(JwtBearerOptions.ClockSkew)} is {skew}, " +
                "which refuses an assertion valid at the instant its request arrives instead of " +
                "allowing for clock offset. Set a value of zero or more.")
            : ValidateOptionsResult.Success;
}
