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
/// Refuses, while the host is still starting, token lifetimes and a refresh token reuse policy for new clients that no
/// token could be issued or redeemed under.
/// </summary>
/// <remarks>
/// Every client registering after startup, and every client resolved from its metadata document, takes these values:
/// a lifetime of zero or less issues tokens that have expired when they are issued, and a reuse policy the enumeration
/// does not define fails each refresh of those clients with an error that names neither the setting nor the value.
/// </remarks>
public sealed class NewClientTokenLifetimesValidator : IValidateOptions<OidcOptions>
{
    private const string Section = nameof(OidcOptions.NewClientOptions);
    private const string RefreshToken = $"{Section}.{nameof(NewClientOptions.RefreshToken)}";

    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, OidcOptions options)
    {
        var settings = options.NewClientOptions;
        var refreshToken = settings.RefreshToken;

        if (settings.AccessTokenExpiresIn <= TimeSpan.Zero)
            return NotPositive($"{Section}.{nameof(NewClientOptions.AccessTokenExpiresIn)}", settings.AccessTokenExpiresIn);

        if (refreshToken.AbsoluteExpiresIn <= TimeSpan.Zero)
            return NotPositive($"{RefreshToken}.{nameof(RefreshTokenOptions.AbsoluteExpiresIn)}", refreshToken.AbsoluteExpiresIn);

        if (refreshToken.SlidingExpiresIn is { } sliding && sliding <= TimeSpan.Zero)
            return NotPositive($"{RefreshToken}.{nameof(RefreshTokenOptions.SlidingExpiresIn)}", sliding);

        if (!Enum.IsDefined(refreshToken.ReusePolicy))
        {
            return ValidateOptionsResult.Fail(
                $"{RefreshToken}.{nameof(RefreshTokenOptions.ReusePolicy)} is '{refreshToken.ReusePolicy}', which is " +
                $"none of {string.Join(", ", Enum.GetNames<RefreshTokenReusePolicy>())}.");
        }

        return ValidateOptionsResult.Success;
    }

    private static ValidateOptionsResult NotPositive(string setting, TimeSpan value)
        => ValidateOptionsResult.Fail(
            $"{setting} is {value}, so every token it governs would expire as it is issued. Set a positive lifetime.");
}
