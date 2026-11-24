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
/// a lifetime of zero or less issues tokens that have expired when they are issued, one of <see cref="TimeSpan.MaxValue"/>,
/// a natural way to write "no limit", is no expiry the clock can add to the issue time, so every issuance fails, and a
/// reuse policy the enumeration does not define fails each refresh of those clients with an error that names neither
/// the setting nor the value.
/// </remarks>
public sealed class NewClientTokenLifetimesValidator : IValidateOptions<OidcOptions>
{
    private const string Section = nameof(OidcOptions.NewClientOptions);
    private const string RefreshToken = $"{Section}.{nameof(NewClientOptions.RefreshToken)}";

    /// <summary>
    /// The longest lifetime accepted. A grant held for longer is held by nobody, and at this length the expiry of a
    /// token, and of the revocation record kept for its lifetimes together, stays far inside what every clock and store
    /// holds.
    /// </summary>
    internal static readonly TimeSpan LongestLifetime = TimeSpan.FromDays(3650);

    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, OidcOptions options)
    {
        var settings = options.NewClientOptions;
        var refreshToken = settings.RefreshToken;

        if (OutOfRange(settings.AccessTokenExpiresIn))
            return Refused($"{Section}.{nameof(NewClientOptions.AccessTokenExpiresIn)}", settings.AccessTokenExpiresIn);

        if (OutOfRange(refreshToken.AbsoluteExpiresIn))
            return Refused($"{RefreshToken}.{nameof(RefreshTokenOptions.AbsoluteExpiresIn)}", refreshToken.AbsoluteExpiresIn);

        if (refreshToken.SlidingExpiresIn is { } sliding && OutOfRange(sliding))
            return Refused($"{RefreshToken}.{nameof(RefreshTokenOptions.SlidingExpiresIn)}", sliding);

        if (!Enum.IsDefined(refreshToken.ReusePolicy))
        {
            return ValidateOptionsResult.Fail(
                $"{RefreshToken}.{nameof(RefreshTokenOptions.ReusePolicy)} is '{refreshToken.ReusePolicy}', which is " +
                $"none of {string.Join(", ", Enum.GetNames<RefreshTokenReusePolicy>())}.");
        }

        return ValidateOptionsResult.Success;
    }

    private static bool OutOfRange(TimeSpan lifetime) => lifetime <= TimeSpan.Zero || LongestLifetime < lifetime;

    private static ValidateOptionsResult Refused(string setting, TimeSpan value)
        => ValidateOptionsResult.Fail(
            $"{setting} is {value}, which no token can be issued under. Set a positive lifetime no longer than " +
            $"{LongestLifetime}.");
}
