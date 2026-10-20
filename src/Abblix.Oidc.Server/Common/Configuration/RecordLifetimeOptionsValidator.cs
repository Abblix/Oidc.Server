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
/// Fails at startup on a duration that would keep nothing: a record gone before anything could read it, or a write
/// the storage refuses outright. That includes a time to keep the record of a session's clients too short for the
/// record to be renewed.
/// </summary>
/// <remarks>
/// At zero or below a record would be gone before anything could read it. For the session's clients that means a
/// logout notifying nobody; for a logout confirmation it means the storage refusing the write outright, so every
/// logout question would fault. A retention merely shorter than the host's sessions cannot be detected here,
/// because the session lifetime is the host's cookie setting.
/// <para>
/// The session's clients are refused anything under <see cref="MinSessionClientsRetention"/> as well. A renewal of
/// their record notes itself until a retention after the moment it started, so a retention shorter than the
/// renewal itself would hand the storage an expiry already past, which a store such as Redis refuses, and the
/// authorization making the renewal would fail.
/// </para>
/// </remarks>
public sealed class RecordLifetimeOptionsValidator : IValidateOptions<OidcOptions>
{
    /// <summary>
    /// The shortest time the record of a session's clients may be kept: far longer than renewing the longest list
    /// of clients takes, and shorter than any session worth notifying the clients of.
    /// </summary>
    internal static readonly TimeSpan MinSessionClientsRetention = TimeSpan.FromHours(1);

    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, OidcOptions options)
    {
        if (options.SessionClientsRetention < MinSessionClientsRetention)
        {
            return ValidateOptionsResult.Fail(
                $"{nameof(options.SessionClientsRetention)} is {options.SessionClientsRetention}, under the " +
                $"{MinSessionClientsRetention} the record of the clients in a session needs to be renewed reliably. " +
                "Set it to at least the longest a session can last.");
        }

        if (options.LogoutConfirmationLifetime <= TimeSpan.Zero)
        {
            return ValidateOptionsResult.Fail(
                $"{nameof(options.LogoutConfirmationLifetime)} is {options.LogoutConfirmationLifetime}, so the " +
                "value asking the end user to confirm a logout could not be stored at all and every logout " +
                "question would fail. Set it to as long as somebody may take to answer.");
        }

        return ValidateOptionsResult.Success;
    }
}
