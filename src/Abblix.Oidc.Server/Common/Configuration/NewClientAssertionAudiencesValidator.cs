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
/// Refuses, while the host is still starting, assertion audiences for new clients that lack the issuer identifier or
/// name a value the enumeration does not define.
/// </summary>
/// <remarks>
/// Every client registered after startup takes the set, so one the server cannot apply would refuse the assertions of
/// each of them, conforming ones included, and be noticed only when they fail.
/// </remarks>
public sealed class NewClientAssertionAudiencesValidator : IValidateOptions<OidcOptions>
{
    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, OidcOptions options)
    {
        var audiences = options.NewClientOptions.ClientAssertionAudiences;
        return ClientAssertionAudiencesCheck.IsAccepted(audiences)
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail(
                $"{nameof(OidcOptions.NewClientOptions)}.{nameof(NewClientOptions.ClientAssertionAudiences)} is " +
                $"'{audiences}', which is not a set this server accepts: it holds " +
                $"{nameof(ClientAssertionAudiences.Issuer)} and may add " +
                $"{nameof(ClientAssertionAudiences.TokenEndpoint)}, " +
                $"{nameof(ClientAssertionAudiences.BackChannelAuthenticationEndpoint)} and " +
                $"{nameof(ClientAssertionAudiences.AllowArray)}.");
    }
}
