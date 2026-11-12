// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.ClientInformation;

/// <summary>
/// Reads a set of client assertion audiences as a security profile admits it.
/// </summary>
internal static class ClientAssertionAudiencesExtensions
{
    /// <summary>
    /// The set itself, or <see cref="ClientAssertionAudiences.Issuer"/> alone where
    /// <paramref name="requirements"/> take the issuer identifier only, as a string.
    /// </summary>
    /// <remarks>
    /// FAPI 2.0 section 5.3.2.1 has the server "only accept its issuer identifier value ... as a string in the aud
    /// claim received in client authentication assertions", so neither the token endpoint URL nor an array survives
    /// it, whatever the host granted.
    /// </remarks>
    public static ClientAssertionAudiences AdmittedBy(
        this ClientAssertionAudiences audiences,
        SecurityProfileRequirements requirements)
        => requirements.RequireStringAudienceInClientAssertion ? ClientAssertionAudiences.Issuer : audiences;
}
