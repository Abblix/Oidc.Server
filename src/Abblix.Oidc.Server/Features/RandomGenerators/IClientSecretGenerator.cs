// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.RandomGenerators;

/// <summary>
/// Defines an interface responsible for generating secure client secrets for OpenID Connect (OIDC) clients.
/// Client secrets are used as credentials for client authentication to the OIDC provider or authorization server.
/// </summary>
public interface IClientSecretGenerator
{
    /// <summary>
    /// Generates a new, secure client secret string of the specified length. The generated secret is intended
    /// for use by confidential clients in OAuth 2.0 and OpenID Connect authentication flows. It is crucial
    /// that the generated secret is of sufficient length and randomness to ensure the security of client
    /// authentication processes.
    /// </summary>
    /// <param name="length">The desired length of the client secret. It is recommended that secrets be of
    /// sufficient length (e.g., at least 32 characters) to ensure adequate security against brute-force
    /// or guessing attacks.</param>
    /// <returns>A securely generated client secret string of the specified length. The secret should consist
    /// of a cryptographically strong, random sequence of characters that can include a mix of letters,
    /// digits, and special characters.</returns>
    string GenerateClientSecret(int length);
}
