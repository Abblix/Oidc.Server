// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;

/// <summary>
/// Encapsulates both transmission and storage formats of client credentials.
/// Maintains plain-text secret for immediate transmission in registration response,
/// while also providing SHA-512 hash for secure persistence.
/// </summary>
/// <param name="ClientId">Generated or provided identifier for the OAuth 2.0 client.</param>
/// <param name="ClientSecret">Plain-text secret sent to client in registration response; null for public clients or private_key_jwt.</param>
/// <param name="Sha512Hash">SHA-512 hash for secure storage; prevents storing plain-text secrets in database.</param>
/// <param name="ExpiresAt">Enables secret rotation by enforcing time-limited validity; null indicates no expiration.</param>
public record ClientCredentials(
    string ClientId,
    string? ClientSecret,
    byte[]? Sha512Hash,
    DateTimeOffset? ExpiresAt);
