// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

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
