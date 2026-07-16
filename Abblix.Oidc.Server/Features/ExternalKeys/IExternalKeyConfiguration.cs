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

namespace Abblix.Oidc.Server.Features.ExternalKeys;

/// <summary>
/// Selects which key an <see cref="Abblix.Jwt.IKeyCustodian"/> signs with and which it unwraps, and under which
/// algorithm each operates. The algorithm is advertised on the published key and forwarded to the custodian on
/// every operation, so it must be one the custodian provisions (for example <c>RS256</c>, <c>PS384</c> or
/// <c>ES256</c> for signing; <c>RSA-OAEP-256</c> for unwrapping). A backend's options implement this directly, so
/// the wiring passes the options straight through with no separate mapping.
/// </summary>
public interface IExternalKeyConfiguration
{
    /// <summary>The custodian's name for the signing key; also its published <c>kid</c>.</summary>
    string SigningKeyName { get; }

    /// <summary>The JWS algorithm the signing key uses.</summary>
    string SigningAlgorithm { get; }

    /// <summary>The custodian's name for the encryption key; also its published <c>kid</c>.</summary>
    string EncryptionKeyName { get; }

    /// <summary>The JWE key-management algorithm the encryption key uses.</summary>
    string EncryptionAlgorithm { get; }
}
