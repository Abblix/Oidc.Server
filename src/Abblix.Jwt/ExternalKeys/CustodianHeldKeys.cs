// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Jwt.ExternalKeys;

/// <summary>
/// Selects which of the custodian's keys the host produces with, for a host that chose to keep the private halves
/// where they never leave the custodian (<c>UseKeysInCustodian</c>). The keys belong to the operator: they are
/// already provisioned in the custodian, so this only names them. Each algorithm is advertised on the published key
/// and forwarded to the custodian on every operation, so it must be one the custodian provisions for that key.
/// </summary>
/// <remarks>
/// A name here is the custodian's name for the LOGICAL key, not a published <c>kid</c>. Every version of that key
/// is published under its own version-qualified <c>kid</c> minted by the custodian (Vault Transit
/// <c>&lt;name&gt;:&lt;version&gt;</c>, Azure Key Vault <c>&lt;name&gt;/&lt;version&gt;</c>), which is what lets a
/// rotation overlap and routes each private operation back to the exact version that signed. The bare name is the
/// published <c>kid</c> only for a custodian that does not version its keys and leaves the <c>kid</c> unset.
/// </remarks>
public sealed record CustodianHeldKeys
{
    /// <summary>
    /// The custodian's name for the signing key, whose versions are published and signed with. Required: a host
    /// with no signing key cannot issue a token at all, so the compiler asks for it instead of a startup failure.
    /// </summary>
    public required string SigningKeyName { get; init; }

    /// <summary>
    /// The JWS algorithm the signing key uses, for example <c>RS256</c>, <c>PS384</c> or <c>ES256</c> (an EC one
    /// needs a custodian key on the matching curve).
    /// </summary>
    public string SigningAlgorithm { get; init; } = SigningAlgorithms.RS256;

    /// <summary>
    /// The custodian's name for the encryption key, whose versions are published and unwrapped with. Name it when
    /// anything encrypts to this provider: it both encrypts the provider's own tokens (a service token configured
    /// to be encrypted) and decrypts inbound JWE a client sent, such as an encrypted request object or client
    /// assertion, and its published half is what tells a client where to encrypt.
    /// </summary>
    /// <remarks>
    /// Optional, and unset means no encryption key is published at all, rather than a guessed name the custodian
    /// may not hold: a signing-only deployment is the common high-assurance case.
    /// </remarks>
    public string? EncryptionKeyName { get; init; }

    /// <summary>
    /// The JWE key-management algorithm the encryption key uses. Has no effect unless
    /// <see cref="EncryptionKeyName"/> names a key.
    /// </summary>
    public string EncryptionAlgorithm { get; init; } = EncryptionAlgorithms.KeyManagement.RsaOaep256;
}
