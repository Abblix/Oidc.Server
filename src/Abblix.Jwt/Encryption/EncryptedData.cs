// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Jwt.Encryption;

/// <summary>
/// Represents the result of JWE content encryption operation.
/// Contains the components required for JWE Compact Serialization per RFC 7516.
/// </summary>
/// <param name="InitializationVector">The random initialization vector (IV) used for content encryption.</param>
/// <param name="Ciphertext">The encrypted content (plaintext encrypted with CEK).</param>
/// <param name="AuthenticationTag">The authentication tag for verifying ciphertext integrity.</param>
public record EncryptedData(
	byte[] InitializationVector,
	byte[] Ciphertext,
	byte[] AuthenticationTag);
