// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Jwt.Encryption;

/// <summary>
/// What the Concat KDF derives from an ECDH-ES shared secret, settled from the token before the agreement is run.
/// </summary>
/// <param name="AlgorithmId">The KDF's AlgorithmID: 'alg' in the key-wrapping variants, 'enc' in Direct Key
/// Agreement (RFC 7518 section 4.6.2).</param>
/// <param name="KeySizeInBytes">The size of the derived key.</param>
/// <param name="Unwraps">Whether the derived key unwraps the Encrypted Key, rather than being the Content Encryption
/// Key itself.</param>
internal readonly record struct EcdhEsDerivation(string AlgorithmId, int KeySizeInBytes, bool Unwraps);
