// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;

namespace Abblix.Oidc.Server.Features.ResourceIndicators;

/// <summary>
/// The key a token's audience published and the key management algorithm a token is encrypted to it under, chosen
/// together, since whether a key can be used depends on the algorithm it would be used with.
/// </summary>
/// <param name="Key">The audience's published key.</param>
/// <param name="Algorithm">The key management algorithm to encrypt to it under.</param>
public sealed record AudienceEncryptionKey(JsonWebKey Key, string Algorithm);
