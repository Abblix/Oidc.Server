// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;

namespace Abblix.Oidc.Server.Features.Tokens;

/// <summary>
/// Represents an encoded JSON Web Token (JWT) along with its decoded model representation.
/// </summary>
/// <param name="Token">The decoded model representation of the JWT.</param>
/// <param name="EncodedJwt">The encoded string form of the JWT.</param>
public record EncodedJsonWebToken(JsonWebToken Token, string EncodedJwt);
