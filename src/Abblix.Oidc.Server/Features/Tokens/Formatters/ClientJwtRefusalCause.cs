// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.Tokens.Formatters;

/// <summary>
/// Why a JWT cannot be issued to a client.
/// </summary>
public enum ClientJwtRefusalCause
{
    /// <summary>
    /// The client is registered for a signature algorithm its security profile does not admit: the client's
    /// registration is what is wrong.
    /// </summary>
    AlgorithmOutsideProfile,

    /// <summary>
    /// No signing key of the tenant performs the algorithm the client is registered for: the tenant's keys are what is
    /// wrong, a key rotated out or never configured.
    /// </summary>
    NoTenantSigningKey,

    /// <summary>
    /// The client registered an encryption algorithm for the JWT and publishes no key it can encrypt to under its
    /// security profile, or none could be read: the client's keys are what is wrong.
    /// </summary>
    NoClientEncryptionKey,
}
