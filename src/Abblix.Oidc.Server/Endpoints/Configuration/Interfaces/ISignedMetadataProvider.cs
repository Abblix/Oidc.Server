// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Endpoints.Configuration.Interfaces;

/// <summary>
/// Produces the RFC 8414 §2.1 <c>signed_metadata</c> value for a discovery document.
/// </summary>
/// <remarks>
/// Lives in the core rather than in an adapter because the value is a property of the metadata, not of the
/// framework that serves it: both the MVC and the Minimal API adapters assemble the same
/// <see cref="Model.ConfigurationResponse"/> and owe their clients the same signature over it.
/// </remarks>
public interface ISignedMetadataProvider
{
    /// <summary>
    /// Signs <paramref name="metadata"/> and returns the compact JWS.
    /// </summary>
    /// <param name="metadata">
    /// The fully assembled metadata, including resolved endpoint URLs and any mTLS aliases, and without
    /// <c>signed_metadata</c> itself: RFC 8414 §2.1 has the bundle assert the metadata, not restate its own
    /// signature.
    /// </param>
    /// <returns>The compact-serialized JWS.</returns>
    Task<string> SignAsync(Model.ConfigurationResponse metadata);
}
