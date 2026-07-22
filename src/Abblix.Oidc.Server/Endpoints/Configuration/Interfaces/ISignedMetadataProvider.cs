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
