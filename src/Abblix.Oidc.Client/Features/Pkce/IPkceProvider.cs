// Abblix OIDC Client Library
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

namespace Abblix.Oidc.Client.Features.Pkce;

/// <summary>
/// Creates the PKCE values that bind an authorization request to the client that made it.
/// </summary>
public interface IPkceProvider
{
    /// <summary>
    /// Creates fresh PKCE values for one authorization request.
    /// </summary>
    /// <param name="cancellationToken">Cancels the call.</param>
    /// <exception cref="PkceException">
    /// The provider cannot honour a transformation this client is willing to use.
    /// </exception>
    Task<PkceParameters> CreateAsync(CancellationToken cancellationToken = default);
}
