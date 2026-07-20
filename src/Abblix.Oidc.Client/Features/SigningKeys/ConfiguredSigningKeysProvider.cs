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

using Abblix.Jwt;

namespace Abblix.Oidc.Client.Features.SigningKeys;

/// <summary>
/// Serves a fixed set of the provider's verification keys, held by the host rather than read from the
/// provider.
/// </summary>
/// <remarks>
/// Three situations call for this. A provider may publish no key set at all, the way many OAuth 2.0 providers
/// publish no discovery document. A deployment may be unable to reach the provider's key endpoint at all,
/// which is normal in segmented networks. And an operator may want the keys pinned deliberately, so that a
/// key the provider starts serving is not automatically trusted.
///
/// The trade is rotation: a provider that rotates its keys makes this client reject its tokens until the host
/// is reconfigured. That is the price of pinning, and it is the reason this is not the default.
/// </remarks>
public sealed class ConfiguredSigningKeysProvider : IIssuerSigningKeysProvider
{
    private readonly IReadOnlyCollection<JsonWebKey> _keys;

    /// <summary>
    /// Creates the provider over the keys the host registered.
    /// </summary>
    public ConfiguredSigningKeysProvider(IReadOnlyCollection<JsonWebKey> keys)
    {
        if (keys.Count == 0)
            throw new SigningKeysException(
                "No verification keys were configured, so no signature made by the provider could be checked.");

        _keys = keys;
    }

    /// <inheritdoc />
    /// <remarks>
    /// A key named by the token but absent from the configured set does not narrow the result to nothing:
    /// every held key is returned and signature verification makes the final call, exactly as when the key
    /// set is read from the provider.
    /// </remarks>
    public Task<IReadOnlyCollection<JsonWebKey>> GetSigningKeysAsync(
        string? keyId, CancellationToken cancellationToken = default)
    {
        if (keyId is null)
            return Task.FromResult(_keys);

        var named = _keys.Where(key => key.KeyId == keyId).ToArray();
        return Task.FromResult<IReadOnlyCollection<JsonWebKey>>(named.Length > 0 ? named : _keys);
    }
}
