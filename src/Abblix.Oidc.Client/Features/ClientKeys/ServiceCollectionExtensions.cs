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


using Abblix.Jwt;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Abblix.Oidc.Client.Features.ClientKeys;

/// <summary>
/// Registers this client's own keys.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Gives this client the private halves of the encryption keys it published to its provider, so it can
    /// read a token the provider encrypted for it.
    /// </summary>
    /// <param name="services">The service collection to add to.</param>
    /// <param name="decryptionKeys">The keys.</param>
    /// <returns>The same collection, so calls chain.</returns>
    /// <remarks>
    /// Needed only by a client registered with <c>id_token_encrypted_response_alg</c>. Without this call the
    /// client holds no keys and refuses an encrypted token, which is the correct answer for a client that
    /// asked for none.
    /// </remarks>
    public static IServiceCollection AddClientDecryptionKeys(
        this IServiceCollection services, IReadOnlyCollection<JsonWebKey> decryptionKeys)
    {
        // Replaces the empty default: this call IS the host saying it holds keys. Replace rather than
        // TryAdd so the answer does not depend on whether this ran before or after the default was added.
        services.Replace(ServiceDescriptor.Singleton<IClientKeysProvider>(
            _ => new ConfiguredClientKeysProvider(decryptionKeys)));

        return services;
    }

    /// <summary>
    /// Registers the empty default, so the verifier always has a source to ask.
    /// </summary>
    internal static IServiceCollection AddClientKeysPlaceholder(this IServiceCollection services)
    {
        services.TryAddSingleton<IClientKeysProvider, NoClientKeysProvider>();

        return services;
    }
}
