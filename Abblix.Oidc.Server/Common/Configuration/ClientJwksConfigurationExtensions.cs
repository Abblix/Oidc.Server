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
using Abblix.Oidc.Server.Features.ClientInformation;
using Microsoft.Extensions.Configuration;

namespace Abblix.Oidc.Server.Common.Configuration;

/// <summary>
/// Configuration-time extensions that populate <see cref="ClientInfo.Jwks"/> from raw
/// configuration sections by binding into <see cref="JsonWebKeySetSettings"/> (a flat
/// DTO that <see cref="Microsoft.Extensions.Configuration"/> can handle natively) and
/// mapping to the polymorphic <see cref="JsonWebKey"/> hierarchy.
/// </summary>
/// <remarks>
/// The same primitive is exposed at two layers so the host can apply the fix as close
/// to the source binding as practical:
/// <list type="bullet">
/// <item><description>
/// <c>settings.Clients.WithJwksFromConfiguration(section)</c> — eager, runs right after
/// <c>configuration.Get&lt;Settings&gt;()</c>, so every later consumer of
/// <c>settings.Clients</c> sees populated <c>Jwks</c>.
/// </description></item>
/// <item><description>
/// <c>options.AddClientJwksFromConfiguration(section)</c> — convenience inside the
/// <c>AddOidcServices</c> options lambda, equivalent to mutating
/// <c>options.Clients</c> through <c>WithJwksFromConfiguration</c>.
/// </description></item>
/// </list>
/// </remarks>
public static class ClientJwksConfigurationExtensions
{
    /// <summary>
    /// Returns the same client collection with <see cref="ClientInfo.Jwks"/> populated for
    /// each entry whose configuration counterpart includes an inline <c>Jwks</c> sub-section.
    /// Mutates in place when the input is already a <typeparamref name="T"/> array; otherwise
    /// materialises a fresh array.
    /// </summary>
    /// <typeparam name="T">A concrete client type — either <see cref="ClientInfo"/> directly
    /// or a host-supplied derived type (e.g. carrying app-specific metadata). The return type
    /// preserves <typeparamref name="T"/> so the host can assign the result back to its own
    /// strongly-typed <c>Clients</c> array without casting.</typeparam>
    /// <param name="clients">The clients whose <c>Jwks</c> should be populated.</param>
    /// <param name="clientsSection">The configuration section that holds the Clients tree —
    /// typically <c>configuration.GetSection("Clients")</c>.</param>
    /// <returns>The same clients (as an array) with any newly populated <c>Jwks</c>.</returns>
    /// <remarks>
    /// <para>
    /// Per-client self-correcting: an entry whose <see cref="ClientInfo.Jwks"/> is already
    /// non-null (because the host populated it programmatically or a future TFM's binder
    /// gained native polymorphic support) is skipped.
    /// </para>
    /// <para>
    /// Configuration entries without a matching <c>ClientId</c> in <paramref name="clients"/>
    /// are silently skipped, so the same <c>appsettings.json</c> can declare clients that only
    /// some deployments load.
    /// </para>
    /// </remarks>
    /// <exception cref="InvalidOperationException">A <c>Jwks</c> sub-section contains a key
    /// with a missing or unsupported <c>kty</c> discriminator.</exception>
    /// <exception cref="FormatException">A byte-array member of a JWK is not valid
    /// base64url.</exception>
    public static T[] WithJwksFromConfiguration<T>(
        this IEnumerable<T> clients,
        IConfigurationSection clientsSection)
        where T : ClientInfo
    {
        var array = clients as T[] ?? clients.ToArray();
        if (!clientsSection.Exists() || array.Length == 0)
            return array;

        foreach (var entry in clientsSection.GetChildren())
        {
            var clientId = entry[nameof(ClientInfo.ClientId)];
            if (string.IsNullOrEmpty(clientId))
                continue;

            var jwksSection = entry.GetSection(nameof(ClientInfo.Jwks));
            if (!jwksSection.Exists())
                continue;

            var client = Array.Find(array, c => c.ClientId == clientId);
            if (client is null)
                continue;

            // Treat "Jwks set but Keys empty" as "needs binding" too. On .NET 10
            // the standard configuration binder pre-creates a JsonWebKeySet with an
            // empty Keys array (it constructs the wrapper but cannot construct the
            // polymorphic JsonWebKey entries), so a plain "Jwks is not null" guard
            // skips clients whose JWKs the host actually does want bound from config,
            // leaving signature verification at runtime with zero keys for the issuer.
            if (client.Jwks is { Keys.Length: > 0 })
                continue;

            if (jwksSection.Get<JsonWebKeySetSettings>() is {} jwks)
                client.Jwks = jwks;
        }

        return array;
    }

    /// <summary>
    /// Convenience wrapper for use inside the <c>AddOidcServices</c> options lambda:
    /// equivalent to <c>options.Clients = options.Clients.WithJwksFromConfiguration(section)</c>.
    /// </summary>
    public static void AddClientJwksFromConfiguration(
        this OidcOptions options,
        IConfigurationSection clientsSection)
    {
        options.Clients = options.Clients.WithJwksFromConfiguration(clientsSection);
    }
}
