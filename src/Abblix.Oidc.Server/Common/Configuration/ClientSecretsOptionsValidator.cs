// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Common.Configuration;

/// <summary>
/// Fails loudly at startup when a configured client cannot authenticate with the secret it appears
/// to carry, instead of answering <c>invalid_client</c> to every request it ever makes.
/// </summary>
/// <remarks>
/// A registry kept in configuration makes a mistyped hash easy and its consequences invisible. The
/// .NET configuration binder discards an element whose binding threw, so a hash the file spells
/// wrongly leaves the client with no secret at all rather than with a bad one, and nothing downstream
/// distinguishes that from a client deliberately registered without secrets: the token endpoint
/// simply refuses it, logging at debug level. A hash of the wrong length is the same mistake caught
/// one step later - a digest pasted into the wrong notation decodes without error and compares
/// against nothing.
/// </remarks>
public class ClientSecretsOptionsValidator : IValidateOptions<OidcOptions>
{
    /// <summary>Length in bytes of a SHA-256 digest.</summary>
    private const int Sha256HashLength = 256 / 8;

    /// <summary>Length in bytes of a SHA-512 digest.</summary>
    private const int Sha512HashLength = 512 / 8;

    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, OidcOptions options)
    {
        if (options.Clients == null)
            return ValidateOptionsResult.Success;

        var failures = new List<string>();

        foreach (var client in options.Clients)
        {
            CheckSecretsArePresent(failures, client);

            foreach (var secret in client.ClientSecrets ?? [])
            {
                CheckHashLength(failures, client, secret.Sha256Hash, Sha256HashLength, nameof(secret.Sha256Hash));
                CheckHashLength(failures, client, secret.Sha512Hash, Sha512HashLength, nameof(secret.Sha512Hash));
            }
        }

        return failures.Count == 0
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail(failures);
    }

    /// <summary>
    /// A client authenticating by shared secret needs one in the form its method actually reads.
    /// The check exists for the client that was given a secret the binder could not read, so the
    /// no-secrets message names that cause first.
    /// </summary>
    /// <remarks>
    /// Presence alone proves nothing, because each method reads one form of the secret and silently
    /// skips the other: client_secret_basic and client_secret_post compare the presented secret
    /// against a stored hash and never read <see cref="ClientSecret.Value"/>, while
    /// client_secret_jwt signs with the raw value as the HMAC key and cannot use a hash, which is
    /// one-way. A secret in the wrong form passes a presence check and is then skipped on every
    /// request, with nothing said above debug level - the same quiet refusal this validator exists
    /// to catch.
    /// </remarks>
    private static void CheckSecretsArePresent(List<string> failures, ClientInfo client)
    {
        var authenticatesBySecret = client.TokenEndpointAuthMethod is
            ClientAuthenticationMethods.ClientSecretBasic or
            ClientAuthenticationMethods.ClientSecretPost or
            ClientAuthenticationMethods.ClientSecretJwt;

        if (!authenticatesBySecret)
            return;

        if (client.ClientSecrets is not { Length: > 0 })
        {
            failures.Add(
                $"Client '{client.ClientId}' authenticates with '{client.TokenEndpointAuthMethod}' and has no " +
                $"usable secret. When the registry comes from configuration, this is what a hash the binder could " +
                $"not read looks like: check that every hash is a valid Base64 or hexadecimal string.");
            return;
        }

        if (client.TokenEndpointAuthMethod is ClientAuthenticationMethods.ClientSecretJwt)
        {
            if (!Array.Exists(client.ClientSecrets, secret => !string.IsNullOrEmpty(secret.Value)))
            {
                failures.Add(
                    $"Client '{client.ClientId}' authenticates with '{client.TokenEndpointAuthMethod}', which uses " +
                    $"the raw secret value as the HMAC key, and no secret carries " +
                    $"{nameof(ClientSecret.Value)}. A hash cannot serve this method: it is one-way, and the key " +
                    $"the client signs with cannot be recovered from it.");
            }
        }
        else if (!Array.Exists(client.ClientSecrets, secret => secret.Sha256Hash != null || secret.Sha512Hash != null))
        {
            failures.Add(
                $"Client '{client.ClientId}' authenticates with '{client.TokenEndpointAuthMethod}', which compares " +
                $"the presented secret against a stored hash, and no secret carries one. A secret holding only the " +
                $"raw value never matches: store the hash, for example via {nameof(ClientSecret.Sha256HashBase64)} " +
                $"or {nameof(ClientSecret.Sha256HashHex)}.");
        }
    }

    private static void CheckHashLength(
        List<string> failures,
        ClientInfo client,
        byte[]? hash,
        int expectedLength,
        string propertyName)
    {
        if (hash is null || hash.Length == expectedLength)
            return;

        failures.Add(
            $"Client '{client.ClientId}' has a {propertyName} of {hash.Length} bytes, where {expectedLength} are " +
            $"expected. A digest written in the other notation decodes to the wrong length rather than failing, " +
            $"so this usually means Base64 and hexadecimal were swapped.");
    }
}
