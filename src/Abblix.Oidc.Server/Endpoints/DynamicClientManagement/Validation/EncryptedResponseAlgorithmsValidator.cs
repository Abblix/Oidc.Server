// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.Tokens.Formatters;
using Microsoft.Extensions.Options;
using static Abblix.Oidc.Server.Model.ClientRegistrationRequest;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// Validates the JWE algorithms a client requests for the JWTs this server encrypts or decrypts:
/// <c>id_token_encrypted_response_alg</c>/<c>enc</c> and <c>userinfo_encrypted_response_alg</c>/<c>enc</c>
/// (OIDC Core), <c>introspection_encrypted_response_alg</c>/<c>enc</c> (RFC 9701),
/// <c>request_object_encryption_alg</c>/<c>enc</c> (RFC 9101) and
/// <c>authorization_encrypted_response_alg</c>/<c>enc</c> (JARM section 3). Each key-management (<c>alg</c>) value
/// must appear in the server's supported key-management algorithms and each content-encryption (<c>enc</c>)
/// value in its supported content-encryption algorithms; and each algorithm a JWT this server sends is encrypted under
/// must have a key the client will hold, so a registration that could never be sent the JWT it asked to have encrypted
/// is answered with <c>invalid_client_metadata</c> instead of every such JWT being refused afterwards.
/// </summary>
/// <remarks>
/// OpenID Connect Core 1.0 section 10.2 names the key by the algorithm's family. An asymmetric algorithm needs "a public
/// key used for encryption published by the recipient in its JWK Set document", so a registration naming neither
/// <c>jwks</c> nor <c>jwks_uri</c> has none. A symmetric one needs the key "derived from the client_secret value"
/// (<see cref="ClientSecretEncryptionKey"/>), so the server must hold the secret itself rather than its hash, and the
/// client must be confidential ("Symmetric encryption MUST NOT be used by public (non-confidential) Clients"); section
/// 10.2 derives a key only for AES key wrapping and direct encryption, so a password-based algorithm has none.
/// A key set passed by value is judged here, as it changes only by a registration; whether a key published at the
/// <c>jwks_uri</c> carries the algorithm is not, since the client can change that document after registration, so it is
/// decided where the JWT is encrypted.
/// </remarks>
/// <param name="jwtValidator">Source of the JWE algorithms the server supports (the registered encryptors).</param>
/// <param name="options">Supplies the content encryption algorithm a client that registered none is sent, which fixes
/// the length of a key used directly as the content encryption key.</param>
/// <param name="clientInfoProvider">Supplies the stored client an update keeps the secrets of.</param>
/// <param name="timeProvider">Supplies the time a stored secret's expiry is judged against.</param>
public class EncryptedResponseAlgorithmsValidator(
    IJsonWebTokenValidator jwtValidator,
    IOptions<OidcOptions> options,
    IClientInfoProvider clientInfoProvider,
    TimeProvider timeProvider) : IClientRegistrationContextValidator
{
    /// <inheritdoc />
    public async Task<OidcError?> ValidateAsync(TenantDefinition tenant, ClientRegistrationValidationContext context)
        => ValidateSupported(context.Request) ?? await ValidateKeySourcesAsync(tenant, context);

    private OidcError? ValidateSupported(Model.ClientRegistrationRequest request)
        => ValidateAlg(request.IdTokenEncryptedResponseAlg, Parameters.IdTokenEncryptedResponseAlg)
            ?? ValidateEnc(request.IdTokenEncryptedResponseEnc, Parameters.IdTokenEncryptedResponseEnc)
            ?? ValidateAlg(request.UserInfoEncryptedResponseAlg, Parameters.UserInfoEncryptedResponseAlg)
            ?? ValidateEnc(request.UserInfoEncryptedResponseEnc, Parameters.UserInfoEncryptedResponseEnc)
            ?? ValidateAlg(request.IntrospectionEncryptedResponseAlg, Parameters.IntrospectionEncryptedResponseAlg)
            ?? ValidateEnc(request.IntrospectionEncryptedResponseEnc, Parameters.IntrospectionEncryptedResponseEnc)
            ?? ValidateAlg(request.RequestObjectEncryptionAlg, Parameters.RequestObjectEncryptionAlg)
            ?? ValidateEnc(request.RequestObjectEncryptionEnc, Parameters.RequestObjectEncryptionEnc)
            ?? ValidateAlg(request.AuthorizationEncryptedResponseAlg, Parameters.AuthorizationEncryptedResponseAlg)
            ?? ValidateEnc(request.AuthorizationEncryptedResponseEnc, Parameters.AuthorizationEncryptedResponseEnc);

    /// <summary>
    /// Refuses the first algorithm a JWT this server sends is encrypted under that the client will have no key for. The
    /// request object is left out: the client encrypts it, to a key of this server.
    /// </summary>
    private async Task<OidcError?> ValidateKeySourcesAsync(
        TenantDefinition tenant,
        ClientRegistrationValidationContext context)
    {
        var request = context.Request;
        var defaultEncryption = options.Value.DefaultContentEncryptionAlgorithm;
        (string Name, string? Algorithm, string ContentEncryption)[] encrypted =
        [
            (Parameters.IdTokenEncryptedResponseAlg, request.IdTokenEncryptedResponseAlg,
                request.IdTokenEncryptedResponseEnc ?? defaultEncryption),
            (Parameters.UserInfoEncryptedResponseAlg, request.UserInfoEncryptedResponseAlg,
                request.UserInfoEncryptedResponseEnc ?? defaultEncryption),
            (Parameters.IntrospectionEncryptedResponseAlg, request.IntrospectionEncryptedResponseAlg,
                request.IntrospectionEncryptedResponseEnc ?? defaultEncryption),

            // JARM section 3 names its own default, as ClientJwtEncryption.ForJarm does
            (Parameters.AuthorizationEncryptedResponseAlg, request.AuthorizationEncryptedResponseAlg,
                request.AuthorizationEncryptedResponseEnc ?? options.Value.DefaultAuthorizationResponseEncryptionAlgorithm),
        ];

        foreach (var (name, algorithm, contentEncryption) in encrypted)
        {
            if (algorithm is not null &&
                await ValidateKeySourceAsync(tenant, context, name, algorithm, contentEncryption) is { } error)
            {
                return error;
            }
        }

        return null;
    }

    private async Task<OidcError?> ValidateKeySourceAsync(
        TenantDefinition tenant,
        ClientRegistrationValidationContext context,
        string name,
        string algorithm,
        string contentEncryption)
    {
        if (!ClientSecretEncryptionKey.IsSymmetric(algorithm))
        {
            if (context.Request.JwksUri is not null || Array.Exists(
                    context.Request.Jwks?.Keys ?? [],
                    key => key.Usage is (null or PublicKeyUsages.Encryption) &&
                           ClientEncryptionKeyResolver.Carries(key, algorithm)))
            {
                return null;
            }

            return ErrorFactory.InvalidClientMetadata(
                $"The {name} {algorithm} encrypts to a key the client publishes, but it registers neither " +
                $"{Parameters.JwksUri} nor {Parameters.Jwks} holding an encryption key for it");
        }

        if (ClientSecretEncryptionKey.SizeInBytes(algorithm, contentEncryption) is null)
        {
            return ErrorFactory.InvalidClientMetadata(
                $"The {name} {algorithm} is an algorithm no key is derived from the client secret for");
        }

        if (!await HoldsSecretAsync(tenant, context))
        {
            return ErrorFactory.InvalidClientMetadata(
                $"The {name} {algorithm} encrypts with a key derived from the client secret, which this client " +
                "does not hold in a form the server can read");
        }

        return null;
    }
    /// <summary>
    /// Validates a JWE key-management (<c>alg</c>) value against the server's supported key-management algorithms.
    /// </summary>
    private OidcError? ValidateAlg(string? alg, string description)
    {
        if (alg is not null && !jwtValidator.EncryptionAlgorithmsSupported.Contains(alg, StringComparer.Ordinal))
        {
            return new OidcError(
                ErrorCodes.InvalidRequest,
                $"The encryption key-management algorithm for {description} is not supported");
        }

        return null;
    }

    /// <summary>
    /// Validates a JWE content-encryption (<c>enc</c>) value against the server's supported content-encryption
    /// algorithms.
    /// </summary>
    private OidcError? ValidateEnc(string? enc, string description)
    {
        if (enc is not null && !jwtValidator.EncryptionMethodsSupported.Contains(enc, StringComparer.Ordinal))
        {
            return new OidcError(
                ErrorCodes.InvalidRequest,
                $"The encryption method for {description} is not supported");
        }

        return null;
    }

    /// <summary>
    /// Whether the server will hold the client's secret itself: a new registration keeps it for the authentication
    /// methods <see cref="RegisterClientRequestProcessor.KeepsSecretValue"/> names, and an update keeps the secrets the
    /// stored client holds (RFC 7592 section 2.2).
    /// </summary>
    private async Task<bool> HoldsSecretAsync(TenantDefinition tenant, ClientRegistrationValidationContext context)
    {
        var request = context.Request;
        switch (context.Operation)
        {
            case DynamicClientOperation.Register:
                return RegisterClientRequestProcessor.KeepsSecretValue(request.TokenEndpointAuthMethod);

            case DynamicClientOperation.Update:
                if (request.ClientId is null ||
                    await clientInfoProvider.TryFindClientAsync(tenant, request.ClientId) is not { } stored)
                {
                    return false;
                }

                // Judged as the client will be after the update: its secrets, under the method it now registers
                var updated = new ClientInfo(stored.ClientId)
                {
                    ClientSecrets = stored.ClientSecrets,
                    TokenEndpointAuthMethod = request.TokenEndpointAuthMethod,
                };
                return ClientSecretEncryptionKey.SecretOf(updated, timeProvider.GetUtcNow()) is not null;

            default:
                throw new InvalidOperationException($"Unsupported dynamic client operation: {context.Operation}");
        }
    }
}
