// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Endpoints.Configuration.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.Tokens.Formatters;
using static Abblix.Oidc.Server.Model.ClientRegistrationRequest;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// Validates the JWE algorithms a client requests for the JWTs this server encrypts or decrypts:
/// <c>id_token_encrypted_response_alg</c>/<c>enc</c> and <c>userinfo_encrypted_response_alg</c>/<c>enc</c>
/// (OIDC Core), <c>introspection_encrypted_response_alg</c>/<c>enc</c> (RFC 9701),
/// <c>request_object_encryption_alg</c>/<c>enc</c> (RFC 9101) and
/// <c>authorization_encrypted_response_alg</c>/<c>enc</c> (JARM section 3). Each algorithm of a JWT this server sends
/// must be one issuance encrypts with (<see cref="IJwtAlgorithmsProvider.EncryptedResponseAlgorithmsSupported"/> and
/// <see cref="IJwtAlgorithmsProvider.EncryptedResponseMethodsSupported"/>), and the key management algorithm of a request
/// object one the tenant's own published encryption keys open, the list discovery advertises as
/// <c>request_object_encryption_alg_values_supported</c>; and each algorithm a JWT this server sends is encrypted under
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
/// A request object is decrypted with the tenant's published encryption keys alone, none of them symmetric, so a
/// symmetric <c>request_object_encryption_alg</c>, which Dynamic Client Registration 1.0 section 2 has a client include
/// "when symmetric encryption will be used", names an encryption this server does not decrypt and is refused.
/// </remarks>
/// <param name="jwtAlgorithms">The JWE algorithms the server encrypts and decrypts with, as discovery advertises
/// them.</param>
/// <param name="serviceKeys">The tenant's own keys, which a request object is encrypted to.</param>
/// <param name="clientInfoProvider">Supplies the stored client an update keeps the secrets of.</param>
/// <param name="timeProvider">Supplies the time a stored secret's expiry is judged against.</param>
/// <param name="encryptionAlgorithms">Tells which key types a key management algorithm is carried out with.</param>
public class EncryptedResponseAlgorithmsValidator(
    IJwtAlgorithmsProvider jwtAlgorithms,
    IAuthServiceKeysProvider serviceKeys,
    IClientInfoProvider clientInfoProvider,
    TimeProvider timeProvider,
    EncryptionAlgorithmsProvider encryptionAlgorithms) : IClientRegistrationContextValidator
{
    /// <inheritdoc />
    public async Task<OidcError?> ValidateAsync(TenantDefinition tenant, ClientRegistrationValidationContext context)
        => ValidatePairs(context.Request)
           ?? ValidateSupported(context.Request, await RequestObjectAlgorithmsAsync(tenant, context.Request))
           ?? await ValidateKeySourcesAsync(tenant, context);

    /// <summary>
    /// Refuses a content encryption algorithm registered without its key management algorithm. OpenID Connect Dynamic
    /// Client Registration 1.0 section 2: "When id_token_encrypted_response_enc is included,
    /// id_token_encrypted_response_alg MUST also be provided", and the same of the userinfo and request object pairs;
    /// RFC 9701 section 6: "This parameter MUST NOT be specified without setting introspection_encrypted_response_alg";
    /// JARM section 3: "When authorization_encrypted_response_enc is included, authorization_encrypted_response_alg
    /// MUST also be provided".
    /// </summary>
    private static OidcError? ValidatePairs(Model.ClientRegistrationRequest request)
    {
        (string? Method, string MethodName, string? Algorithm, string AlgorithmName)[] pairs =
        [
            (request.IdTokenEncryptedResponseEnc, Parameters.IdTokenEncryptedResponseEnc,
                request.IdTokenEncryptedResponseAlg, Parameters.IdTokenEncryptedResponseAlg),
            (request.UserInfoEncryptedResponseEnc, Parameters.UserInfoEncryptedResponseEnc,
                request.UserInfoEncryptedResponseAlg, Parameters.UserInfoEncryptedResponseAlg),
            (request.IntrospectionEncryptedResponseEnc, Parameters.IntrospectionEncryptedResponseEnc,
                request.IntrospectionEncryptedResponseAlg, Parameters.IntrospectionEncryptedResponseAlg),
            (request.RequestObjectEncryptionEnc, Parameters.RequestObjectEncryptionEnc,
                request.RequestObjectEncryptionAlg, Parameters.RequestObjectEncryptionAlg),
            (request.AuthorizationEncryptedResponseEnc, Parameters.AuthorizationEncryptedResponseEnc,
                request.AuthorizationEncryptedResponseAlg, Parameters.AuthorizationEncryptedResponseAlg),
        ];

        foreach (var (method, methodName, algorithm, algorithmName) in pairs)
        {
            if (method is not null && algorithm is null)
                return ErrorFactory.InvalidClientMetadata($"The {methodName} is registered without {algorithmName}");
        }

        return null;
    }

    /// <summary>
    /// The key management algorithms a request object to <paramref name="tenant"/> is opened under: the same answer
    /// discovery gives, so a client registers only what it was told. Not asked where the client registers none.
    /// </summary>
    private async Task<IEnumerable<string>> RequestObjectAlgorithmsAsync(
        TenantDefinition tenant,
        Model.ClientRegistrationRequest request)
    {
        if (request.RequestObjectEncryptionAlg is null)
            return [];

        return await serviceKeys.GetInboundKeyManagementAlgorithmsAsync(
            tenant,
            jwtAlgorithms.RequestObjectEncryptionAlgValuesSupported,
            encryptionAlgorithms);
    }

    private OidcError? ValidateSupported(
        Model.ClientRegistrationRequest request,
        IEnumerable<string> requestObjectAlgorithms)
    {
        var responseAlgorithms = jwtAlgorithms.EncryptedResponseAlgorithmsSupported;
        var responseMethods = jwtAlgorithms.EncryptedResponseMethodsSupported;

        return ValidateAlg(request.IdTokenEncryptedResponseAlg, Parameters.IdTokenEncryptedResponseAlg, responseAlgorithms)
            ?? ValidateEnc(request.IdTokenEncryptedResponseEnc, Parameters.IdTokenEncryptedResponseEnc, responseMethods)
            ?? ValidateAlg(request.UserInfoEncryptedResponseAlg, Parameters.UserInfoEncryptedResponseAlg, responseAlgorithms)
            ?? ValidateEnc(request.UserInfoEncryptedResponseEnc, Parameters.UserInfoEncryptedResponseEnc, responseMethods)
            ?? ValidateAlg(
                request.IntrospectionEncryptedResponseAlg, Parameters.IntrospectionEncryptedResponseAlg, responseAlgorithms)
            ?? ValidateEnc(
                request.IntrospectionEncryptedResponseEnc, Parameters.IntrospectionEncryptedResponseEnc, responseMethods)
            ?? ValidateAlg(request.RequestObjectEncryptionAlg, Parameters.RequestObjectEncryptionAlg, requestObjectAlgorithms)
            ?? ValidateEnc(
                request.RequestObjectEncryptionEnc,
                Parameters.RequestObjectEncryptionEnc,
                jwtAlgorithms.RequestObjectEncryptionEncValuesSupported)
            ?? ValidateAlg(
                request.AuthorizationEncryptedResponseAlg, Parameters.AuthorizationEncryptedResponseAlg, responseAlgorithms)
            ?? ValidateEnc(
                request.AuthorizationEncryptedResponseEnc, Parameters.AuthorizationEncryptedResponseEnc, responseMethods);
    }

    /// <summary>
    /// Refuses the first algorithm a JWT this server sends is encrypted under that the client will have no key for. The
    /// request object is left out: the client encrypts it, to a key of this server.
    /// </summary>
    private async Task<OidcError?> ValidateKeySourcesAsync(
        TenantDefinition tenant,
        ClientRegistrationValidationContext context)
    {
        var request = context.Request;
        // The fallback each of these JWTs is encrypted with where the client registers no enc
        const string defaultEncryption = ClientJwtEncryption.DefaultContentEncryptionAlgorithm;
        (string Name, string? Algorithm, string ContentEncryption)[] encrypted =
        [
            (Parameters.IdTokenEncryptedResponseAlg, request.IdTokenEncryptedResponseAlg,
                request.IdTokenEncryptedResponseEnc ?? defaultEncryption),
            (Parameters.UserInfoEncryptedResponseAlg, request.UserInfoEncryptedResponseAlg,
                request.UserInfoEncryptedResponseEnc ?? defaultEncryption),
            (Parameters.IntrospectionEncryptedResponseAlg, request.IntrospectionEncryptedResponseAlg,
                request.IntrospectionEncryptedResponseEnc ?? defaultEncryption),
            (Parameters.AuthorizationEncryptedResponseAlg, request.AuthorizationEncryptedResponseAlg,
                request.AuthorizationEncryptedResponseEnc ?? defaultEncryption),
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
        if (!ClientSecretEncryptionKey.IsSymmetric(encryptionAlgorithms, algorithm))
        {
            if (context.Request.JwksUri is not null || Array.Exists(
                    context.Request.Jwks?.Keys ?? [],
                    key => key.Usage is (null or PublicKeyUsages.Encryption) &&
                           encryptionAlgorithms.CanEncrypt(key, algorithm)))
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
    /// Validates a JWE key-management (<c>alg</c>) value against the key-management algorithms
    /// <paramref name="supported"/>.
    /// A value outside them is client metadata the server rejects, which RFC 7591 section 3.2.2 answers with
    /// <c>invalid_client_metadata</c>: "The value of one of the client metadata fields is invalid and the server has
    /// rejected this request".
    /// </summary>
    private static OidcError? ValidateAlg(string? alg, string description, IEnumerable<string> supported)
    {
        if (alg is not null && !supported.Contains(alg, StringComparer.Ordinal))
        {
            return ErrorFactory.InvalidClientMetadata(
                $"The encryption key-management algorithm for {description} is not supported");
        }

        return null;
    }

    /// <summary>
    /// Validates a JWE content-encryption (<c>enc</c>) value against the content-encryption algorithms
    /// <paramref name="supported"/>.
    /// </summary>
    private static OidcError? ValidateEnc(string? enc, string description, IEnumerable<string> supported)
    {
        if (enc is not null && !supported.Contains(enc, StringComparer.Ordinal))
        {
            return ErrorFactory.InvalidClientMetadata($"The encryption method for {description} is not supported");
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
