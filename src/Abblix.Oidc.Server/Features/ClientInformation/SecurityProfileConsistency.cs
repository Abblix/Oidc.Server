// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;

namespace Abblix.Oidc.Server.Features.ClientInformation;

/// <summary>
/// Checks whether a client's configuration can actually satisfy the profile it selects, so a
/// contradiction surfaces loudly at registration or startup instead of as a per-request rejection
/// the operator has to reverse-engineer. The runtime validators already tighten a request to the
/// profile; this is the fail-loud companion that catches static configuration that can never produce
/// a conformant flow in the first place.
/// </summary>
public static class SecurityProfileConsistency
{
    /// <summary>
    /// Returns the human-readable violations that prevent a client with the given registered response
    /// types from satisfying the effective profile, or an empty list when the configuration is
    /// self-consistent. The check operates on response types because that is the one part of a FAPI
    /// client the profile cannot silently fix at request time: a client that never permits the
    /// authorization-code response type, or that permits an implicit/hybrid one, is misconfigured
    /// rather than merely tightened.
    /// </summary>
    /// <param name="allowedResponseTypes">The response-type combinations the client is registered for.</param>
    /// <param name="tokenEndpointAuthMethod">How the client authenticates at the token endpoint.</param>
    /// <param name="assertionAudiences">What the client's authentication assertions may name as their audience
    /// (<see cref="ClientInfo.ClientAssertionAudiences"/>); always <see cref="ClientAssertionAudiences.Issuer"/> for a
    /// registration, which cannot ask for more.</param>
    /// <param name="requirements">The control bundle the client is held to, floor included.</param>
    /// <remarks>
    /// The BUNDLE rather than a profile name, because a client is held to the deployment's profile
    /// tightened by its own and no enum value names that combination. Taking a name here would put
    /// the resolution inside this method, where it would silently undo whichever floor its caller
    /// had just applied - and the two controls below are the ones nothing else enforces, so the
    /// gap would show up as a client authenticating with a shared secret under a profile that
    /// admits no such client.
    /// </remarks>
    public static IReadOnlyList<string> FindViolations(
        IReadOnlyList<string[]> allowedResponseTypes,
        string tokenEndpointAuthMethod,
        ClientAssertionAudiences assertionAudiences,
        SecurityProfileRequirements requirements)
    {
        var violations = new List<string>(AssertionAudienceViolations(assertionAudiences, requirements));

        // RFC 6749 draws the line at whether the client can hold a credential at all, and the
        // registered authentication method is where that shows: a client authenticating with
        // nothing IS the public client the profile excludes.
        if (requirements.RequireConfidentialClient &&
            tokenEndpointAuthMethod == ClientAuthenticationMethods.None)
        {
            violations.Add(
                "the client's security profile admits confidential clients only, " +
                "but the client authenticates with none at the token endpoint");
        }

        // Both surviving methods prove possession of a key. Every other method the server offers
        // proves possession of a shared secret, which is what the profile removes.
        if (requirements.RequireKeyBasedClientAuthentication &&
            !KeyBasedAuthenticationMethods.Contains(tokenEndpointAuthMethod))
        {
            violations.Add(
                "the client's security profile requires client authentication by mutual TLS or a " +
                $"private key JWT, but the client uses {tokenEndpointAuthMethod}");
        }

        if (!requirements.RequireCodeResponseTypeOnly)
            return violations;

        // A single-element "code" entry, matched case-insensitively to stay consistent with the
        // token-bearing check below (both ultimately use HasFlag's OrdinalIgnoreCase comparison).
        var allowsCode = allowedResponseTypes.Any(
            responseType => responseType is { Length: 1 } && responseType.HasFlag(ResponseTypes.Code));
        if (!allowsCode)
        {
            violations.Add(
                "the client's security profile requires the authorization-code response type, " +
                "but the client does not allow it");
        }

        if (allowedResponseTypes.Any(responseType => responseType.ReturnsTokenFromAuthorization()))
        {
            violations.Add(
                "the client's security profile forbids implicit and hybrid response types, " +
                "but the client allows a response type that returns a token from the authorization endpoint");
        }

        return violations;
    }

    /// <summary>
    /// The service tokens issued to a client: the access and refresh tokens, which this server signs and encrypts with
    /// what the deployment configures for each rather than with what the client registers.
    /// </summary>
    /// <param name="serviceTokens">The deployment's service token settings.</param>
    public static (string Name, ServiceTokenOptions Token)[] IssuedToAClient(ServiceTokensOptions serviceTokens)
        =>
        [
            (nameof(serviceTokens.AccessToken), serviceTokens.AccessToken),
            (nameof(serviceTokens.RefreshToken), serviceTokens.RefreshToken),
        ];

    /// <summary>
    /// Names each of <paramref name="tokens"/> this server would sign with an algorithm, or encrypt with one, the
    /// profile does not admit, or an empty list: FAPI 1.0 Part 2 sections 8.6 and 8.6.1, FAPI 2.0 section 5.4.1 "when
    /// creating or processing JWTs".
    /// </summary>
    /// <param name="tokens">The service token settings, each with the name it is configured under.</param>
    /// <param name="requirements">The control bundle in force.</param>
    public static IReadOnlyList<string> FindServiceTokenViolations(
        IEnumerable<(string Name, ServiceTokenOptions Token)> tokens,
        SecurityProfileRequirements requirements)
    {
        var violations = new List<string>();
        foreach (var (name, token) in tokens)
        {
            var signing = token.Signing.Algorithm;
            if (!requirements.PermitsSigningAlgorithm(signing))
            {
                violations.Add(
                    $"ServiceTokens.{name}.Signing.Algorithm is {signing}, which a security profile in force here does " +
                    $"not admit; set it to {string.Join(" or ", SecurityProfileRequirements.FapiSigningAlgorithms)}.");
            }

            // Encrypted unless turned off. Only an algorithm the setting names is judged here: a key declaring a
            // forbidden one is passed over where the token is formatted, which is the one answer to that question
            if (token.Encrypt != false && token.Encryption.Algorithm is { } encryption &&
                !requirements.PermitsKeyManagementAlgorithm(encryption))
            {
                violations.Add(
                    $"ServiceTokens.{name} is encrypted with {encryption}, which a security profile in force here " +
                    "forbids.");
            }
        }

        return violations;
    }

    /// <summary>
    /// Names a client key set the profile leaves nothing to encrypt to, or an empty list: FAPI 1.0 Part 2 section
    /// 8.6.1, "For JWE, both clients and authorization servers shall not use the RSA1_5 algorithm". A client that
    /// publishes encryption keys has what is issued to it encrypted, and is not sent it in the clear because every key
    /// declares an algorithm its profile forbids.
    /// </summary>
    /// <param name="clientKeysProvider">Supplies the encryption keys the client publishes.</param>
    /// <param name="client">The client.</param>
    /// <param name="requirements">The control bundle the client is held to.</param>
    public static async Task<IReadOnlyList<string>> FindEncryptionKeyViolationsAsync(
        IClientKeysProvider clientKeysProvider,
        ClientInfo client,
        SecurityProfileRequirements requirements)
    {
        // Fetched only where the profile forbids an algorithm a key may declare
        if (!requirements.ForbidRsa1_5KeyManagement)
            return [];

        var keys = await clientKeysProvider.GetEncryptionKeys(client).ToArrayAsync();

        // A key declaring no algorithm can be used with any the profile admits
        if (keys.Length == 0 || keys.Any(key => key.Algorithm is not { } declared ||
                                               requirements.PermitsKeyManagementAlgorithm(declared)))
        {
            return [];
        }

        return
        [
            "the client's key set publishes only encryption keys declaring an algorithm its security profile " +
            $"forbids ({string.Join(", ", keys.Select(key => key.Algorithm).Distinct())})",
        ];
    }

    /// <summary>
    /// Names what keeps a client from being issued the certificate-bound access tokens its profile issues alone, or an
    /// empty list: FAPI 1.0 Part 2 section 8.2, "shall only support sender-constrained access tokens via MTLS".
    /// </summary>
    /// <param name="tokenEndpointAuthMethod">How the client authenticates at the token endpoint.</param>
    /// <param name="tlsClientCertificateBoundAccessTokens">Whether the client registers certificate-bound access
    /// tokens (RFC 8705 section 3.4).</param>
    /// <param name="requireDPoP">Whether the client registers DPoP-bound access tokens (RFC 9449 section 5.2).</param>
    /// <param name="requirements">The control bundle the client is held to, floor included.</param>
    public static IReadOnlyList<string> FindTokenBindingViolations(
        string tokenEndpointAuthMethod,
        bool tlsClientCertificateBoundAccessTokens,
        bool requireDPoP,
        SecurityProfileRequirements requirements)
    {
        if (!requirements.RequireCertificateBoundTokens)
            return [];

        var violations = new List<string>();

        // RFC 9449 section 5.2 has a client registered with dpop_bound_access_tokens always use DPoP at the token
        // endpoint, which a profile issuing certificate-bound tokens only refuses on every request
        if (requireDPoP)
        {
            violations.Add(
                "the client's security profile issues certificate-bound access tokens only, " +
                "but the client requires DPoP-bound access tokens");
        }

        // RFC 8705 section 3: a token is bound to the certificate of a client that authenticates with mutual TLS or
        // registers tls_client_certificate_bound_access_tokens; any other client is refused every token
        if (!tlsClientCertificateBoundAccessTokens && tokenEndpointAuthMethod
                is not (ClientAuthenticationMethods.TlsClientAuth or ClientAuthenticationMethods.SelfSignedTlsClientAuth))
        {
            violations.Add(
                "the client's security profile issues certificate-bound access tokens only, but the client " +
                "neither authenticates with mutual TLS nor registers tls_client_certificate_bound_access_tokens");
        }

        return violations;
    }

    /// <summary>
    /// FAPI 2.0 section 5.3.2.1: the server "shall only accept its issuer identifier value ... as a string in the aud
    /// claim received in client authentication assertions", which leaves no room for an endpoint URL or an
    /// array.
    /// </summary>
    private static IEnumerable<string> AssertionAudienceViolations(
        ClientAssertionAudiences assertionAudiences,
        SecurityProfileRequirements requirements)
    {
        if (requirements.RequireStringAudienceInClientAssertion &&
            assertionAudiences != ClientAssertionAudiences.Issuer)
        {
            yield return "the client's security profile accepts only the issuer identifier, as a string, as the " +
                         $"audience of a client assertion, but the client is allowed {assertionAudiences}";
        }
    }

    /// <summary>
    /// Names each algorithm this server would sign with for the client, or the client is pinned to sign with, that its
    /// profile does not admit, or an empty list when every one is admitted: FAPI 1.0 Part 2 section 8.6 has "both
    /// clients and authorization servers" use "PS256 or ES256 algorithms". A client pinned to another algorithm
    /// for its request objects, assertions or CIBA requests could sign nothing the server accepts.
    /// </summary>
    /// <remarks>
    /// The client's configuration is what the server signs with, so it is judged here rather than when a token is
    /// issued, where the only answers left would be a token signed against the profile or a failure the client could
    /// do nothing about. A userinfo or introspection response configured <c>none</c> is plain JSON and carries no
    /// JWS, and a logout token without an algorithm of its own takes the ID token's, so neither is named; an ID token
    /// or authorization response configured <c>none</c> is an unsigned JWS, and is.
    /// </remarks>
    /// <param name="client">The client whose configuration is checked.</param>
    /// <param name="requirements">The control bundle the client is held to, floor included.</param>
    public static IReadOnlyList<string> FindSigningAlgorithmViolations(
        ClientInfo client,
        SecurityProfileRequirements requirements)
        => FindSigningAlgorithmViolations(
            [
                (nameof(ClientInfo.IdentityTokenSignedResponseAlgorithm), client.IdentityTokenSignedResponseAlgorithm),
                (nameof(ClientInfo.AuthorizationSignedResponseAlgorithm), client.AuthorizationSignedResponseAlgorithm),
                (nameof(ClientInfo.LogoutTokenSignedResponseAlgorithm), client.LogoutTokenSignedResponseAlgorithm),
                (nameof(ClientInfo.UserInfoSignedResponseAlgorithm), SignedOrNull(client.UserInfoSignedResponseAlgorithm)),
                (nameof(ClientInfo.IntrospectionSignedResponseAlgorithm),
                    SignedOrNull(client.IntrospectionSignedResponseAlgorithm)),
                (nameof(ClientInfo.RequestObjectSigningAlgorithm), client.RequestObjectSigningAlgorithm),
                (nameof(ClientInfo.TokenEndpointAuthSigningAlgorithm), client.TokenEndpointAuthSigningAlgorithm),
                (nameof(ClientInfo.BackChannelAuthenticationRequestSigningAlg),
                    client.BackChannelAuthenticationRequestSigningAlg),
            ],
            requirements);

    /// <summary>
    /// The same over named algorithms the caller lists, which a registration has as metadata rather than as a
    /// client.
    /// </summary>
    /// <param name="algorithms">Each setting's name and the algorithm it names, null where it signs nothing of its
    /// own.</param>
    /// <param name="requirements">The control bundle the client is held to, floor included.</param>
    public static IReadOnlyList<string> FindSigningAlgorithmViolations(
        IEnumerable<(string Name, string? Algorithm)> algorithms,
        SecurityProfileRequirements requirements)
        =>
        [
            ..
            from setting in algorithms
            where setting.Algorithm is { } algorithm && !requirements.PermitsSigningAlgorithm(algorithm)
            select $"the client's security profile admits only {string.Join(" and ", SecurityProfileRequirements.FapiSigningAlgorithms)} " +
                   $"signatures, but {setting.Name} is {setting.Algorithm}",
        ];

    /// <summary>
    /// Names each algorithm the client's configuration names that its profile does not admit, for signatures and for
    /// encryption alike.
    /// </summary>
    /// <param name="client">The client whose configuration is checked.</param>
    /// <param name="requirements">The control bundle the client is held to, floor included.</param>
    public static IReadOnlyList<string> FindAlgorithmViolations(
        ClientInfo client,
        SecurityProfileRequirements requirements)
        =>
        [
            ..FindSigningAlgorithmViolations(client, requirements),
            ..FindEncryptionAlgorithmViolations(
                [
                    (nameof(ClientInfo.IdentityTokenEncryptedResponseAlgorithm),
                        client.IdentityTokenEncryptedResponseAlgorithm),
                    (nameof(ClientInfo.UserInfoEncryptedResponseAlgorithm), client.UserInfoEncryptedResponseAlgorithm),
                    (nameof(ClientInfo.IntrospectionEncryptedResponseAlgorithm),
                        client.IntrospectionEncryptedResponseAlgorithm),
                    (nameof(ClientInfo.AuthorizationEncryptedResponseAlgorithm),
                        client.AuthorizationEncryptedResponseAlgorithm),
                    (nameof(ClientInfo.RequestObjectEncryptionAlgorithm), client.RequestObjectEncryptionAlgorithm),
                ],
                requirements),
        ];

    /// <summary>
    /// Names each key management algorithm the profile does not admit: FAPI 1.0 Part 2 section 8.6.1, "For JWE, both
    /// clients and authorization servers shall not use the RSA1_5 algorithm".
    /// </summary>
    /// <param name="algorithms">Each setting's name and the key management algorithm it names, null where it names
    /// none.</param>
    /// <param name="requirements">The control bundle the client is held to, floor included.</param>
    public static IReadOnlyList<string> FindEncryptionAlgorithmViolations(
        IEnumerable<(string Name, string? Algorithm)> algorithms,
        SecurityProfileRequirements requirements)
        => requirements.ForbidRsa1_5KeyManagement
            ?
            [
                ..
                from setting in algorithms
                where setting.Algorithm == EncryptionAlgorithms.KeyManagement.Rsa1_5
                select $"the client's security profile forbids RSA1_5 encryption, but {setting.Name} is RSA1_5",
            ]
            : [];

    /// <summary>
    /// Names each redirect URI the profile does not admit, or an empty list when it admits every one: FAPI 1.0 Part 1
    /// section 5.2.2 has the server "require redirect URIs to use the https scheme".
    /// </summary>
    /// <param name="redirectUris">The redirect URIs the client registers.</param>
    /// <param name="requirements">The control bundle the client is held to, floor included.</param>
    public static IReadOnlyList<string> FindRedirectUriViolations(
        IEnumerable<Uri> redirectUris,
        SecurityProfileRequirements requirements)
        => requirements.RequireExactHttpsRedirectUris
            ?
            [
                ..
                from redirectUri in redirectUris
                where redirectUri is not { IsAbsoluteUri: true, Scheme: "https" }
                select $"the client's security profile admits only https redirect URIs, but {redirectUri} is not one",
            ]
            : [];

    /// <summary>
    /// Names a jwks_uri the profile does not admit, or nothing: FAPI 1.0 Part 2 section 8.9 "requires that jwks_uri
    /// endpoints shall be served over TLS".
    /// </summary>
    /// <param name="jwksUri">The jwks_uri the client registers, or null where it registers none.</param>
    /// <param name="requirements">The control bundle the client is held to, floor included.</param>
    public static IReadOnlyList<string> FindJwksUriViolations(Uri? jwksUri, SecurityProfileRequirements requirements)
        => requirements.RequireHttpsJwksUri && jwksUri is { } uri && uri is not { IsAbsoluteUri: true, Scheme: "https" }
            ? [$"the client's security profile requires a jwks_uri served over TLS, but {uri} is not"]
            : [];

    /// <summary>
    /// The algorithm of a response that may also go unsigned, or null where it does: for userinfo and introspection
    /// <c>none</c> is a plain JSON response rather than an unsigned JWS.
    /// </summary>
    /// <param name="algorithm">The algorithm the client is configured for.</param>
    public static string? SignedOrNull(string? algorithm)
        => algorithm == SigningAlgorithms.None ? null : algorithm;

    /// <summary>
    /// The client authentication methods that prove possession of a key rather than of a shared
    /// secret: mutual TLS in both its forms (RFC 8705 section 2) and the private key JWT assertion
    /// (OpenID Connect Core section 9).
    /// </summary>
    private static readonly string[] KeyBasedAuthenticationMethods =
    [
        ClientAuthenticationMethods.TlsClientAuth,
        ClientAuthenticationMethods.SelfSignedTlsClientAuth,
        ClientAuthenticationMethods.PrivateKeyJwt,
    ];
}
