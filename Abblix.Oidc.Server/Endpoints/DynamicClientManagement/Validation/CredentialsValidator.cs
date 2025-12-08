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

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// Validates that client authentication methods are consistent with the credentials provided during registration.
/// Ensures public clients don't have credentials, and confidential clients have the required credentials
/// for their chosen authentication method (JWKS for JWT methods, TLS metadata for TLS methods).
/// </summary>
public class CredentialsValidator : SyncClientRegistrationContextValidator
{
    /// <summary>
    /// Validates that the client's authentication method is consistent with its ability to hold credentials.
    /// </summary>
    /// <param name="context">The validation context containing client registration data.</param>
    /// <returns>
    /// A <see cref="OidcError"/> if the client type is inconsistent with authentication method,
    /// or null if the request is valid.
    /// </returns>
    protected override OidcError? Validate(ClientRegistrationValidationContext context)
    {
        var request = context.Request;

        switch (request.TokenEndpointAuthMethod.ToLowerInvariant())
        {
            // Public clients (auth method = "none") must NOT have JWKS or client secrets
            case ClientAuthenticationMethods.None when HasJwksCredentials(request):
                return new OidcError(
                    ErrorCodes.InvalidClientMetadata,
                    "Public clients (token_endpoint_auth_method='none') cannot have 'jwks' or 'jwks_uri'. " +
                    "Remove credentials or use a confidential authentication method like 'private_key_jwt'.");

            // Private key JWT - requires JWKS or JWKS URI
            case ClientAuthenticationMethods.PrivateKeyJwt when !HasJwksCredentials(request):
                return new OidcError(
                    ErrorCodes.InvalidClientMetadata,
                    "Clients using 'private_key_jwt' authentication must provide either 'jwks' or 'jwks_uri'.");

            // Client secret JWT - requires JWKS or JWKS URI for signature verification
            case ClientAuthenticationMethods.ClientSecretJwt when !HasJwksCredentials(request):
                return new OidcError(
                    ErrorCodes.InvalidClientMetadata,
                    "Clients using 'client_secret_jwt' authentication must provide either 'jwks' or 'jwks_uri'.");

            // Client secret basic/post - should NOT have JWKS (would indicate wrong auth method)
            case ClientAuthenticationMethods.ClientSecretBasic or ClientAuthenticationMethods.ClientSecretPost
                when HasJwksCredentials(request):

                return new OidcError(
                    ErrorCodes.InvalidClientMetadata,
                    $"Clients using '{request.TokenEndpointAuthMethod}' authentication should not provide 'jwks' or 'jwks_uri'. " +
                    "Did you mean to use 'private_key_jwt'?");

            // TLS auth - should NOT have JWKS (uses certificate-based authentication)
            case ClientAuthenticationMethods.TlsClientAuth or ClientAuthenticationMethods.SelfSignedTlsClientAuth
                when HasJwksCredentials(request):

                return new OidcError(
                    ErrorCodes.InvalidClientMetadata,
                    $"Clients using '{request.TokenEndpointAuthMethod}' authentication should not provide 'jwks' or 'jwks_uri'. " +
                    "TLS authentication uses certificate-based authentication, not JWKs.");

            // TLS auth - MUST have TLS metadata
            case ClientAuthenticationMethods.TlsClientAuth or ClientAuthenticationMethods.SelfSignedTlsClientAuth
                when !HasTlsMetadata(request):

                return new OidcError(
                    ErrorCodes.InvalidClientMetadata,
                    $"Clients using '{request.TokenEndpointAuthMethod}' authentication must provide at least one TLS metadata field: " +
                    "'tls_client_auth_subject_dn', 'tls_client_auth_san_dns', 'tls_client_auth_san_uri', " +
                    "'tls_client_auth_san_ip', or 'tls_client_auth_san_email'.");
        }

        return null;
    }

    /// <summary>
    /// Checks if the request contains JWKS credentials (either jwks or jwks_uri).
    /// </summary>
    private static bool HasJwksCredentials(ClientRegistrationRequest request)
        => request is { Jwks.Keys.Length: > 0 } or { JwksUri: not null };

    /// <summary>
    /// Checks if the request contains TLS metadata for certificate-based authentication.
    /// </summary>
    private static bool HasTlsMetadata(ClientRegistrationRequest request)
        => request
            is { TlsClientAuthSubjectDn.Length: > 0 }
            or { TlsClientAuthSanDns.Length: > 0 }
            or { TlsClientAuthSanUri.Length: > 0 }
            or { TlsClientAuthSanIp.Length: > 0 }
            or { TlsClientAuthSanEmail.Length: > 0 };
}
