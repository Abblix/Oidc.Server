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

using System.Net;
using System.Security.Cryptography.X509Certificates;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// Validates tls_client_auth metadata fields for RFC 8705 mutual TLS client authentication.
/// Ensures that required metadata is present and properly formatted when tls_client_auth method is selected.
/// </summary>
public class TlsClientAuthValidator : SyncClientRegistrationContextValidator
{
    /// <summary>
    /// Validates the client registration context for tls_client_auth method.
    /// Ensures at least one identification field is provided and all fields are properly formatted.
    /// </summary>
    /// <param name="context">The client registration validation context containing the request to validate.</param>
    /// <returns>
    /// An <see cref="OidcError"/> if validation fails, or null if the request is valid or not using tls_client_auth.
    /// </returns>
    protected override OidcError? Validate(ClientRegistrationValidationContext context)
    {
        var request = context.Request;

        if (!IsTlsClientAuth(request))
            return null;

        if (!HasAnyTlsMetadata(request))
        {
            return ErrorFactory.InvalidClientMetadata(
                "When using tls_client_auth, at least one of the following must be specified: " +
                "tls_client_auth_subject_dn, tls_client_auth_san_dns, tls_client_auth_san_uri, " +
                "tls_client_auth_san_ip, or tls_client_auth_san_email");
        }

        return ValidateSubjectDn(request)
               ?? ValidateSanDns(request)
               ?? ValidateSanUris(request)
               ?? ValidateSanIps(request)
               ?? ValidateSanEmails(request);
    }

    /// <summary>
    /// Determines whether the client registration request is using tls_client_auth authentication method.
    /// </summary>
    /// <param name="request">The client registration request to check.</param>
    /// <returns>True if using tls_client_auth; otherwise, false.</returns>
    private static bool IsTlsClientAuth(ClientRegistrationRequest request) =>
        string.Equals(request.TokenEndpointAuthMethod, ClientAuthenticationMethods.TlsClientAuth, StringComparison.Ordinal);

    /// <summary>
    /// Checks whether any TLS client authentication metadata is provided in the request.
    /// At least one of Subject DN or SAN fields must be specified for tls_client_auth.
    /// </summary>
    /// <param name="request">The client registration request to check.</param>
    /// <returns>True if any TLS metadata is provided; otherwise, false.</returns>
    private static bool HasAnyTlsMetadata(ClientRegistrationRequest request) =>
        !string.IsNullOrWhiteSpace(request.TlsClientAuthSubjectDn) ||
        request.TlsClientAuthSanDns is { Length: > 0 } ||
        request.TlsClientAuthSanUri is { Length: > 0 } ||
        request.TlsClientAuthSanIp is { Length: > 0 } ||
        request.TlsClientAuthSanEmail is { Length: > 0 };

    /// <summary>
    /// Validates the Subject Distinguished Name field if provided.
    /// Ensures it conforms to RFC 4514 Distinguished Name format.
    /// </summary>
    /// <param name="request">The client registration request containing the Subject DN to validate.</param>
    /// <returns>An <see cref="OidcError"/> if validation fails; otherwise, null.</returns>
    private static OidcError? ValidateSubjectDn(ClientRegistrationRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.TlsClientAuthSubjectDn))
            return null;

        try
        {
            _ = new X500DistinguishedName(request.TlsClientAuthSubjectDn);
            return null;
        }
        catch
        {
            return ErrorFactory.InvalidClientMetadata(
                "Invalid tls_client_auth_subject_dn: must be a valid RFC 4514 Distinguished Name");
        }
    }

    /// <summary>
    /// Validates DNS Subject Alternative Name entries if provided.
    /// Ensures all DNS names are non-empty and do not contain whitespace characters.
    /// </summary>
    /// <param name="request">The client registration request containing DNS names to validate.</param>
    /// <returns>An <see cref="OidcError"/> if validation fails; otherwise, null.</returns>
    private static OidcError? ValidateSanDns(ClientRegistrationRequest request)
    {
        if (request.TlsClientAuthSanDns is not { Length: > 0 })
            return null;

        foreach (var dns in request.TlsClientAuthSanDns)
        {
            if (string.IsNullOrWhiteSpace(dns))
                return ErrorFactory.InvalidClientMetadata("tls_client_auth_san_dns entries must not be empty");

            if (dns.Contains(' ') || dns.Contains('\n') || dns.Contains('\r'))
                return ErrorFactory.InvalidClientMetadata($"Invalid DNS name in tls_client_auth_san_dns: '{dns}'");
        }

        return null;
    }

    /// <summary>
    /// Validates URI Subject Alternative Name entries if provided.
    /// Ensures all URIs are absolute URIs with scheme and host components.
    /// </summary>
    /// <param name="request">The client registration request containing URIs to validate.</param>
    /// <returns>An <see cref="OidcError"/> if validation fails; otherwise, null.</returns>
    private static OidcError? ValidateSanUris(ClientRegistrationRequest request)
    {
        if (request.TlsClientAuthSanUri is not { Length: > 0 })
            return null;

        if (request.TlsClientAuthSanUri.Any(uri => !uri.IsAbsoluteUri))
            return ErrorFactory.InvalidClientMetadata("Invalid URI in tls_client_auth_san_uri: must be absolute");

        return null;
    }

    /// <summary>
    /// Validates IP address Subject Alternative Name entries if provided.
    /// Ensures all IP addresses are valid IPv4 or IPv6 addresses.
    /// </summary>
    /// <param name="request">The client registration request containing IP addresses to validate.</param>
    /// <returns>An <see cref="OidcError"/> if validation fails; otherwise, null.</returns>
    private static OidcError? ValidateSanIps(ClientRegistrationRequest request)
    {
        if (request.TlsClientAuthSanIp is not { Length: > 0 })
            return null;

        return (
            from ip in request.TlsClientAuthSanIp
            where !IPAddress.TryParse(ip, out _)
            select ErrorFactory.InvalidClientMetadata($"Invalid IP address in tls_client_auth_san_ip: '{ip}'")
            ).FirstOrDefault();
    }

    /// <summary>
    /// Validates email Subject Alternative Name entries if provided.
    /// Performs basic validation ensuring emails are non-empty and contain an '@' character.
    /// </summary>
    /// <param name="request">The client registration request containing email addresses to validate.</param>
    /// <returns>An <see cref="OidcError"/> if validation fails; otherwise, null.</returns>
    private static OidcError? ValidateSanEmails(ClientRegistrationRequest request)
    {
        if (request.TlsClientAuthSanEmail is not { Length: > 0 })
            return null;

        return (
            from email in request.TlsClientAuthSanEmail
            where string.IsNullOrWhiteSpace(email) || !email.Contains('@')
            select ErrorFactory.InvalidClientMetadata($"Invalid email in tls_client_auth_san_email: '{email}'")
            ).FirstOrDefault();
    }
}
