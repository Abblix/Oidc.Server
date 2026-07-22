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
using Abblix.Oidc.Server.Features.SecureHttpFetch;
using Microsoft.Extensions.Logging;
using static Abblix.Oidc.Server.Model.ClientRegistrationRequest;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// Validates the OIDC Core §8 <c>subject_type</c> metadata and computes the pairwise sector
/// identifier per OIDC Core §8.1: when <c>pairwise</c> is requested, either a supplied
/// <c>sector_identifier_uri</c> (HTTPS, JSON document of redirect URIs) is dereferenced and
/// cross-checked against the registered <c>redirect_uris</c>, or all redirect URIs must
/// share a single host. The resolved host is stored on the context for later persistence.
/// </summary>
/// <param name="logger">Logger used for warnings about sector-identifier mismatches.</param>
/// <param name="secureHttpFetcher">SSRF-protected fetcher for the sector identifier document.</param>
public partial class SubjectTypeValidator(
    ILogger<SubjectTypeValidator> logger,
    ISecureHttpFetcher secureHttpFetcher): IClientRegistrationContextValidator
{
    /// <inheritdoc />
    public async Task<OidcError?> ValidateAsync(ClientRegistrationValidationContext context)
    {
        var request = context.Request;
        if (request.SubjectType != SubjectTypes.Pairwise)
            return null;

        var sectorIdentifierUri = request.SectorIdentifierUri;
        if (sectorIdentifierUri != null)
            return await Validate(context, sectorIdentifierUri);

        return Validate(context);
    }

    /// <summary>
    /// Validates pairwise subject type when sector identifier URI is provided.
    /// </summary>
    private async Task<OidcError?> Validate(
        ClientRegistrationValidationContext context,
        Uri sectorIdentifierUri)
    {
        var validationError = ValidateSectorIdentifierUriFormat(sectorIdentifierUri);
        if (validationError != null)
            return validationError;

        // SSRF protection is handled by the SsrfValidatingHttpFetcher decorator
        var contentResult = await secureHttpFetcher.FetchAsync<Uri[]>(sectorIdentifierUri);
        if (contentResult.TryGetFailure(out var contentError))
            return contentError;

        var error = ValidateSectorIdentifierContent(
            sectorIdentifierUri,
            contentResult.GetSuccess(),
            context.Request.RedirectUris);

        if (error != null)
            return error;

        context.SectorIdentifier = sectorIdentifierUri.Host;
        return null;
    }

    /// <summary>
    /// Validates that sector identifier URI has correct format (absolute URI with HTTPS scheme).
    /// </summary>
    private static OidcError? ValidateSectorIdentifierUriFormat(Uri sectorIdentifierUri)
    {
        if (!sectorIdentifierUri.IsAbsoluteUri)
        {
            return ErrorFactory.InvalidClientMetadata(
                $"{Parameters.SectorIdentifierUri} must be absolute URI");
        }

        if (sectorIdentifierUri.Scheme != Uri.UriSchemeHttps)
        {
            return ErrorFactory.InvalidClientMetadata(
                $"{Parameters.SectorIdentifierUri} must have {Uri.UriSchemeHttps} scheme");
        }

        return null;
    }

    /// <summary>
    /// Validates the content fetched from sector identifier URI.
    /// </summary>
    private OidcError? ValidateSectorIdentifierContent(
        Uri sectorIdentifierUri,
        Uri[] sectorIdentifierContent,
        IEnumerable<Uri> redirectUris)
    {
        if (sectorIdentifierContent.Any(uri => uri.Scheme != Uri.UriSchemeHttps))
        {
            return ErrorFactory.InvalidClientMetadata("All schemes in the redirect URIs must be https");
        }

        // OIDC Core §8.1 / OIDC Registration §5: the values of the registered redirect_uris MUST be
        // included in the elements of the sector identifier document — the subset check goes from the
        // registration towards the document, not the other way around. The document is intentionally
        // shareable across several clients of the same sector, so it may list URIs this client did not
        // register. The inverted check (document minus registration) both rejected such legitimate
        // shared documents and let a client register a redirect URI absent from the document — i.e.
        // claim a sector it does not belong to, breaking pairwise subject isolation.
        var missingUris = redirectUris.Except(sectorIdentifierContent).ToArray();
        if (missingUris.Length > 0)
        {
            LogSectorIdentifierMissingUris(sectorIdentifierUri, missingUris);

            return ErrorFactory.InvalidClientMetadata(
                $"One or more registered redirect URIs are not listed in the document fetched from the {Parameters.SectorIdentifierUri}");
        }

        return null;
    }

    /// <summary>
    /// Validates pairwise subject type when no sector identifier URI is provided.
    /// </summary>
    private static OidcError? Validate(ClientRegistrationValidationContext context)
    {
        var redirectUris = context.Request.RedirectUris;

        // Without a redirect URI there is no host, and the host is what a pairwise identifier is derived
        // from when no sector identifier URI was registered - so this combination cannot be honoured and
        // is refused rather than worked around. It is reachable: a client asking only for a grant type
        // that needs no redirection registers none, which the redirect URI validator correctly permits,
        // and it arrives here with the list absent or empty.
        if (redirectUris is not { Length: > 0 })
        {
            return ErrorFactory.InvalidClientMetadata(
                "The client specified pairwise subject type without a sector identifier URI, which needs "
                + "a redirect URI to take the host from, and none was registered");
        }

        if (redirectUris.Any(uri => uri.Scheme != Uri.UriSchemeHttps))
        {
            return ErrorFactory.InvalidClientMetadata("All schemes in the redirect URIs must be https");
        }

        var hosts = redirectUris.Select(uri => uri.Host).Distinct().ToArray();
        if (hosts.Length > 1)
        {
            return ErrorFactory.InvalidRedirectUri(
                "The client specified pairwise subject type, but provides several redirect URIs with different hosts");
        }

        context.SectorIdentifier = hosts[0];
        return null;
    }
}
