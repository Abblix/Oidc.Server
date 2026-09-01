// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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

        // A client registering no redirect URIs satisfies the subset check below with nothing to check:
        // the rule is that everything it registered must appear in the sector document, and it registered
        // nothing. Passing an empty set says that, where passing null would only ask the question again.
        var error = ValidateSectorIdentifierContent(
            sectorIdentifierUri,
            contentResult.GetSuccess(),
            context.Request.RedirectUris ?? []);

        if (error != null)
            return error;

        context.SectorIdentifier = sectorIdentifierUri.Host;
        return null;
    }

    /// <summary>
    /// Whether a URI can have a sector host taken from it at all.
    /// </summary>
    /// <remarks>
    /// Both halves, because the first one throws without the second: <see cref="Uri.Scheme"/> raises
    /// <see cref="InvalidOperationException"/> on a relative URI rather than returning anything, so a
    /// scheme comparison on its own turns a registration that should be refused into a server fault.
    /// <para>
    /// Nothing upstream can be relied on to have looked. <c>RedirectUrisValidator</c> enters its
    /// absoluteness loop only for the grant types that cannot answer without a redirect URI, so a
    /// CIBA-only registration walks past it with the list untouched; and the entries of a sector
    /// identifier document come from an address the client chose, so they are third-party JSON arriving
    /// at the same expression. <c>[AbsoluteUri]</c> is honoured by the form binder rather than by the
    /// JSON deserializer, so a registration body carries a relative value through intact.
    /// </para>
    /// </remarks>
    private static bool IsHttpsUri(Uri uri) => uri.IsAbsoluteUri && uri.Scheme == Uri.UriSchemeHttps;

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
        if (sectorIdentifierContent.Any(uri => !IsHttpsUri(uri)))
        {
            return ErrorFactory.InvalidClientMetadata(
                "Every URI in the sector identifier document must be an absolute https URI");
        }

        // OIDC Core §8.1 / OIDC Registration §5: the values of the registered redirect_uris MUST be
        // included in the elements of the sector identifier document - the subset check goes from the
        // registration towards the document, not the other way around. The document is intentionally
        // shareable across several clients of the same sector, so it may list URIs this client did not
        // register. The inverted check (document minus registration) both rejected such legitimate
        // shared documents and let a client register a redirect URI absent from the document - i.e.
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

        if (redirectUris.Any(uri => !IsHttpsUri(uri)))
        {
            return ErrorFactory.InvalidClientMetadata(
                "Every redirect URI must be an absolute https URI to take a sector host from");
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
