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
using Abblix.Utils;
using Microsoft.Extensions.Logging;
using static Abblix.Oidc.Server.Model.ClientRegistrationRequest;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// This class validates the subject type in a client registration request. It checks if the subject type is pairwise,
/// and if so, verifies the sector identifier URI and its content. It also ensures that all redirect URIs use the HTTPS scheme.
/// If any validation fails, it returns a AuthError.
/// </summary>
/// <param name="secureHttpFetcher">The secure HTTP fetcher for retrieving content from external URIs.</param>
/// <param name="logger">The logger for logging purposes.</param>
public class SubjectTypeValidator(
    ISecureHttpFetcher secureHttpFetcher,
    ILogger<SubjectTypeValidator> logger): IClientRegistrationContextValidator
{
    /// <summary>
    /// Validates the subject type in the client registration request.
    /// </summary>
    /// <param name="context">The validation context containing client registration data.</param>
    /// <returns>
    /// A AuthError if any validation fails, or null if the request is valid.
    /// </returns>
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

        var missingUris = sectorIdentifierContent.Except(redirectUris).ToArray();
        if (missingUris.Length > 0)
        {
            logger.LogWarning(
                "The following URIs are present in the {SectorIdentifierUri}, but missing from the Redirect URIs: {@MissingUris}",
                Sanitized.Value(sectorIdentifierUri),
                missingUris);

            return ErrorFactory.InvalidClientMetadata(
                $"The content received from the {Parameters.SectorIdentifierUri} contains one or more URIs that are not in the registered list of redirect URIs");
        }

        return null;
    }

    /// <summary>
    /// Validates pairwise subject type when no sector identifier URI is provided.
    /// </summary>
    private static OidcError? Validate(ClientRegistrationValidationContext context)
    {
        var redirectUris = context.Request.RedirectUris;

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
