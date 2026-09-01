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
using Abblix.Oidc.Server.Model;
using Microsoft.Extensions.Logging;
using static Abblix.Oidc.Server.Model.ClientRegistrationRequest;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// Validates the OIDC Core Section 8 <c>subject_type</c> metadata and computes the pairwise sector
/// identifier. When <c>pairwise</c> is requested, a supplied <c>sector_identifier_uri</c> (HTTPS) is
/// dereferenced and every URI the registration is required to have listed there is checked against
/// its contents; otherwise the host is taken from the registered redirect URIs, which must agree on
/// one (OIDC Core Section 8.1). A backchannel client that registered NO redirect URI takes its host
/// instead from the URI CIBA Core 1.0 Section 4 puts in their place - the <c>jwks_uri</c> in poll and
/// ping, the <c>backchannel_client_notification_endpoint</c> in push. Registering both is allowed and
/// they need not agree: the redirect URIs decide, and the backchannel URI is only ever the sector of a
/// client that has none.
/// The resolved host is stored on the context for later persistence.
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
            RequiredInSectorDocument(context.Request));

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
    /// The URIs this registration must have listed in its sector identifier document.
    /// </summary>
    /// <remarks>
    /// OIDC Core Section 8.1 puts the redirect URIs there. CIBA Core 1.0 Section 4 adds two more and
    /// says which one by delivery mode: "In CIBA Poll and Ping modes the jwks_uri is used in place of
    /// the redirect_uri. In CIBA Push mode the backchannel_client_notification_endpoint is used in
    /// place of the redirect_uri", and the sector document "can contain jwks_uris and
    /// backchannel_client_notification_endpoints as well as redirect_uri".
    /// <para>
    /// Each entry is conditional on the mode that names it, so a registration with no delivery mode
    /// contributes exactly what it did before this existed. A URI the client did not register
    /// contributes nothing - the subset check asks whether what was REGISTERED appears in the
    /// document, so an absent value has nothing to be missing.
    /// </para>
    /// </remarks>
    private static IEnumerable<Uri> RequiredInSectorDocument(ClientRegistrationRequest request)
    {
        // A client registering no redirect URIs satisfies the subset check with nothing to check: the
        // rule is that everything it registered must appear in the sector document, and it registered
        // nothing. Yielding nothing says that, where a null would only ask the question again.
        foreach (var redirectUri in request.RedirectUris ?? [])
            yield return redirectUri;

        switch (request.BackChannelTokenDeliveryMode)
        {
            case BackchannelTokenDeliveryModes.Push
                when request.BackChannelClientNotificationEndpoint is {} notificationEndpoint:
                yield return notificationEndpoint;
                break;

            case BackchannelTokenDeliveryModes.Poll or BackchannelTokenDeliveryModes.Ping
                when request.JwksUri is {} jwksUri:
                yield return jwksUri;
                break;
        }
    }

    /// <summary>
    /// Validates the content fetched from sector identifier URI.
    /// </summary>
    private OidcError? ValidateSectorIdentifierContent(
        Uri sectorIdentifierUri,
        Uri[] sectorIdentifierContent,
        IEnumerable<Uri> requiredUris)
    {
        if (sectorIdentifierContent.Any(uri => uri.Scheme != Uri.UriSchemeHttps))
        {
            return ErrorFactory.InvalidClientMetadata("All schemes in the sector identifier document must be https");
        }

        // OIDC Core Section 8.1 / OIDC Registration Section 5: the registered values MUST be included in the elements
        // of the sector identifier document - the subset check goes from the registration towards the
        // document, not the other way around. The document is intentionally shareable across several
        // clients of the same sector, so it may list URIs this client did not register. The inverted
        // check (document minus registration) both rejected such legitimate shared documents and let a
        // client register a URI absent from the document - i.e. claim a sector it does not belong to,
        // breaking pairwise subject isolation.
        var missingUris = requiredUris.Except(sectorIdentifierContent).ToArray();
        if (missingUris.Length > 0)
        {
            LogSectorIdentifierMissingUris(sectorIdentifierUri, missingUris);

            // The missing values are named individually. A message saying "redirect URIs" to a client
            // whose notification endpoint was the omission sends its author to the wrong metadata.
            return ErrorFactory.InvalidClientMetadata(
                $"These registered URIs are not listed in the document fetched from the "
                + $"{Parameters.SectorIdentifierUri}: {string.Join(", ", (object[])missingUris)}");
        }

        return null;
    }

    /// <summary>
    /// Validates pairwise subject type when no sector identifier URI is provided.
    /// </summary>
    private static OidcError? Validate(ClientRegistrationValidationContext context)
    {
        var redirectUris = context.Request.RedirectUris;
        if (redirectUris is { Length: > 0 })
            return ValidateFromRedirectUris(context, redirectUris);

        // A client asking only for a grant type that needs no redirection registers no redirect URI,
        // which the redirect URI validator correctly permits, so it arrives here with the list absent
        // or empty. CIBA Core 1.0 Section 4 says where its host comes from instead: "In CIBA Poll and
        // Ping modes the jwks_uri is used in place of the redirect_uri. In CIBA Push mode the
        // backchannel_client_notification_endpoint is used in place of the redirect_uri."
        var sectorUri = SectorUriForDeliveryMode(context.Request);
        if (sectorUri == null)
        {
            return ErrorFactory.InvalidClientMetadata(
                "The client specified pairwise subject type without a sector identifier URI, so the host "
                + "is taken from a registered URI: a redirect URI, or for a backchannel client the "
                + "jwks_uri in poll and ping modes and the backchannel_client_notification_endpoint in "
                + "push mode. None of these was registered");
        }

        // Absoluteness is checked rather than assumed, and both halves matter. A registration body
        // is attacker-shaped JSON: [AbsoluteUri] is honoured by the form binder, not by the JSON
        // deserializer, so a relative "/jwks" arrives intact and every Uri member below it - Scheme,
        // Host - throws rather than returning anything. And the scheme is checked HERE because for
        // poll and ping nothing else ever checks the jwks_uri's: BackChannelAuthenticationValidator
        // enforces the specification's "It MUST be an HTTPS URL" for the notification endpoint alone,
        // and is registered after this validator besides. Delete this and https stops being required
        // of the value a poll client's whole sector is derived from.
        if (!sectorUri.IsAbsoluteUri || sectorUri.Scheme != Uri.UriSchemeHttps)
        {
            return ErrorFactory.InvalidClientMetadata(
                "The URI a pairwise sector identifier is taken from must be an absolute https URI");
        }

        context.SectorIdentifier = sectorUri.Host;
        return null;
    }

    /// <summary>
    /// The URI whose host is the sector for a backchannel client that registered no redirect URI,
    /// or <c>null</c> when the registration names none.
    /// </summary>
    /// <remarks>
    /// A registration with no delivery mode yields null here and is refused, which is what this method
    /// did before it could answer anything else. The absent-mode arm returns null rather than throwing
    /// because an absent mode is a valid non-backchannel registration, not an unhandled case.
    /// </remarks>
    private static Uri? SectorUriForDeliveryMode(ClientRegistrationRequest request)
        => request.BackChannelTokenDeliveryMode switch
        {
            BackchannelTokenDeliveryModes.Push => request.BackChannelClientNotificationEndpoint,

            // Ping registers a notification endpoint too, and its sector is still the jwks_uri: Section 4
            // groups ping with poll for this, and only push with the notification endpoint.
            BackchannelTokenDeliveryModes.Poll or BackchannelTokenDeliveryModes.Ping => request.JwksUri,

            _ => null,
        };

    /// <summary>
    /// Takes the sector from the registered redirect URIs, which must be https and share one host.
    /// </summary>
    private static OidcError? ValidateFromRedirectUris(
        ClientRegistrationValidationContext context,
        Uri[] redirectUris)
    {
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
