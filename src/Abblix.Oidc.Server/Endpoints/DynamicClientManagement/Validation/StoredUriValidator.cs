// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using static Abblix.Oidc.Server.Model.ClientRegistrationRequest;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// Refuses a registration carrying a relative URI in any member, so no address is stored on a client
/// without something having read it.
/// </summary>
/// <remarks>
/// Every URI member is named here, including the ones another validator also looks at. Those others are
/// each GATED on something that is not the address - a pairwise subject type, a TLS authentication
/// method, a backchannel delivery mode, a grant type that redirects - so a registration naming none of
/// those walks past them with the member stored. What is asked here is asked unconditionally.
/// <para>
/// What makes this a defect rather than tidiness is <c>frontchannel_logout_uri</c>. A relative value
/// reaches <c>FrontChannelLogoutService</c>, which builds the logout page's frame-source policy with
/// <see cref="Uri.GetLeftPart"/> - and that raises on a relative URI, unconditionally, at logout rather
/// than at registration.
/// </para>
/// <para>
/// ABSOLUTENESS only. The scheme requirements in this pipeline are conditional - a native client's
/// redirect URI carries its own, a fetched address answers to the deployment's policy - and the
/// validators that own those conditions already state them. What is unconditional is that a stored
/// address must name somewhere.
/// </para>
/// <para>
/// The list is written out rather than reflected over, because a reader of this file should be able to
/// see what is checked. What keeps it from falling behind - which it did twice while it was shorter - is
/// <c>UriMemberCoverageTests</c>, which finds every URI member on the model by its TYPE and requires
/// this validator to refuse a relative value in each. A member added without a line here fails that row.
/// </para>
/// </remarks>
public class StoredUriValidator : SyncClientRegistrationContextValidator
{
    /// <summary>
    /// Returns an <c>invalid_client_metadata</c> error naming the first member that carries a relative
    /// URI; <c>null</c> when every member is absent or absolute.
    /// </summary>
    protected override OidcError? Validate(ClientRegistrationValidationContext context)
    {
        var request = context.Request;

        return Validate(Parameters.LogoUri, request.LogoUri)
            ?? Validate(Parameters.ClientUri, request.ClientUri)
            ?? Validate(Parameters.PolicyUri, request.PolicyUri)
            ?? Validate(Parameters.TosUri, request.TermsOfServiceUri)
            ?? Validate(Parameters.JwksUri, request.JwksUri)
            ?? Validate(Parameters.SectorIdentifierUri, request.SectorIdentifierUri)
            ?? Validate(Parameters.InitiateLoginUri, request.InitiateLoginUri)
            ?? Validate(Parameters.BackChannelLogoutUri, request.BackChannelLogoutUri)
            ?? Validate(Parameters.FrontChannelLogoutUri, request.FrontChannelLogoutUri)
            ?? Validate(
                Parameters.BackChannelClientNotificationEndpoint,
                request.BackChannelClientNotificationEndpoint)
            ?? Validate(Parameters.RedirectUris, request.RedirectUris)
            ?? Validate(Parameters.PostLogoutRedirectUris, request.PostLogoutRedirectUris)
            ?? Validate(Parameters.RequestUris, request.RequestUris)
            ?? Validate(Parameters.TlsClientAuthSanUri, request.TlsClientAuthSanUri);
    }

    /// <summary>
    /// A single member: absent passes, relative is refused.
    /// </summary>
    /// <remarks>
    /// Null means the member was not sent, and absence is not a bad address.
    /// </remarks>
    private static OidcError? Validate(string name, Uri? uri)
        => uri is { IsAbsoluteUri: false } ? Relative(name) : null;

    /// <summary>
    /// An array member: every element answered by the rule above, plus the one rule an element has and a
    /// member does not.
    /// </summary>
    /// <remarks>
    /// A null ELEMENT is refused where a null MEMBER passes. The member was never sent and absence is
    /// not a bad address; the element was sent and names nothing. Written out rather than folded into
    /// the single-value rule, because that difference is the whole reason the two are separate methods -
    /// and because a registration body is attacker-shaped JSON where the deserializer honours no
    /// annotation against an explicit null, so <c>[null]</c> is reachable and once faulted the endpoint.
    /// </remarks>
    private static OidcError? Validate(string name, Uri[]? uris)
    {
        if (uris is null)
            return null;

        foreach (var uri in uris)
        {
            if (uri is null)
                return Relative(name);

            if (Validate(name, uri) is { } error)
                return error;
        }

        return null;
    }

    private static OidcError Relative(string member)
        => ErrorFactory.InvalidClientMetadata($"The {member} is not an absolute URI");
}
