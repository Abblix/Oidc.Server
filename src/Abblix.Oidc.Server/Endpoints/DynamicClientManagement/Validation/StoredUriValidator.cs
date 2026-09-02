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
/// A null single member is ABSENT and passes; a null ELEMENT of an array was sent and is refused. That
/// asymmetry is the shape a registration body has: it is attacker-shaped JSON and the deserializer
/// honours no annotation against an explicit null, so both are reachable and they mean different things.
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

        var singles = new[]
        {
            (Parameters.LogoUri, request.LogoUri),
            (Parameters.ClientUri, request.ClientUri),
            (Parameters.PolicyUri, request.PolicyUri),
            (Parameters.TosUri, request.TermsOfServiceUri),
            (Parameters.JwksUri, request.JwksUri),
            (Parameters.SectorIdentifierUri, request.SectorIdentifierUri),
            (Parameters.InitiateLoginUri, request.InitiateLoginUri),
            (Parameters.BackChannelLogoutUri, request.BackChannelLogoutUri),
            (Parameters.FrontChannelLogoutUri, request.FrontChannelLogoutUri),
            (Parameters.BackChannelClientNotificationEndpoint, request.BackChannelClientNotificationEndpoint),
        };

        foreach (var (name, uri) in singles)
        {
            if (uri is { IsAbsoluteUri: false })
                return Relative(name);
        }

        var arrays = new[]
        {
            (Parameters.RedirectUris, request.RedirectUris),
            (Parameters.PostLogoutRedirectUris, request.PostLogoutRedirectUris),
            (Parameters.RequestUris, request.RequestUris),
            (Parameters.TlsClientAuthSanUri, request.TlsClientAuthSanUri),
        };

        foreach (var (name, uris) in arrays)
        {
            if (uris is { Length: > 0 } && Array.Exists(uris, uri => uri is not { IsAbsoluteUri: true }))
                return Relative(name);
        }

        return null;
    }

    private static OidcError Relative(string member)
        => ErrorFactory.InvalidClientMetadata($"The {member} is not an absolute URI");
}
