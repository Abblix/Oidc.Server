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

        return ValidateOptional(Parameters.LogoUri, request.LogoUri)
            ?? ValidateOptional(Parameters.ClientUri, request.ClientUri)
            ?? ValidateOptional(Parameters.PolicyUri, request.PolicyUri)
            ?? ValidateOptional(Parameters.TosUri, request.TermsOfServiceUri)
            ?? ValidateOptional(Parameters.JwksUri, request.JwksUri)
            ?? ValidateOptional(Parameters.SectorIdentifierUri, request.SectorIdentifierUri)
            ?? ValidateOptional(Parameters.InitiateLoginUri, request.InitiateLoginUri)
            ?? ValidateOptional(Parameters.BackChannelLogoutUri, request.BackChannelLogoutUri)
            ?? ValidateOptional(Parameters.FrontChannelLogoutUri, request.FrontChannelLogoutUri)
            ?? ValidateOptional(
                Parameters.BackChannelClientNotificationEndpoint,
                request.BackChannelClientNotificationEndpoint)
            ?? ValidateOptional(Parameters.RedirectUris, request.RedirectUris)
            ?? ValidateOptional(Parameters.PostLogoutRedirectUris, request.PostLogoutRedirectUris)
            ?? ValidateOptional(Parameters.RequestUris, request.RequestUris)
            ?? ValidateOptional(Parameters.TlsClientAuthSanUri, request.TlsClientAuthSanUri);
    }

    /// <summary>
    /// A member the registration may omit: absent passes, present must be absolute.
    /// </summary>
    /// <remarks>
    /// <c>null</c> means the member was not sent, and absence is not a bad address - almost every
    /// registration omits most of these, so refusing null here refuses nearly everything. Measured on
    /// the way to this shape: writing the test as <c>uri is not { IsAbsoluteUri: true }</c>, which is
    /// correct for an ELEMENT, turned 58 of 218 end-to-end rows red.
    /// </remarks>
    private static OidcError? ValidateOptional(string name, Uri? uri)
        => uri is { IsAbsoluteUri: false } ? Relative(name) : null;

    /// <summary>
    /// An array member the registration may omit: absent or empty passes, every element present is
    /// answered by <see cref="ValidateElement"/>.
    /// </summary>
    private static OidcError? ValidateOptional(string name, Uri[]? uris)
    {
        if (uris is null)
            return null;

        foreach (var uri in uris)
        {
            if (ValidateElement(name, uri) is { } error)
                return error;
        }

        return null;
    }

    /// <summary>
    /// One element of an array member: it was sent, so <c>null</c> is refused rather than passed.
    /// </summary>
    /// <remarks>
    /// The one place this differs from <see cref="ValidateOptional(string, Uri?)"/>, and the reason the
    /// two are separate methods rather than one. A null MEMBER was never sent; a null ELEMENT was sent
    /// and names nothing, so it is a bad value rather than an absent one. Both are reachable because a
    /// registration body is attacker-shaped JSON and the deserializer honours no annotation against an
    /// explicit null - <c>[null]</c> once faulted the endpoint by being dereferenced here.
    /// </remarks>
    private static OidcError? ValidateElement(string name, Uri? uri)
        => uri is not { IsAbsoluteUri: true } ? Relative(name) : null;

    private static OidcError Relative(string member)
        => ErrorFactory.InvalidClientMetadata($"The {member} is not an absolute URI");
}
