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
/// Validates that every remaining URI member a registration can carry names a destination, so that no
/// address is stored on a client without something having read it.
/// </summary>
/// <remarks>
/// The members here are the ones that had no validator at all: each was deserialized, stored on the
/// client and echoed back with nothing checking anything. They are gathered into one class because what
/// they share is the whole rule - a stored address must be absolute - rather than because they belong
/// together in the specification.
/// <para>
/// The member that makes this a defect rather than tidiness is <c>frontchannel_logout_uri</c>. A
/// relative value reaches <c>new UriBuilder(uri)</c> in <c>FrontChannelLogoutNotifier</c>, which throws
/// on a relative URI - the same shape as a relative address faulting at fetch time, one member over,
/// and at logout rather than at registration. The rest are addresses shown to a person, where a
/// relative value resolves against whatever page happens to render it.
/// </para>
/// <para>
/// ABSOLUTENESS only, and deliberately no opinion on the scheme. An https requirement for these members
/// is a claim about what the specifications say, and this file does not make claims it has not read:
/// the members this server FETCHES have their scheme decided by the fetch policy, which is a different
/// question and is answered by <see cref="JwksUriValidator"/> and
/// <see cref="BackChannelLogoutUriValidator"/>.
/// </para>
/// </remarks>
public class StoredUriValidator : SyncClientRegistrationContextValidator
{
    /// <summary>
    /// Returns an <c>invalid_client_metadata</c> error naming the first member that carries a relative
    /// URI; <c>null</c> when every one it reads is absent or absolute.
    /// </summary>
    protected override OidcError? Validate(ClientRegistrationValidationContext context)
    {
        var request = context.Request;

        // Named one by one rather than by reflection over the model: a member added later should have to
        // be thought about, and a loop over "every Uri property" would silently adopt one whose rule is
        // not this rule - a sector identifier, an address the fetch policy owns.
        var singles = new[]
        {
            (Parameters.FrontChannelLogoutUri, request.FrontChannelLogoutUri),
            (Parameters.LogoUri, request.LogoUri),
            (Parameters.ClientUri, request.ClientUri),
            (Parameters.PolicyUri, request.PolicyUri),
            (Parameters.TosUri, request.TermsOfServiceUri),
        };

        foreach (var (name, uri) in singles)
        {
            if (uri is { IsAbsoluteUri: false })
                return Relative(name);
        }

        if (request.RequestUris is { Length: > 0 } requestUris
            && Array.Exists(requestUris, uri => !uri.IsAbsoluteUri))
        {
            return Relative(Parameters.RequestUris);
        }

        return null;
    }

    private static OidcError Relative(string member)
        => ErrorFactory.InvalidClientMetadata($"The {member} is not an absolute URI");
}
