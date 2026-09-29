// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.Issuer;

/// <summary>
/// The settings of the one issuer a deployment without multi-tenancy serves, taken from <see cref="OidcOptions"/>.
/// </summary>
/// <param name="options">The options holding the issuer's settings.</param>
/// <param name="pairwiseSubject">The pairwise key, registered apart from the options, or null when there is none.
/// </param>
internal sealed class OptionsIssuerSettings(
    IOptions<OidcOptions> options,
    PairwiseSubjectSettings? pairwiseSubject = null) : IIssuerSettings
{
    /// <inheritdoc />
    public IEnumerable<ClientInfo> Clients => options.Value.Clients;

    /// <inheritdoc />
    public ScopeDefinition[]? Scopes => options.Value.Scopes;

    /// <inheritdoc />
    public ResourceDefinition[]? Resources => options.Value.Resources;

    /// <inheritdoc />
    public Uri? DefaultResourceIndicator => options.Value.DefaultResourceIndicator;

    /// <inheritdoc />
    public Uri? AccountSelectionUri => options.Value.AccountSelectionUri;

    /// <inheritdoc />
    public Uri? ConsentUri => options.Value.ConsentUri;

    /// <inheritdoc />
    public Uri? InteractionUri => options.Value.InteractionUri;

    /// <inheritdoc />
    public Uri? LoginUri => options.Value.LoginUri;

    /// <inheritdoc />
    public Uri? RegistrationUri => options.Value.RegistrationUri;

    /// <inheritdoc />
    public ClientSecurityProfile DefaultSecurityProfile => options.Value.DefaultSecurityProfile;

    /// <inheritdoc />
    public PairwiseSubjectSettings? PairwiseSubject => pairwiseSubject;
}
