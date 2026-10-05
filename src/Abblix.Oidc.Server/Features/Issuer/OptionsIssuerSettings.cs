// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using Abblix.Jwt.ExternalKeys;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Licensing;
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.Issuer;

/// <summary>
/// The settings of the one issuer a deployment without multi-tenancy serves, taken from <see cref="OidcOptions"/>.
/// </summary>
/// <param name="options">The options holding the issuer's settings, read as they are now, so a reload reaches them.
/// </param>
/// <param name="pairwiseSubject">The pairwise key, registered apart from the options, or null when there is none.
/// </param>
/// <param name="custodianKeys">The custodian's keys to produce with, named when the custodian placement was chosen,
/// or null when none are named.</param>
internal sealed class OptionsIssuerSettings(
    IOptionsMonitor<OidcOptions> options,
    PairwiseSubjectSettings? pairwiseSubject = null,
    CustodianHeldKeys? custodianKeys = null) : IIssuerSettings, ILicensedIssuer
{
    /// <inheritdoc />
    public string Id => string.Empty;

    /// <inheritdoc />
    public string KeyPartition => KeyRingOptions.DefaultPartition;

    /// <inheritdoc />
    public CancellationToken Released => CancellationToken.None;

    /// <inheritdoc />
    string ILicensedIssuer.VouchedId => string.Empty;

    /// <inheritdoc />
    public IEnumerable<ClientInfo> Clients => options.CurrentValue.Clients;

    /// <inheritdoc />
    public ScopeDefinition[]? Scopes => options.CurrentValue.Scopes;

    /// <inheritdoc />
    public ResourceDefinition[]? Resources => options.CurrentValue.Resources;

    /// <inheritdoc />
    public Uri? DefaultResourceIndicator => options.CurrentValue.DefaultResourceIndicator;

    /// <inheritdoc />
    public bool InferResourceFromScope => options.CurrentValue.InferResourceFromScope;

    /// <inheritdoc />
    public Uri? AccountSelectionUri => options.CurrentValue.AccountSelectionUri;

    /// <inheritdoc />
    public Uri? ConsentUri => options.CurrentValue.ConsentUri;

    /// <inheritdoc />
    public Uri? InteractionUri => options.CurrentValue.InteractionUri;

    /// <inheritdoc />
    public Uri? LoginUri => options.CurrentValue.LoginUri;

    /// <inheritdoc />
    public Uri? RegistrationUri => options.CurrentValue.RegistrationUri;

    /// <inheritdoc />
    public ClientSecurityProfile DefaultSecurityProfile => options.CurrentValue.DefaultSecurityProfile;

    /// <inheritdoc />
    public PairwiseSubjectSettings? PairwiseSubject => pairwiseSubject;

    /// <inheritdoc />
    public string CheckSessionCookieName => options.CurrentValue.CheckSessionCookie.Name;

    /// <inheritdoc />
    public IReadOnlyCollection<JsonWebKey> SigningKeys => options.CurrentValue.SigningKeys;

    /// <inheritdoc />
    public IReadOnlyCollection<JsonWebKey> EncryptionKeys => options.CurrentValue.EncryptionKeys;

    /// <inheritdoc />
    public CustodianHeldKeys? CustodianKeys => custodianKeys;

    /// <inheritdoc />
    public Uri? MtlsBaseUri => options.CurrentValue.Discovery.MtlsBaseUri;
}
