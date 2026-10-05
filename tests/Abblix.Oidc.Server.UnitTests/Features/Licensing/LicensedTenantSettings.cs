// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Collections.Generic;
using System.Threading;
using Abblix.Jwt;
using Abblix.Jwt.ExternalKeys;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.Licensing;
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;

namespace Abblix.Oidc.Server.UnitTests.Features.Licensing;

/// <summary>
/// A tenant's creation as the server's own settings present it to the license: its id and its release, every other
/// setting that of a server without tenants.
/// </summary>
internal sealed class LicensedTenantSettings(string id, CancellationToken released) : IIssuerSettings, ILicensedIssuer
{
    private static readonly IIssuerSettings Rest = SingleIssuer.Settings;

    public string Id => id;

    public string? VouchedId => id;

    public CancellationToken Released => released;

    public string KeyPartition => Rest.KeyPartition;

    public IEnumerable<ClientInfo> Clients => Rest.Clients;

    public ScopeDefinition[]? Scopes => Rest.Scopes;

    public ResourceDefinition[]? Resources => Rest.Resources;

    public Uri? DefaultResourceIndicator => Rest.DefaultResourceIndicator;

    public bool InferResourceFromScope => Rest.InferResourceFromScope;

    public Uri? AccountSelectionUri => Rest.AccountSelectionUri;

    public Uri? ConsentUri => Rest.ConsentUri;

    public Uri? InteractionUri => Rest.InteractionUri;

    public Uri? LoginUri => Rest.LoginUri;

    public Uri? RegistrationUri => Rest.RegistrationUri;

    public ClientSecurityProfile DefaultSecurityProfile => Rest.DefaultSecurityProfile;

    public PairwiseSubjectSettings? PairwiseSubject => Rest.PairwiseSubject;

    public string CheckSessionCookieName => Rest.CheckSessionCookieName;

    public IReadOnlyCollection<JsonWebKey> SigningKeys => Rest.SigningKeys;

    public IReadOnlyCollection<JsonWebKey> EncryptionKeys => Rest.EncryptionKeys;

    public CustodianHeldKeys? CustodianKeys => Rest.CustodianKeys;

    public Uri? MtlsBaseUri => Rest.MtlsBaseUri;
}
