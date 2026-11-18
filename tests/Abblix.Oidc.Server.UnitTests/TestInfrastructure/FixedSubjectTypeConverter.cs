// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Collections.Generic;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;

namespace Abblix.Oidc.Server.UnitTests.TestInfrastructure;

/// <summary>
/// Converts every tenant's subjects with the one pairwise key a test configures, for a test about a service that
/// converts subjects rather than about where the key comes from.
/// </summary>
/// <param name="converter">The converter holding the key.</param>
internal sealed class FixedSubjectTypeConverter(SubjectTypeConverter converter) : ISubjectTypeConverter
{
    public FixedSubjectTypeConverter() : this(new SubjectTypeConverter())
    {
    }

    public IEnumerable<string> SubjectTypesSupported(TenantDefinition tenant) => converter.SubjectTypesSupported;

    public string Convert(TenantDefinition tenant, string subject, ClientInfo clientInfo)
        => converter.Convert(subject, clientInfo);

    public string? ConvertBack(TenantDefinition tenant, string subject, ClientInfo clientInfo)
        => converter.ConvertBack(subject, clientInfo);
}
