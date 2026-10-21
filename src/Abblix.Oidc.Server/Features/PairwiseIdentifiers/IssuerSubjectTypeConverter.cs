// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.MultiTenancy;

namespace Abblix.Oidc.Server.Features.PairwiseIdentifiers;

/// <summary>
/// Converts subjects with the pairwise key of the tenant they are issued for, keeping one
/// <see cref="SubjectTypeConverter"/> for each tenant.
/// </summary>
/// <param name="converters">The converter of each tenant.</param>
internal sealed class IssuerSubjectTypeConverter(IIssuerLocal<SubjectTypeConverter> converters) : ISubjectTypeConverter
{
    private SubjectTypeConverter ConverterOf(TenantDefinition tenant)
    {
        var pairwiseSubject = tenant.PairwiseSubject;
        return converters.GetOrCreate(tenant, pairwiseSubject, () => new SubjectTypeConverter(pairwiseSubject));
    }

    /// <inheritdoc />
    public IEnumerable<string> SubjectTypesSupported(TenantDefinition tenant)
        => ConverterOf(tenant).SubjectTypesSupported;

    /// <inheritdoc />
    public string Convert(TenantDefinition tenant, string subject, ClientInfo clientInfo)
        => ConverterOf(tenant).Convert(subject, clientInfo);

    /// <inheritdoc />
    public string? ConvertBack(TenantDefinition tenant, string subject, ClientInfo clientInfo)
        => ConverterOf(tenant).ConvertBack(subject, clientInfo);
}
