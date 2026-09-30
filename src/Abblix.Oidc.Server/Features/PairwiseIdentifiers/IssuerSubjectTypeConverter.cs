// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Issuer;

namespace Abblix.Oidc.Server.Features.PairwiseIdentifiers;

/// <summary>
/// Converts subjects with the pairwise key of the issuer serving the request, keeping one
/// <see cref="SubjectTypeConverter"/> for each issuer.
/// </summary>
/// <param name="settings">The settings of the issuer serving the request, holding its pairwise key.</param>
/// <param name="converters">The converter of each issuer.</param>
internal sealed class IssuerSubjectTypeConverter(
    IIssuerSettings settings,
    IIssuerLocal<SubjectTypeConverter> converters) : ISubjectTypeConverter
{
    private SubjectTypeConverter Converter
    {
        get
        {
            var pairwiseSubject = settings.PairwiseSubject;
            return converters.GetOrCreate(pairwiseSubject, () => new SubjectTypeConverter(pairwiseSubject));
        }
    }

    /// <inheritdoc />
    public IEnumerable<string> SubjectTypesSupported => Converter.SubjectTypesSupported;

    /// <inheritdoc />
    public string Convert(string subject, ClientInfo clientInfo) => Converter.Convert(subject, clientInfo);

    /// <inheritdoc />
    public string? ConvertBack(string subject, ClientInfo clientInfo) => Converter.ConvertBack(subject, clientInfo);
}
