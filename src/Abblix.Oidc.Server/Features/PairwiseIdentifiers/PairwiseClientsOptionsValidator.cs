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
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.PairwiseIdentifiers;

/// <summary>
/// Refuses at startup configured clients that take pairwise subject identifiers from a server with no key to seal
/// them.
/// </summary>
/// <remarks>
/// Such a client is served and fails every token request with a 500, while discovery says pairwise is not
/// supported. The key judged is the one registered for the whole server; under multi-tenancy each tenant's clients
/// are judged against the tenant's own key instead.
/// </remarks>
/// <param name="pairwiseSubject">The pairwise key registered for the whole server, or null when there is none.
/// </param>
public sealed class PairwiseClientsOptionsValidator(PairwiseSubjectSettings? pairwiseSubject = null)
    : IValidateOptions<OidcOptions>
{
    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, OidcOptions options)
        => Refusal(options.Clients, pairwiseSubject) is { } refusal
            ? ValidateOptionsResult.Fail(refusal)
            : ValidateOptionsResult.Success;

    /// <summary>
    /// Why <paramref name="clients"/> cannot be served with <paramref name="pairwiseSubject"/>, or null when they
    /// can.
    /// </summary>
    public static string? Refusal(IEnumerable<ClientInfo>? clients, PairwiseSubjectSettings? pairwiseSubject)
    {
        if (pairwiseSubject is not null)
            return null;

        var pairwise = (clients ?? [])
            .Where(client => client.SubjectType == SubjectTypes.Pairwise)
            .Select(client => $"'{client.ClientId}'")
            .ToArray();

        return pairwise.Length == 0
            ? null
            : $"The clients {string.Join(", ", pairwise)} take pairwise subject identifiers, but no pairwise key is " +
              "configured to seal them.";
    }
}
