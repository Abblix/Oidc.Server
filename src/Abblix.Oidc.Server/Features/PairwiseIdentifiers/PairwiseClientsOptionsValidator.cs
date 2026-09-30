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
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.PairwiseIdentifiers;

/// <summary>
/// Refuses at startup configured clients that take pairwise subject identifiers from a server that cannot issue
/// them.
/// </summary>
/// <remarks>
/// Such a client is served and fails every token request with a 500, while discovery says pairwise is not
/// supported. Whether the server can issue them is the subject type converter's answer, the one discovery publishes
/// and dynamic registration relies on: the server's own converter can once a pairwise key is configured, and a
/// host's own may issue them another way. Under multi-tenancy each tenant's clients are judged against the
/// tenant's own key instead.
/// </remarks>
/// <param name="serviceProvider">The container the converter issuing subject identifiers is resolved from. It is
/// asked when a check runs rather than when this is built, because the server's converter reads settings the
/// options being checked serve, and taking it here would make the options depend on themselves.</param>
public sealed class PairwiseClientsOptionsValidator(IServiceProvider serviceProvider) : IValidateOptions<OidcOptions>
{
    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, OidcOptions options)
    {
        // The converter is asked only when a client takes pairwise identifiers, as few deployments have one
        var pairwise = PairwiseClients(options.Clients);
        if (pairwise.Length == 0 ||
            serviceProvider.GetService<ISubjectTypeConverter>() is not { } subjectTypeConverter ||
            subjectTypeConverter.SubjectTypesSupported.Contains(SubjectTypes.Pairwise))
        {
            return ValidateOptionsResult.Success;
        }

        return ValidateOptionsResult.Fail(Refusal(pairwise));
    }

    /// <summary>
    /// Why <paramref name="clients"/> cannot be served with <paramref name="pairwiseSubject"/> as the key sealing
    /// their pairwise identifiers, or null when they can.
    /// </summary>
    public static string? Refusal(IEnumerable<ClientInfo>? clients, PairwiseSubjectSettings? pairwiseSubject)
    {
        var pairwise = PairwiseClients(clients);
        return pairwiseSubject is null && pairwise.Length > 0 ? Refusal(pairwise) : null;
    }

    private static string[] PairwiseClients(IEnumerable<ClientInfo>? clients)
        => (clients ?? [])
            .Where(client => client.SubjectType == SubjectTypes.Pairwise)
            .Select(client => $"'{client.ClientId}'")
            .ToArray();

    private static string Refusal(string[] pairwise)
        => $"The clients {string.Join(", ", pairwise)} take pairwise subject identifiers, but no pairwise key is " +
           "configured to seal them.";
}
