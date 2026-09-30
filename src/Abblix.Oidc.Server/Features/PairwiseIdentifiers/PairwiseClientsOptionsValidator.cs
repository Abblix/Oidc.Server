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
using Abblix.Oidc.Server.Features.MultiTenancy;
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
        // The converter is asked only when a client takes pairwise identifiers, as few deployments have one. Under
        // multi-tenancy the tenant list judges each tenant's clients by the tenant's key, and the server's own
        // clients are refused as server-wide, so there is nothing here to ask the tenants' converter about.
        var pairwise = PairwiseClients(options.Clients);
        if (pairwise.Length == 0 || UnderMultiTenancy)
            return ValidateOptionsResult.Success;

        ISubjectTypeConverter? subjectTypeConverter;
        try
        {
            subjectTypeConverter = serviceProvider.GetService<ISubjectTypeConverter>();
        }
        catch (InvalidOperationException exception)
        {
            return ValidateOptionsResult.Fail(
                $"The clients {string.Join(", ", pairwise)} take pairwise subject identifiers, and the subject type " +
                $"converter that would issue them could not be resolved at startup: {exception.Message}");
        }

        if (subjectTypeConverter is null)
            return ValidateOptionsResult.Success;

        bool issuesPairwise;
        try
        {
            issuesPairwise = subjectTypeConverter.SubjectTypesSupported.Contains(SubjectTypes.Pairwise);
        }
        catch (InvalidOperationException exception)
        {
            return ValidateOptionsResult.Fail(
                $"The clients {string.Join(", ", pairwise)} take pairwise subject identifiers, and the subject type " +
                $"converter{Named(subjectTypeConverter)} could not be asked at startup whether it issues them: " +
                $"{exception.Message}");
        }

        return issuesPairwise
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail(
                $"The clients {string.Join(", ", pairwise)} take pairwise subject identifiers, which the subject " +
                $"type converter{Named(subjectTypeConverter)} does not issue: configure a pairwise key for the " +
                "server's own converter, or register one that issues them.");
    }

    /// <summary>
    /// Whether the server serves tenants, told by the check of the tenant list that only multi-tenancy registers,
    /// asked of the container without building anything.
    /// </summary>
    private bool UnderMultiTenancy
        => serviceProvider.GetService<IServiceProviderIsService>() is { } services &&
#pragma warning disable ABXMT001
           services.IsService(typeof(IValidateOptions<MultiTenancyOptions>));
#pragma warning restore ABXMT001

    private static string Named(ISubjectTypeConverter subjectTypeConverter)
        => $" ({subjectTypeConverter.GetType().FullName})";

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
