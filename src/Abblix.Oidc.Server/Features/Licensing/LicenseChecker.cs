// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Collections.Concurrent;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Issuer;

namespace Abblix.Oidc.Server.Features.Licensing;

/// <summary>
/// Manages and enforces licensing constraints on clients and issuers within the application, ensuring compliance
/// with defined licensing terms.
/// </summary>
/// <remarks>
/// This class dynamically validates the number of clients and issuers against the licensing terms,
/// logging warnings or errors when the application
/// operates beyond these constraints. It supports real-time updates to the license,
/// allowing the application to adjust to new licenses dynamically.
/// </remarks>
public static partial class LicenseChecker
{
    private const double ClientLimitOverExceedingFactor = 1.3;

    /// <summary>
    /// What an installation gets with no license supplied: one issuer, and no ceiling on client applications.
    /// </summary>
    /// <remarks>
    /// The published terms meter the size of the company and the number of production issuers, never the number
    /// of client applications or users, so a client count here would refuse registrations the terms allow. The
    /// issuer limit stays because a second independent issuer is exactly what the terms do meter.
    /// The client-limit machinery below is kept for a license that carries the claim: absent it, nothing counts.
    /// </remarks>
    private static readonly License FreeLicense = new() { IssuerLimit = 1 };
    private static readonly LicenseManager LicenseManager = new();

    private static ConcurrentDictionary<(string IssuerId, string ClientId), object>? _knownClientIds;
    private static ConcurrentDictionary<string, object>? _knownIssuers;

    /// <summary>
    /// Registers a new license with the license management system, allowing for real-time updates
    /// to the application's licensing constraints.
    /// </summary>
    /// <param name="license">The license to add to the system.</param>
    internal static void AddLicense(License license) => LicenseManager.AddLicense(license);

    /// <summary>
    /// Reports what the loaded licenses mean for the deployment, once loading has finished.
    /// </summary>
    /// <param name="utcNow">The moment to evaluate the licenses at.</param>
    internal static void ReportLoadedLicenses(DateTimeOffset utcNow)
        => LicenseManager.ReportLoadedLicenses(utcNow);

    /// <summary>
    /// Asynchronously applies licensing checks to a task that returns client information.
    /// </summary>
    /// <param name="clientInfo">The task returning client information to be checked against licensing constraints.
    /// </param>
    /// <param name="issuer">The settings of the issuer the client is registered with.</param>
    /// <returns>A task that, upon completion, returns the client information if it complies with the licensing
    /// constraints; otherwise, logs an error.</returns>
    public static async Task<ClientInfo?> WithLicenseCheck(this Task<ClientInfo?> clientInfo, IIssuerSettings issuer)
        => (await clientInfo).CheckClientLicense(issuer);

    /// <summary>
    /// Applies licensing checks to client information.
    /// </summary>
    /// <param name="clientInfo">The client information to check against licensing constraints.</param>
    /// <param name="issuer">The settings of the issuer the client is registered with.</param>
    /// <returns>The client information if it complies with the licensing constraints; otherwise, logs an error.
    /// </returns>
    /// <remarks>
    /// A client is counted once for each issuer it is registered with, since two tenants may each register a client
    /// under one id. The issuer is the one the deployment declares rather than the one a request names, which a
    /// forged Host header could vary to push the count past the limit.
    /// </remarks>
    public static ClientInfo? CheckClientLicense(this ClientInfo? clientInfo, IIssuerSettings issuer)
    {
        // Guard clauses: nothing is counted for an absent client, or under a license that sets no client limit
        if (clientInfo == null)
            return clientInfo;

        var utcNow = TimeProvider.System.GetUtcNow();
        var currentLicense = LicenseManager.TryGetCurrentLicenseLimit(utcNow) ?? FreeLicense;
        if (!currentLicense.ClientLimit.HasValue)
            return clientInfo;

        _knownClientIds ??= new ConcurrentDictionary<(string IssuerId, string ClientId), object>();
        var client = (issuer.Id, clientInfo.ClientId);
        if (currentLicense.ClientLimit.Value * ClientLimitOverExceedingFactor < _knownClientIds.Count &&
            !_knownClientIds.ContainsKey(client))
        {
            if (LicenseLogger.Instance.IsAllowed(new { Client = client }, utcNow, TimeSpan.FromMinutes(1)))
            {
                LogClientLimitExceededByMargin(
                    LicenseLogger.Instance,
                    currentLicense.ClientLimit,
                    _knownClientIds.Keys.Select(Named),
                    Named(client));
            }

            return null; // Prevents processing of clients exceeding the limit by more than 30%
        }

        _knownClientIds.TryAdd(client, null!);
        if (currentLicense.ClientLimit.Value < _knownClientIds.Count &&
            LicenseLogger.Instance.IsAllowed(new { Client = client }, utcNow, TimeSpan.FromMinutes(15)))
        {
            LogClientLimitExceeded(
                LicenseLogger.Instance,
                currentLicense.ClientLimit.Value,
                _knownClientIds.Keys.Select(Named));
        }

        return clientInfo;
    }

    /// <summary>
    /// A counted client as a log names it: its id, after the issuer's when the deployment serves several.
    /// </summary>
    private static string Named((string IssuerId, string ClientId) client)
        => client.IssuerId.Length == 0 ? client.ClientId : $"{client.IssuerId}/{client.ClientId}";

    /// <summary>
    /// Applies licensing checks to an issuer value.
    /// </summary>
    /// <param name="issuer">The issuer to check against licensing constraints.</param>
    /// <returns>The issuer if it complies with the licensing constraints; otherwise, logs an error.</returns>
    public static string CheckIssuer(string issuer)
    {
        var utcNow = TimeProvider.System.GetUtcNow();
        var currentLicense = LicenseManager.TryGetCurrentLicenseLimit(utcNow) ?? FreeLicense;

        if (currentLicense.ValidIssuers is { Count: > 0 } && !currentLicense.ValidIssuers.Contains(issuer))
        {
            // Throttled like every other license log site. A misconfigured issuer is reported on every single
            // request, so an unthrottled Critical record here floods the log - and on Windows the Event Log -
            // with one entry per request, drowning the very message an operator needs to find.
            if (LicenseLogger.Instance.IsAllowed(new { issuer }, utcNow, TimeSpan.FromMinutes(15)))
            {
                // Log error: the allowed list of issuers does not contain current value.
                LogIssuerNotAllowed(LicenseLogger.Instance, issuer, currentLicense.ValidIssuers);
            }

            throw new InvalidOperationException("The license terms violation detected");
        }

        if (currentLicense.IssuerLimit.HasValue)
        {
            _knownIssuers ??= new ConcurrentDictionary<string, object>(StringComparer.Ordinal);
            _knownIssuers.TryAdd(issuer, null!);
            if (currentLicense.IssuerLimit.Value < _knownIssuers.Count)
            {
                // The decision is taken first and stands on its own; only the record of it is throttled. This
                // mirrors the client-limit block above, where the refusal sits outside the logging guard and
                // just the message inside it. Conditioning the decision on the logger would make the limit
                // hold only while the logger felt like speaking, and lapse silently in between.
                if (LicenseLogger.Instance.IsAllowed(new { issuer }, utcNow, TimeSpan.FromMinutes(15)))
                {
                    // Log error: Exceeded the licensed limit of issuers.
                    LogIssuerLimitExceeded(
                        LicenseLogger.Instance,
                        currentLicense.IssuerLimit.Value,
                        _knownIssuers.Keys);
                }

                throw new InvalidOperationException("The license terms violation detected");
            }
        }

        return issuer;
    }
}
