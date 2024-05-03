// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
// 
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
// 
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
// 
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
// 
// For full licensing terms, please visit:
// 
// https://oidc.abblix.com/license
// 
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

using System.Collections.Concurrent;
using Abblix.Oidc.Server.Features.ClientInformation;
using Microsoft.Extensions.Logging;

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
public static class LicenseChecker
{
    private const double ClientLimitOverExceedingFactor = 1.3;

    private static readonly License FreeLicense = new() { ClientLimit = 2, IssuerLimit = 1 };
    private static readonly LicenseManager LicenseManager = new();

    private static ConcurrentDictionary<string, object>? _knownClientIds;
    private static ConcurrentDictionary<string, object>? _knownIssuers;

    /// <summary>
    /// Registers a new license with the license management system, allowing for real-time updates
    /// to the application's licensing constraints.
    /// </summary>
    /// <param name="license">The license to add to the system.</param>
    internal static void AddLicense(License license) => LicenseManager.AddLicense(license);

    /// <summary>
    /// Asynchronously applies licensing checks to a task that returns client information.
    /// </summary>
    /// <param name="clientInfo">The task returning client information to be checked against licensing constraints.
    /// </param>
    /// <returns>A task that, upon completion, returns the client information if it complies with the licensing
    /// constraints; otherwise, logs an error.</returns>
    public static async Task<ClientInfo?> WithLicenseCheck(this Task<ClientInfo?> clientInfo)
        => (await clientInfo).CheckClient();

    /// <summary>
    /// Applies licensing checks to client information.
    /// </summary>
    /// <param name="clientInfo">The client information to check against licensing constraints.</param>
    /// <returns>The client information if it complies with the licensing constraints; otherwise, logs an error.
    /// </returns>
    public static ClientInfo? CheckClient(this ClientInfo? clientInfo)
    {
        if (clientInfo != null)
        {
            var utcNow = DateTimeOffset.UtcNow;
            var currentLicense = LicenseManager.TryGetCurrentLicenseLimit(utcNow) ?? FreeLicense;
            if (currentLicense.ClientLimit.HasValue)
            {
                _knownClientIds ??= new ConcurrentDictionary<string, object>(StringComparer.Ordinal);
                if (currentLicense.ClientLimit.Value * ClientLimitOverExceedingFactor < _knownClientIds.Count &&
                    !_knownClientIds.ContainsKey(clientInfo.ClientId))
                {
                    if (LicenseLogger.Instance.IsAllowed(new { clientInfo.ClientId }, utcNow, TimeSpan.FromMinutes(1)))
                    {
                        LicenseLogger.Instance.LogCritical(
                            "Client limit exceeded: licensed for {ClientLimit} clients, current count exceeds by more than 30%. Used client IDs: {@ClientIds}, new client ID: {ClientId}",
                            currentLicense.ClientLimit,
                            _knownClientIds.Keys,
                            clientInfo.ClientId);
                    }

                    return null; // Prevents processing of clients exceeding the limit by more than 30%
                }

                _knownClientIds.TryAdd(clientInfo.ClientId, null!);
                if (currentLicense.ClientLimit.Value < _knownClientIds.Count &&
                    LicenseLogger.Instance.IsAllowed(new { clientInfo.ClientId }, utcNow, TimeSpan.FromMinutes(15)))
                {
                    LicenseLogger.Instance.LogError(
                        "Licensed client limit of {ClientLimit} exceeded. Current clients: {@ClientIds}. Immediate license upgrade required",
                        currentLicense.ClientLimit.Value, _knownClientIds.Keys);
                }
            }
        }

        return clientInfo;
    }

    /// <summary>
    /// Applies licensing checks to an issuer value.
    /// </summary>
    /// <param name="issuer">The issuer to check against licensing constraints.</param>
    /// <returns>The issuer if it complies with the licensing constraints; otherwise, logs an error.</returns>
    public static string CheckIssuer(string issuer)
    {
        var utcNow = DateTimeOffset.UtcNow;
        var currentLicense = LicenseManager.TryGetCurrentLicenseLimit(utcNow) ?? FreeLicense;

        if (currentLicense.ValidIssuers is { Count: > 0 } && !currentLicense.ValidIssuers.Contains(issuer))
        {
            // Log error: the allowed list of issuers does not contain current value.
            LicenseLogger.Instance.LogCritical("The issuer {Issuer} is not allowed by current license. The list of allowed issuers is {@Issuers}",
                issuer, currentLicense.ValidIssuers);

            throw new InvalidOperationException("The license terms violation detected");
        }

        if (currentLicense.IssuerLimit.HasValue)
        {
            _knownIssuers ??= new ConcurrentDictionary<string, object>(StringComparer.Ordinal);
            _knownIssuers.TryAdd(issuer, null!);
            if (currentLicense.IssuerLimit.Value < _knownIssuers.Count &&
                LicenseLogger.Instance.IsAllowed(new { issuer }, utcNow, TimeSpan.FromMinutes(15)))
            {
                // Log error: Exceeded the licensed limit of issuers.
                LicenseLogger.Instance.LogError("Exceeded the licensed limit of issuers: {IssuerLimit}. The list of used issuers is {@Issuers}",
                    currentLicense.IssuerLimit.Value, _knownIssuers.Keys);

                throw new InvalidOperationException("The license terms violation detected");
            }
        }

        return issuer;
    }
}
