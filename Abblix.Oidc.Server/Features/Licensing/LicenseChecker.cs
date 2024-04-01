// Abblix OpenID Connect Server Library
// Copyright (c) 2024 by Abblix LLP
// 
// This software is provided 'as-is', without any express or implied warranty. In no
// event will the authors be held liable for any damages arising from the use of this
// software.
// 
// Permitted Use: This software is open for use and extension by non-profit,
// educational and community projects under the condition that it remains unmodified
// and used in its entirety through official Nuget packages. Any unauthorized
// modification, forking of the whole repository, or altering individual files is
// strictly prohibited to ensure development occurs solely within the official Abblix LLP
// repository.
// 
// Prohibited Actions: Redistribution, modification, incorporation of this software or
// any part thereof into other products, and creation of derivative works are not
// permitted without obtaining a commercial license from Abblix LLP.
// 
// Commercial Use: A separate license is required for commercial use, including
// functionalities extended beyond the original software. For information on obtaining
// a commercial license, please contact Abblix LLP.
// 
// Enforcement: Unauthorized redistribution, modification, or use of this software in
// other projects or products is strictly prohibited without prior written permission
// from the copyright holder. Violations may be subject to legal action.
// 
// For more information, please refer to the license agreement located at:
// https://github.com/Abblix/Oidc.Server/blob/master/README.md

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
