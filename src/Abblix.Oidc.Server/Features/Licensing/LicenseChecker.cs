// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Collections.Concurrent;
using System.Collections.Immutable;
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

    private static ConcurrentDictionary<(string IssuerId, string ClientId), Counted>? _knownClientIds;
    private static ConcurrentDictionary<string, Counted>? _knownIssuers;

    // The creations each count watches for their release, one watch per creation however many entries it holds, so
    // the watches stay as many as the creations served while clients come and go
    private static readonly ConcurrentDictionary<(object Count, CancellationToken Holder), byte> Watched = new();

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
    /// forged Host header could vary to push the count past the limit. A client stops counting once its issuer is
    /// released, so a deployment whose tenants come and go counts the clients of the tenants it serves; with a
    /// catalog of tenants of the host's own, which tells no release, only a client removed through registration
    /// leaves the count. On a server without tenants, a client removed through registration or dropped by a reload of
    /// the settings, served by the reloadable client store, leaves the count.
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

        _knownClientIds ??= new ConcurrentDictionary<(string IssuerId, string ClientId), Counted>();
        var client = (ClientIssuerOf(issuer), clientInfo.ClientId);
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

        Count(_knownClientIds, client, clientInfo.ClientId, CountedAs(string.Empty, issuer).Released);
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
    /// Counts <paramref name="key"/> until <paramref name="holder"/> is canceled, so what the license meters is what
    /// the deployment serves now rather than everything the process has seen.
    /// </summary>
    /// <remarks>
    /// Each creation of the tenant that counts the entry holds it, and the entry leaves the count once every creation
    /// holding it is released, so a tenant created again under its id keeps its place while requests of the earlier
    /// creation finish. A creation released already counts for nothing while the catalog remembers the release, for
    /// one pause after it; a request outliving that counts the tenant for the rest of the process.
    /// </remarks>
    private static void Count<TKey>(
        ConcurrentDictionary<TKey, Counted> counted,
        TKey key,
        string name,
        CancellationToken holder)
        where TKey : notnull
    {
        // Added and taken off again at once, a released creation would still raise the count for that instant and
        // refuse a request of a tenant served at the limit meanwhile
        if (holder.IsCancellationRequested)
            return;

        bool held;
        bool written;
        do
        {
            if (counted.TryGetValue(key, out var entry))
            {
                held = entry.Holders.Contains(holder);
                if (held && entry.Name == name)
                    return;

                written = counted.TryUpdate(key, new Counted(name, entry.Holders.Add(holder)), entry);
            }
            else
            {
                held = false;
                written = counted.TryAdd(key, new Counted(name, [holder]));
            }
        }
        while (!written);

        if (!held && Watched.TryAdd((counted, holder), 0))
            ReleaseOnCancel(counted, holder);
    }

    /// <summary>
    /// Takes <paramref name="holder"/> off every entry of <paramref name="counted"/> once it is canceled.
    /// </summary>
    /// <remarks>
    /// Apart from <see cref="Count{TKey}"/>, whose every call would otherwise allocate the closure, while only the
    /// first count of a creation registers. The watch ends before the entries are read, so a count adding the
    /// creation after the reading registers again and is taken off at once.
    /// </remarks>
    private static void ReleaseOnCancel<TKey>(ConcurrentDictionary<TKey, Counted> counted, CancellationToken holder)
        where TKey : notnull
        => holder.Register(() =>
        {
            Watched.TryRemove((counted, holder), out _);
            foreach (var key in counted.Keys)
                Release(counted, key, holder);
        });

    /// <summary>
    /// Takes <paramref name="holder"/> off the entry under <paramref name="key"/>, and the entry off the count once
    /// no creation holds it.
    /// </summary>
    private static void Release<TKey>(ConcurrentDictionary<TKey, Counted> counted, TKey key, CancellationToken holder)
        where TKey : notnull
    {
        var released = false;
        while (!released && counted.TryGetValue(key, out var entry) && entry.Holders.Contains(holder))
        {
            var rest = entry.Holders.Remove(holder);
            released = rest.IsEmpty
                ? counted.TryRemove(new KeyValuePair<TKey, Counted>(key, entry))
                : counted.TryUpdate(key, new Counted(entry.Name, rest), entry);
        }
    }

    /// <summary>
    /// An entry of a count: the name a log gives it, and the releases of the creations holding it.
    /// </summary>
    /// <remarks>
    /// Compared by reference, so an entry is replaced only by a writer that read it as it stands.
    /// </remarks>
    private sealed class Counted(string name, ImmutableHashSet<CancellationToken> holders)
    {
        public string Name { get; } = name;

        public ImmutableHashSet<CancellationToken> Holders { get; } = holders;
    }

    /// <summary>
    /// What an issuer is counted under and what lets it go: its tenant and the tenant's release when the settings are
    /// the server's own, so a tenant moved to another address keeps one place; otherwise the address itself, counted
    /// for the life of the process.
    /// </summary>
    /// <remarks>
    /// Neither is taken from settings a host registers: their answer would otherwise take every issuer off the count,
    /// or count every issuer as one.
    /// </remarks>
    private static (string Key, CancellationToken Released) CountedAs(string issuer, IIssuerSettings settings)
        => settings is ILicensedIssuer { Id.Length: > 0 } own ? (own.Id, own.Released) : (issuer, CancellationToken.None);

    /// <summary>
    /// The issuer a client is counted with: its tenant when the settings are the server's own, so a client id two
    /// tenants share takes two places; otherwise none, as on a server serving one issuer.
    /// </summary>
    internal static string ClientIssuerOf(IIssuerSettings settings)
        => settings is ILicensedIssuer own ? own.Id : string.Empty;

    /// <summary>
    /// Takes the clients <paramref name="clientIds"/> of the issuer <paramref name="issuerId"/> off the count, as ones
    /// that issuer no longer serves: removed through registration, or dropped from the clients a tenant configures.
    /// </summary>
    /// <remarks>
    /// A request that found one of them before the release counts it again, and it then stays counted until its
    /// issuer is released, for the life of the process when the deployment serves one issuer; with the count past the
    /// margin, such a request is refused instead.
    /// </remarks>
    internal static void ReleaseClients(string issuerId, IEnumerable<string> clientIds)
    {
        if (_knownClientIds is not { } counted)
            return;

        foreach (var clientId in clientIds)
            counted.TryRemove((issuerId, clientId), out _);
    }

    /// <summary>
    /// A counted client as a log names it: its id, after the issuer's when the deployment serves several.
    /// </summary>
    private static string Named((string IssuerId, string ClientId) client)
        => client.IssuerId.Length == 0 ? client.ClientId : $"{client.IssuerId}/{client.ClientId}";

    /// <summary>
    /// How many issuers the license in force allows, or null when it sets no limit.
    /// </summary>
    internal static int? IssuerLimit
        => (LicenseManager.TryGetCurrentLicenseLimit(TimeProvider.System.GetUtcNow()) ?? FreeLicense).IssuerLimit;

    /// <summary>
    /// Applies licensing checks to an issuer value.
    /// </summary>
    /// <param name="issuer">The issuer to check against licensing constraints.</param>
    /// <param name="settings">The settings of that issuer, which tell when it is gone for good and stops counting
    /// toward the limit, so a deployment whose tenants come and go counts the issuers it serves; with a catalog of
    /// tenants of the host's own, which tells no release, the count only grows, and tenants it serves under one id
    /// take one place.</param>
    /// <returns>The issuer if it complies with the licensing constraints; otherwise, logs an error.</returns>
    public static string CheckIssuer(string issuer, IIssuerSettings settings)
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
            _knownIssuers ??= new ConcurrentDictionary<string, Counted>(StringComparer.Ordinal);
            var (key, released) = CountedAs(issuer, settings);
            Count(_knownIssuers, key, issuer, released);
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
                        _knownIssuers.Values.Select(counted => counted.Name));
                }

                throw new InvalidOperationException("The license terms violation detected");
            }
        }

        return issuer;
    }
}
