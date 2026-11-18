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
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.Telemetry;

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

    /// <summary>Makes the check whether an issuer still fits and its counting one step.</summary>
    private static readonly Lock IssuerAdmission = new();

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
    /// Applies the license's terms to the issuer a token is issued under and to the client it is issued to.
    /// </summary>
    /// <param name="issuer">The issuer the token names, checked as <see cref="CheckIssuer"/> checks it.</param>
    /// <param name="tenant">The tenant the token is issued for.</param>
    /// <param name="catalog">The catalog that tenant was resolved from.</param>
    /// <param name="clientId">The client the token names as issued to.</param>
    /// <returns>The issuer, when the terms allow both.</returns>
    /// <remarks>
    /// A client is counted where a token is issued to it, by the client and the issuer the token names, so every
    /// client a token is issued to is counted and two tenants registering a client under one id take two places. A
    /// client of a tenant the server's own catalog serves stops counting once the tenant is released, once the tenant's
    /// definition stops configuring it, or once it is removed through registration. A client of a tenant a catalog of
    /// the host's own resolved stays counted for the life of the process.
    /// </remarks>
    /// <exception cref="InvalidOperationException">The issuer is beyond the license's terms, or the client is beyond
    /// its client limit by more than the margin.</exception>
    public static string CheckLicense(string issuer, TenantDefinition tenant, ITenantCatalog catalog, string clientId)
    {
        // One answer for the issuer and its client, so a catalog refreshed between the two counts both alike
        var counted = CountedAs(issuer, tenant, catalog);
        CheckCountedIssuer(issuer, counted);
        CheckClient((counted.Key, clientId), counted.Released);
        return issuer;
    }

    /// <summary>
    /// Counts <paramref name="client"/>, and refuses it past the client limit by more than the margin.
    /// </summary>
    private static void CheckClient((string IssuerId, string ClientId) client, CancellationToken released)
    {
        var utcNow = TimeProvider.System.GetUtcNow();
        var currentLicense = LicenseManager.TryGetCurrentLicenseLimit(utcNow) ?? FreeLicense;
        if (!currentLicense.ClientLimit.HasValue)
            return;

        // One count for every caller: requests arriving together each assigning a count of their own would each
        // be counted in a count nobody else reads
        var knownClientIds = LazyInitializer.EnsureInitialized(
            ref _knownClientIds,
            () => new ConcurrentDictionary<(string IssuerId, string ClientId), Counted>());
        if (currentLicense.ClientLimit.Value * ClientLimitOverExceedingFactor < knownClientIds.Count &&
            !knownClientIds.ContainsKey(client))
        {
            if (LicenseLogger.Instance.IsAllowed(new { Client = client }, utcNow, TimeSpan.FromMinutes(1)))
            {
                LogClientLimitExceededByMargin(
                    LicenseLogger.Instance,
                    currentLicense.ClientLimit,
                    knownClientIds.Keys.Select(Named),
                    Named(client));
            }

            throw new LicenseViolationException(LicenseRefusalReasons.ClientLimit);
        }

        Count(knownClientIds, client, client.ClientId, released);
        if (currentLicense.ClientLimit.Value < knownClientIds.Count &&
            LicenseLogger.Instance.IsAllowed(new { Client = client }, utcNow, TimeSpan.FromMinutes(15)))
        {
            LogClientLimitExceeded(
                LicenseLogger.Instance,
                currentLicense.ClientLimit.Value,
                knownClientIds.Keys.Select(Named));
        }
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
    /// What <paramref name="issuer"/> and its clients are counted under, and what lets them go: the tenant, when the
    /// server's own catalog vouches that it serves this creation of it at that issuer, or else the issuer itself,
    /// until the server releases that tenant; for a tenant a catalog of the host's own resolved, the issuer itself,
    /// counted for the life of the process.
    /// </summary>
    /// <remarks>
    /// Only the server's own sealed catalog is taken at its word: a catalog a host registers answers for itself, and
    /// taking its word would let one answer count every issuer, or every client of an id, as one. The tenant is a
    /// definition anybody can build, so it is vouched for by the catalog's own record of the creations it served at
    /// the issuer, never by its id alone.
    /// </remarks>
    private static (string Key, CancellationToken Released) CountedAs(
        string issuer,
        TenantDefinition tenant,
        ITenantCatalog catalog)
    {
        if (catalog is not StoreTenantCatalog own)
            return (issuer, CancellationToken.None);

        var released = own.Released(tenant);
        if (VouchedId(issuer, tenant, own) is { } id)
            return (id, released);

        // An issuer the server does not vouch for is let go with its tenant, but one the tenant was never served at and
        // first seen after its release would be let go before it was ever counted, so it counts for the life of the
        // process
        return (issuer, released.IsCancellationRequested ? CancellationToken.None : released);
    }

    /// <summary>
    /// The tenant the clients of <paramref name="issuer"/> are counted with, when the server's own catalog vouches
    /// that it serves this creation of the tenant there. Null for any other issuer, whose clients are counted with the
    /// issuer and are not taken off the count by a removal through registration.
    /// </summary>
    /// <param name="issuer">The issuer the tokens of those clients name.</param>
    /// <param name="tenant">The tenant served at that issuer.</param>
    /// <param name="catalog">The catalog that tenant was resolved from.</param>
    internal static string? ClientIssuerOf(string issuer, TenantDefinition tenant, ITenantCatalog catalog)
        => VouchedId(issuer, tenant, catalog);

    /// <summary>
    /// The id of <paramref name="tenant"/> when the server's own catalog vouches that it serves this creation of the
    /// tenant at <paramref name="issuer"/>; null for a catalog of the host's own and for an issuer
    /// <see cref="StoreTenantCatalog.HasServedAt"/> does not vouch for.
    /// </summary>
    private static string? VouchedId(string issuer, TenantDefinition tenant, ITenantCatalog catalog)
        => catalog is StoreTenantCatalog own && own.HasServedAt(tenant, issuer) ? tenant.Id : null;

    /// <summary>
    /// Takes the clients <paramref name="clientIds"/> of the issuer <paramref name="issuerId"/> off the count, as ones
    /// that issuer no longer serves: removed through registration, or dropped from the clients a tenant configures.
    /// </summary>
    /// <remarks>
    /// A request that found one of them before the release counts it again, and it then stays counted until its
    /// issuer is released, or for the life of the process where it never is; with the count past the margin, such a
    /// request is refused instead.
    /// </remarks>
    internal static void ReleaseClients(string issuerId, IEnumerable<string> clientIds)
    {
        if (_knownClientIds is not { } counted)
            return;

        foreach (var clientId in clientIds)
            counted.TryRemove((issuerId, clientId), out _);
    }

    /// <summary>
    /// A counted client as a log names it: its id after the tenant or issuer it is counted under.
    /// </summary>
    private static string Named((string IssuerId, string ClientId) client)
        => $"{client.IssuerId}/{client.ClientId}";

    /// <summary>
    /// Counts <paramref name="issuer"/> when it is counted already or still fits under <paramref name="issuerLimit"/>,
    /// and answers whether it did.
    /// </summary>
    /// <remarks>
    /// The issuer beyond the count is refused and left uncounted, so the issuers served within the limit go on being
    /// served; counted first, one extra issuer would push the count over and refuse them all. One step, or two new
    /// issuers asking at once could both find a place. A count above the limit can then only come from the license
    /// narrowing or expiring under issuers already served, and that refuses every issuer, as the deployment no longer
    /// fits the license it runs under.
    /// </remarks>
    private static bool TryAdmitIssuer(
        ConcurrentDictionary<string, Counted> knownIssuers,
        string issuer,
        (string Key, CancellationToken Released) counted,
        int issuerLimit)
    {
        var (key, released) = counted;
        lock (IssuerAdmission)
        {
            if (issuerLimit < knownIssuers.Count || !knownIssuers.ContainsKey(key) && issuerLimit <= knownIssuers.Count)
                return false;

            Count(knownIssuers, key, issuer, released);
            return true;
        }
    }

    /// <summary>
    /// Whether the license in force serves <paramref name="issuer"/>: it names no issuers, or names this one.
    /// </summary>
    internal static bool NamesIssuer(string issuer)
        => Names(LicenseManager.TryGetCurrentLicenseLimit(TimeProvider.System.GetUtcNow()) ?? FreeLicense, issuer);

    private static bool Names(License license, string issuer)
        => license.ValidIssuers is not { Count: > 0 } validIssuers || validIssuers.Contains(issuer);

    /// <summary>
    /// How many issuers the license in force allows, or null when it sets no limit.
    /// </summary>
    internal static int? IssuerLimit
        => (LicenseManager.TryGetCurrentLicenseLimit(TimeProvider.System.GetUtcNow()) ?? FreeLicense).IssuerLimit;

    /// <summary>
    /// Applies licensing checks to an issuer value.
    /// </summary>
    /// <param name="issuer">The issuer to check against licensing constraints.</param>
    /// <param name="tenant">The tenant served at that issuer.</param>
    /// <param name="catalog">The catalog that tenant was resolved from, which tells when the tenant is gone for good
    /// and its issuer stops counting toward the limit, so a deployment whose tenants come and go counts the issuers it
    /// serves; a tenant a catalog of the host's own resolved is counted by the issuer string and never released.
    /// </param>
    /// <returns>The issuer if it complies with the licensing constraints; otherwise, logs an error.</returns>
    public static string CheckIssuer(string issuer, TenantDefinition tenant, ITenantCatalog catalog)
        => CheckCountedIssuer(issuer, CountedAs(issuer, tenant, catalog));

    private static string CheckCountedIssuer(string issuer, (string Key, CancellationToken Released) counted)
    {
        var utcNow = TimeProvider.System.GetUtcNow();
        var currentLicense = LicenseManager.TryGetCurrentLicenseLimit(utcNow) ?? FreeLicense;

        if (!Names(currentLicense, issuer))
        {
            // Throttled like every other license log site. A misconfigured issuer is reported on every single
            // request, so an unthrottled Critical record here floods the log - and on Windows the Event Log -
            // with one entry per request, drowning the very message an operator needs to find.
            if (LicenseLogger.Instance.IsAllowed(new { issuer }, utcNow, TimeSpan.FromMinutes(15)))
            {
                // Log error: the allowed list of issuers does not contain current value.
                LogIssuerNotAllowed(LicenseLogger.Instance, issuer, currentLicense.ValidIssuers);
            }

            throw new LicenseViolationException(LicenseRefusalReasons.IssuerNotAllowed);
        }

        if (currentLicense.IssuerLimit is { } issuerLimit)
        {
            // One count for every caller, as with the clients
            var knownIssuers = LazyInitializer.EnsureInitialized(
                ref _knownIssuers,
                () => new ConcurrentDictionary<string, Counted>(StringComparer.Ordinal));
            if (!TryAdmitIssuer(knownIssuers, issuer, counted, issuerLimit))
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
                        issuerLimit,
                        knownIssuers.Values.Select(counted => counted.Name),
                        issuer);
                }

                throw new LicenseViolationException(LicenseRefusalReasons.IssuerLimit);
            }
        }

        return issuer;
    }
}
