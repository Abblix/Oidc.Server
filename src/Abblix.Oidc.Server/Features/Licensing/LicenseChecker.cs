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
    /// Applies the license's terms to the issuer a token is issued under and to the client it is issued to.
    /// </summary>
    /// <param name="issuer">The issuer the token names, checked as <see cref="CheckIssuer"/> checks it.</param>
    /// <param name="settings">The settings of that issuer.</param>
    /// <param name="clientId">The client the token names as issued to.</param>
    /// <returns>The issuer, when the terms allow both.</returns>
    /// <remarks>
    /// A client is counted where a token is issued to it, by the client and the issuer the token names, so every
    /// client a token is issued to is counted and two tenants registering a client under one id take two places. A
    /// client of a tenant the server's own catalog serves stops counting once the tenant is released, once the tenant's
    /// definition stops configuring it, or once it is removed through registration; on a server without tenants, once it is removed through registration or dropped by
    /// a reload of the settings, served by the reloadable client store. A client counted under any other settings stays
    /// counted for the life of the process.
    /// </remarks>
    /// <exception cref="InvalidOperationException">The issuer is beyond the license's terms, or the client is beyond
    /// its client limit by more than the margin.</exception>
    public static string CheckLicense(string issuer, IIssuerSettings settings, string clientId)
    {
        CheckIssuer(issuer, settings);
        CheckClient((VouchedId(settings) ?? issuer, clientId), ReleasedOf(settings));
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

        _knownClientIds ??= new ConcurrentDictionary<(string IssuerId, string ClientId), Counted>();
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

            throw new InvalidOperationException("The license terms violation detected");
        }

        Count(_knownClientIds, client, client.ClientId, released);
        if (currentLicense.ClientLimit.Value < _knownClientIds.Count &&
            LicenseLogger.Instance.IsAllowed(new { Client = client }, utcNow, TimeSpan.FromMinutes(15)))
        {
            LogClientLimitExceeded(
                LicenseLogger.Instance,
                currentLicense.ClientLimit.Value,
                _knownClientIds.Keys.Select(Named));
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
    /// The tenant the server's own settings vouch for: empty on a server without tenants, and null for settings a
    /// host registers or a tenant a catalog of the host's own resolved, which are counted by the issuer they serve.
    /// </summary>
    /// <remarks>
    /// Settings a host registers answer for themselves, and taking their word would let one answer count every
    /// issuer, or every client of an id, as one.
    /// </remarks>
    private static string? VouchedId(IIssuerSettings settings) => (settings as ILicensedIssuer)?.VouchedId;

    /// <summary>
    /// What lets an issuer and its clients go: the release the server's own settings tell, and none for any other,
    /// whose issuers count for the life of the process.
    /// </summary>
    private static CancellationToken ReleasedOf(IIssuerSettings settings)
        => settings is ILicensedIssuer own ? own.Released : CancellationToken.None;

    /// <summary>
    /// The issuer the clients of <paramref name="settings"/> are counted with, when the server can tell it without a
    /// token: the tenant its own settings vouch for, or none on a server without tenants. Null for any other
    /// settings, whose clients are counted with the issuer each token names and are not taken off the count.
    /// </summary>
    internal static string? ClientIssuerOf(IIssuerSettings settings) => VouchedId(settings);

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
    /// toward the limit, so a deployment whose tenants come and go counts the issuers it serves; settings other than
    /// those of a tenant the server's own catalog serves, a server's without tenants included, are counted by the
    /// issuer string and never released.</param>
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
            var key = VouchedId(settings) is { Length: > 0 } tenantId ? tenantId : issuer;
            Count(_knownIssuers, key, issuer, ReleasedOf(settings));
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
