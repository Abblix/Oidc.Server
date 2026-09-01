// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Buffers.Text;
using System.Text;
using Abblix.Jwt.Encryption;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;

namespace Abblix.Oidc.Server.Features.PairwiseIdentifiers;

/// <summary>
/// Implements the OIDC Core Section 8 subject types. A public client's subject passes through unchanged. A pairwise
/// client's subject is sealed into a per-sector pseudonym that is stable (the same user and sector always map to
/// the same value), opaque and unlinkable to outsiders, yet reversible by this server - so the real subject rides
/// inside the pseudonym itself and no separate protected claim is needed. The seal is a deterministic (SIV-style)
/// authenticated encryption keyed by the pairwise salt and bound to the sector as associated data, so different
/// sectors seal the same user to unlinkable values and a pseudonym cannot be opened under the wrong sector.
/// </summary>
public class SubjectTypeConverter : ISubjectTypeConverter
{
    private readonly DeterministicAeadEncryptor? _encryptor;

    /// <summary>
    /// Creates the converter. When <paramref name="settings"/> is present, its salt keys the reversible pairwise
    /// seal and its hash selects the pseudorandom function; when absent, only public subjects are supported and a
    /// pairwise request fails loud.
    /// </summary>
    /// <param name="settings">The pairwise salt and hash, or null when pairwise identifiers are not configured.</param>
    public SubjectTypeConverter(PairwiseSubjectSettings? settings = null)
    {
        _encryptor = settings switch
        {
            { HashAlgorithm: var algorithm, Salt: {} salt }
                => new DeterministicAeadEncryptor(algorithm, System.Convert.FromBase64String(salt)),

            _ => null,
        };
    }

    /// <summary>
    /// The two OIDC Core Section 8 subject types this converter implements: <c>public</c> (passes the local
    /// subject through unchanged) and <c>pairwise</c> (a reversible, per-sector sealed identifier).
    /// </summary>
    public IEnumerable<string> SubjectTypesSupported
    {
        get
        {
            yield return SubjectTypes.Public;
            yield return SubjectTypes.Pairwise;
        }
    }

    /// <summary>
    /// Converts the real subject into the client-facing subject: for a pairwise client, the reversible per-sector
    /// pseudonym; for a public client, the subject unchanged.
    /// </summary>
    public string Convert(string subject, ClientInfo clientInfo)
        => clientInfo.SubjectType switch
        {
            SubjectTypes.Pairwise => Base64Url.EncodeToString(
                Encryptor(clientInfo).Seal(Encoding.UTF8.GetBytes(subject), Sector(clientInfo))),
            _ => subject,
        };

    /// <summary>
    /// Recovers the real subject from the client-facing subject: for a pairwise client, opens the per-sector
    /// pseudonym; for a public client, returns the subject unchanged. Returns <c>null</c> when a pairwise pseudonym
    /// cannot be opened, so the caller can surface a protocol-level rejection instead of faulting.
    /// </summary>
    public string? ConvertBack(string subject, ClientInfo clientInfo) => clientInfo.SubjectType switch
    {
        SubjectTypes.Pairwise => ConvertBackPairwise(subject, clientInfo),
        _ => subject,
    };

    private string? ConvertBackPairwise(string pseudonym, ClientInfo clientInfo)
    {
        // The pseudonym is client-supplied (it rides in the token's 'sub'), so a value that is not valid base64url or
        // does not open is a rejected input, not a server fault: return null and let the caller surface the protocol
        // error. A missing pairwise configuration is a server misconfiguration and still throws (via Encryptor).
        var encryptor = Encryptor(clientInfo);

        byte[] sealedData;
        try
        {
            sealedData = Base64Url.DecodeFromChars(pseudonym);
        }
        catch (FormatException)
        {
            return null;
        }

        var subject = encryptor.Open(sealedData, Sector(clientInfo));
        return subject is not null ? Encoding.UTF8.GetString(subject) : null;
    }

    private DeterministicAeadEncryptor Encryptor(ClientInfo clientInfo)
        => _encryptor ?? throw new InvalidOperationException(
            "PairwiseSubjectSettings must be configured to use pairwise subject identifiers (client " +
            $"'{clientInfo.ClientId}' has {nameof(clientInfo.SubjectType)}={clientInfo.SubjectType}).");

    /// <summary>
    /// The sector the pseudonym is bound to (OIDC Core Section 8.1), as associated-data bytes.
    /// </summary>
    /// <remarks>
    /// When no sector_identifier_uri was provided, the sector is the host component of the registered redirect_uri,
    /// and for a backchannel client that registered NO redirect URI at all it is the host of the URI CIBA Core 1.0
    /// Section 4 puts in the redirect URI's place - the jwks_uri in poll and ping, the
    /// backchannel_client_notification_endpoint in push. "No redirect URI at all" rather than "no usable one", so
    /// that the custom-scheme case below keeps the client_id fallback the paragraph promises it: a native client
    /// registers redirect URIs whose host is meaningless, and letting those fall through to a shared jwks host
    /// would merge unrelated apps into one sector, which is the collision this whole method exists to prevent.
    /// A client_id fallback would produce identifiers that silently change when the same application is
    /// re-registered under a new client id, defeating the stability pairwise identifiers give a sector; it affects
    /// only statically configured clients, since DCR-registered pairwise clients always get SectorIdentifier
    /// computed at registration time, and remains the last resort for a client with none of those URIs (e.g. a pure
    /// client_credentials configuration). The host is meaningful only for http(s) redirect URIs - the web
    /// clients Core Section 8.1 had in mind. Native custom-scheme redirects (RFC 8252 Section 7.1) must not reach
    /// the host branch: the single-slash form (com.example.app:/oauth2redirect) parses with an EMPTY host, and the
    /// authority form (app-one://callback) puts an arbitrary path-like segment into Host - either way unrelated
    /// clients would silently share one sector and seal identical pseudonyms for the same user, defeating the
    /// isolation this subject type exists to provide. Such clients keep per-client isolation via the client_id
    /// fallback.
    /// <para>
    /// The backchannel URI is held to the same test, by the same predicate, because a sector is a sector
    /// whichever URI it came from: a jwks_uri spelled com.example.one:/keys parses as an absolute URI with an
    /// EMPTY host, and an empty host is not null, so the client_id fallback below never fires and every such
    /// client shares one sector. An http(s) URI cannot arrive that way - Uri refuses to construct http:/keys at
    /// all - so one predicate covers both the empty host and the relative URI, which would otherwise throw on
    /// Scheme rather than fall through to anything.
    /// </para>
    /// </remarks>
    private static byte[] Sector(ClientInfo clientInfo)
    {
        var sector =
            clientInfo.SectorIdentifier ??
            clientInfo.RedirectUris.FirstOrDefault(IsWebUri)?.Host ??
            BackchannelSectorHost(clientInfo) ??
            clientInfo.ClientId;

        return Encoding.UTF8.GetBytes(sector);
    }

    /// <summary>
    /// Whether a URI's host names a sector at all: the web clients OIDC Core Section 8.1 had in mind, and
    /// nothing else.
    /// </summary>
    private static bool IsWebUri(Uri uri)
        => uri.IsAbsoluteUri && (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps);

    /// <summary>
    /// The sector a backchannel client takes from the URI CIBA Core 1.0 Section 4 puts in the redirect URI's
    /// place, or <c>null</c> when this client is not one, registered a redirect URI, or named a URI whose host
    /// names nothing.
    /// </summary>
    private static string? BackchannelSectorHost(ClientInfo clientInfo)
        => clientInfo.RedirectUris.Length == 0 &&
           BackchannelSectorUri(clientInfo) is { } sectorUri &&
           IsWebUri(sectorUri)
            ? sectorUri.Host
            : null;

    /// <summary>
    /// The URI whose host is the sector for a backchannel client that registered no redirect URI, or
    /// <c>null</c> when this client is not one.
    /// </summary>
    /// <remarks>
    /// The same order the registration validator resolves, so a statically configured client and a
    /// dynamically registered one bind to the same sector rather than to whichever path reached them.
    /// A mode this server does not implement returns null and takes the client_id fallback. Nothing
    /// refuses such a mode on a statically configured client - the registration validator only sees
    /// requests that came over the network - so that client authenticates normally through whatever
    /// other grant it holds, and keeps the per-client sector it had before this method existed.
    /// </remarks>
    private static Uri? BackchannelSectorUri(ClientInfo clientInfo)
        => clientInfo.BackChannelTokenDeliveryMode switch
        {
            BackchannelTokenDeliveryModes.Push => clientInfo.BackChannelClientNotificationEndpoint,
            BackchannelTokenDeliveryModes.Poll or BackchannelTokenDeliveryModes.Ping => clientInfo.JwksUri,
            _ => null,
        };
}
