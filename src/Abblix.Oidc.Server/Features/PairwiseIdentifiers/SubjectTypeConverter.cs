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
    /// When no sector_identifier_uri was provided, the sector is the host component of the registered redirect_uri.
    /// A client_id fallback would produce identifiers that silently change when the same application is
    /// re-registered under a new client id, defeating the stability pairwise identifiers give a sector; it affects
    /// only statically configured clients, since DCR-registered pairwise clients always get SectorIdentifier
    /// computed at registration time, and remains the last resort for clients with no redirect URIs at all (e.g.
    /// pure client_credentials configurations). The host is meaningful only for http(s) redirect URIs - the web
    /// clients Core Section 8.1 had in mind. Native custom-scheme redirects (RFC 8252 Section 7.1) must not reach
    /// the host branch: the single-slash form (com.example.app:/oauth2redirect) parses with an EMPTY host, and the
    /// authority form (app-one://callback) puts an arbitrary path-like segment into Host - either way unrelated
    /// clients would silently share one sector and seal identical pseudonyms for the same user, defeating the
    /// isolation this subject type exists to provide. Such clients keep per-client isolation via the client_id
    /// fallback.
    /// </remarks>
    private static byte[] Sector(ClientInfo clientInfo)
    {
        var sector =
            clientInfo.SectorIdentifier ??
            clientInfo.RedirectUris.FirstOrDefault(redirectUri =>
                redirectUri.Scheme == Uri.UriSchemeHttp ||
                redirectUri.Scheme == Uri.UriSchemeHttps)?.Host ??
            clientInfo.ClientId;

        return Encoding.UTF8.GetBytes(sector);
    }
}
