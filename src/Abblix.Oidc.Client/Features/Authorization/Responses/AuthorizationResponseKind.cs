namespace Abblix.Oidc.Client.Features.Authorization.Responses;

/// <summary>
/// What kind of answer came back from the authorization endpoint.
/// </summary>
public enum AuthorizationResponseKind
{
    /// <summary>
    /// Neither a code nor an error: nothing this client can act on.
    /// </summary>
    /// <remarks>
    /// Kept as its own case rather than folded into the error one, because it means something different
    /// to whoever has to answer for it. An error is the provider saying no, in a vocabulary defined for
    /// saying no; this is a request that reached the callback address without being an authorization
    /// response at all - a stray link, a scanner, a misconfigured route.
    /// </remarks>
    Unrecognized = 0,

    /// <summary>
    /// A successful response carrying an authorization code (RFC 6749 section 4.1.2).
    /// </summary>
    AuthorizationCode,

    /// <summary>
    /// The provider refused, and said why (RFC 6749 section 4.1.2.1).
    /// </summary>
    Error,

    /// <summary>
    /// Both a code and an error arrived, which no specification defines.
    /// </summary>
    /// <remarks>
    /// Named rather than resolved. Picking either reading invents behaviour the specifications do not
    /// describe, and the safe-looking choice is the dangerous one: treating it as an error discards a
    /// real code, while treating it as a success acts on a code the provider paired with a refusal.
    /// A response nobody wrote down the meaning of is not one to guess at.
    /// </remarks>
    Contradictory,
}