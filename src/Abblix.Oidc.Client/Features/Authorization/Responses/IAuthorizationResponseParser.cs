namespace Abblix.Oidc.Client.Features.Authorization.Responses;

/// <summary>
/// Turns the parameters that arrived at the callback address into an
/// <see cref="AuthorizationResponse"/>.
/// </summary>
public interface IAuthorizationResponseParser
{
    /// <summary>
    /// Reads the response parameters, or throws <see cref="AuthorizationResponseException"/> when they
    /// cannot be read as a response at all.
    /// </summary>
    /// <param name="parameters">
    /// The parameters as delivered, each name mapped to every value that arrived under it.
    /// </param>
    /// <remarks>
    /// The shape is a name-to-values map rather than a name-to-value one so that a repeated parameter
    /// reaches this method instead of being silently resolved by whoever collected them. Which value a
    /// collection API keeps for a duplicate - first, last, or joined - is an implementation detail of
    /// that API, and letting it decide would mean a token endpoint sees one <c>code</c> while the
    /// checks ran against another.
    /// It is also what keeps this package free of ASP.NET Core: an adapter can build the map from a
    /// query string, from a posted form, or from parameters a script lifted out of a fragment, and this
    /// method neither knows nor cares which.
    /// </remarks>
    AuthorizationResponse Parse(IReadOnlyDictionary<string, IReadOnlyList<string>> parameters);
}