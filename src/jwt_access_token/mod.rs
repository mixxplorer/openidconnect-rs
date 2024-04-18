use crate::helpers::{
    deserialize_string_or_vec, serde_utc_seconds, serde_utc_seconds_opt, FilteredFlatten,
};
use crate::jwt::JsonWebTokenAccess;
use crate::jwt::{JsonWebTokenError, JsonWebTokenJsonPayloadSerde};
use crate::types::jwk::JwsSigningAlgorithm;
use crate::types::JwtId;
use crate::verification::JwtAccessTokenVerifier;
use crate::{
    AdditionalClaims, AddressClaim, Audience, AudiencesClaim, AuthenticationContextClass,
    AuthenticationMethodReference, ClaimsVerificationError, ClientId, EndUserBirthday,
    EndUserEmail, EndUserFamilyName, EndUserGivenName, EndUserMiddleName, EndUserName,
    EndUserNickname, EndUserPhoneNumber, EndUserPictureUrl, EndUserProfileUrl, EndUserTimezone,
    EndUserUsername, EndUserWebsiteUrl, ExtraTokenFields, GenderClaim, IssuerClaim, IssuerUrl,
    JsonWebKey, JsonWebToken, JsonWebTokenAlgorithm, JweContentEncryptionAlgorithm, LanguageTag,
    LocalizedClaim, PrivateSigningKey, SignatureVerificationError, StandardClaims,
    SubjectIdentifier,
};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use std::fmt::Debug;
use std::str::FromStr;

// #[cfg(test)]
// mod tests;

// This wrapper layer exists instead of directly verifying the JWT and returning the claims so that
// we can pass it around and easily access a serialized JWT representation of it (e.g., for passing
// to the authorization endpoint as an id_token_hint).
/// OpenID Connect access token according to RFC9068.
#[cfg_attr(
    any(test, feature = "timing-resistant-secret-traits"),
    derive(PartialEq)
)]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct JwtAccessToken<
    AC: AdditionalClaims,
    GC: GenderClaim,
    JE: JweContentEncryptionAlgorithm<KeyType = JS::KeyType>,
    JS: JwsSigningAlgorithm,
>(
    #[serde(bound = "AC: AdditionalClaims")]
    JsonWebToken<JE, JS, JwtAccessTokenClaims<AC, GC>, JsonWebTokenJsonPayloadSerde>,
);

impl<AC, GC, JE, JS> FromStr for JwtAccessToken<AC, GC, JE, JS>
where
    AC: AdditionalClaims,
    GC: GenderClaim,
    JE: JweContentEncryptionAlgorithm<KeyType = JS::KeyType>,
    JS: JwsSigningAlgorithm,
{
    type Err = serde_json::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_json::from_value(Value::String(s.to_string()))
    }
}

impl<AC, GC, JE, JS> JwtAccessToken<AC, GC, JE, JS>
where
    AC: AdditionalClaims,
    GC: GenderClaim,
    JE: JweContentEncryptionAlgorithm<KeyType = JS::KeyType>,
    JS: JwsSigningAlgorithm,
{
    /// Initializes an access token with the specified claims, signed using the given signing key and
    /// algorithm.
    pub fn new<S>(
        claims: JwtAccessTokenClaims<AC, GC>,
        signing_key: &S,
        alg: JS,
    ) -> Result<Self, JsonWebTokenError>
    where
        S: PrivateSigningKey,
        <S as PrivateSigningKey>::VerificationKey: JsonWebKey<SigningAlgorithm = JS>,
    {
        JsonWebToken::new(JwtAccessTokenClaims { ..claims }, signing_key, &alg).map(Self)
    }

    /// Verifies and returns a reference to the ID token claims.
    pub fn claims<'a, K>(
        &'a self,
        verifier: &JwtAccessTokenVerifier<K>,
    ) -> Result<&'a JwtAccessTokenClaims<AC, GC>, ClaimsVerificationError>
    where
        K: JsonWebKey<SigningAlgorithm = JS>,
    {
        verifier.verified_claims(&self.0)
    }

    /// Verifies and returns the ID token claims.
    pub fn into_claims<K>(
        self,
        verifier: &JwtAccessTokenVerifier<K>,
    ) -> Result<JwtAccessTokenClaims<AC, GC>, ClaimsVerificationError>
    where
        K: JsonWebKey<SigningAlgorithm = JS>,
    {
        verifier.verified_claims_owned(self.0)
    }

    /// Returns the [`JwsSigningAlgorithm`] used to sign this ID token.
    ///
    /// This function returns an error if the token is unsigned or utilizes JSON Web Encryption
    /// (JWE).
    pub fn signing_alg(&self) -> Result<&JS, SignatureVerificationError> {
        match self.0.unverified_header().alg {
            JsonWebTokenAlgorithm::Signature(ref signing_alg) => Ok(signing_alg),
            JsonWebTokenAlgorithm::Encryption(ref other) => {
                Err(SignatureVerificationError::UnsupportedAlg(
                    serde_plain::to_string(other).unwrap_or_else(|err| {
                        panic!(
                            "encryption alg {:?} failed to serialize to a string: {}",
                            other, err
                        )
                    }),
                ))
            }
            JsonWebTokenAlgorithm::None => Err(SignatureVerificationError::NoSignature),
        }
    }

    /// Returns the [`JsonWebKey`] usable for verifying this ID token's JSON Web Signature.
    ///
    /// This function returns an error if the token has no signature or a corresponding key cannot
    /// be found.
    pub fn signing_key<'s, K>(
        &self,
        verifier: &'s JwtAccessTokenVerifier<'s, K>,
    ) -> Result<&'s K, SignatureVerificationError>
    where
        K: JsonWebKey<SigningAlgorithm = JS>,
    {
        verifier
            .jwt_verifier
            .signing_key(self.0.unverified_header().kid.as_ref(), self.signing_alg()?)
    }
}

impl<AC, GC, JE, JS> ToString for JwtAccessToken<AC, GC, JE, JS>
where
    AC: AdditionalClaims,
    GC: GenderClaim,
    JE: JweContentEncryptionAlgorithm<KeyType = JS::KeyType>,
    JS: JwsSigningAlgorithm,
{
    fn to_string(&self) -> String {
        serde_json::to_value(self)
            // This should never arise, since we're just asking serde_json to serialize the
            // signing input concatenated with the signature, both of which are precomputed.
            .expect("Access token serialization failed")
            .as_str()
            // This should also never arise, since our JwtAccessToken serializer always calls serialize_str
            .expect("Access token serializer did not produce a str")
            .to_owned()
    }
}

/// OpenID Connect access token claims according th RFC 9068
///
/// Fields in this struct are in the same order as they appear in the RFC starting from section 2.2.
#[cfg_attr(
    any(test, feature = "timing-resistant-secret-traits"),
    derive(PartialEq)
)]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct JwtAccessTokenClaims<AC, GC>
where
    AC: AdditionalClaims,
    GC: GenderClaim,
{
    #[serde(rename = "iss")]
    issuer: IssuerUrl,

    #[serde(rename = "exp", with = "serde_utc_seconds")]
    expiration: DateTime<Utc>,

    // We always serialize as an array, which is valid according to the spec. This sets the
    // 'default' attribute to be compatible with non-spec compliant OIDC providers that omit this
    // field.
    #[serde(
        default,
        rename = "aud",
        deserialize_with = "deserialize_string_or_vec"
    )]
    audiences: Vec<Audience>,

    // sub is covered by standard_claims below
    client_id: ClientId,

    #[serde(rename = "iat", with = "serde_utc_seconds")]
    issue_time: DateTime<Utc>,

    #[serde(rename = "jti")]
    jwt_id: JwtId,

    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "serde_utc_seconds_opt"
    )]
    auth_time: Option<DateTime<Utc>>,

    #[serde(rename = "acr", skip_serializing_if = "Option::is_none")]
    auth_context_ref: Option<AuthenticationContextClass>,

    #[serde(rename = "amr", skip_serializing_if = "Option::is_none")]
    auth_method_refs: Option<Vec<AuthenticationMethodReference>>,

    #[serde(bound = "GC: GenderClaim")]
    #[serde(flatten)]
    standard_claims: StandardClaims<GC>,

    #[serde(bound = "AC: AdditionalClaims")]
    #[serde(flatten)]
    additional_claims: FilteredFlatten<StandardClaims<GC>, AC>,
}
impl<AC, GC> JwtAccessTokenClaims<AC, GC>
where
    AC: AdditionalClaims,
    GC: GenderClaim,
{
    /// Initializes new ID token claims.
    pub fn new(
        issuer: IssuerUrl,
        expiration: DateTime<Utc>,
        audiences: Vec<Audience>,
        client_id: ClientId,
        issue_time: DateTime<Utc>,
        jwt_id: JwtId,
        standard_claims: StandardClaims<GC>,
        additional_claims: AC,
    ) -> Self {
        Self {
            issuer,
            expiration,
            audiences,
            client_id,
            issue_time,
            jwt_id,
            auth_time: None,
            auth_context_ref: None,
            auth_method_refs: None,
            standard_claims,
            additional_claims: additional_claims.into(),
        }
    }

    field_getters_setters![
        pub self [self] ["claim"] {
            set_issuer -> issuer[IssuerUrl] ["iss"],
            set_expiration -> expiration[DateTime<Utc>] ["exp"],
            set_audiences -> audiences[Vec<Audience>] ["aud"],
            set_client_id -> client_id[ClientId] ["client_id"],
            set_issue_time -> issue_time[DateTime<Utc>] ["iat"],
            set_jwt_id -> jwt_id[JwtId] ["jti"],
            set_auth_time -> auth_time[Option<DateTime<Utc>>],
            set_auth_context_ref -> auth_context_ref[Option<AuthenticationContextClass>] ["acr"],
            set_auth_method_refs -> auth_method_refs[Option<Vec<AuthenticationMethodReference>>] ["amr"],
        }
    ];

    /// Returns the `sub` claim.
    pub fn subject(&self) -> &SubjectIdentifier {
        &self.standard_claims.sub
    }
    /// Sets the `sub` claim.
    pub fn set_subject(mut self, subject: SubjectIdentifier) -> Self {
        self.standard_claims.sub = subject;
        self
    }

    field_getters_setters![
        pub self [self.standard_claims] ["claim"] {
            set_name -> name[Option<LocalizedClaim<EndUserName>>],
            set_given_name -> given_name[Option<LocalizedClaim<EndUserGivenName>>],
            set_family_name ->
                family_name[Option<LocalizedClaim<EndUserFamilyName>>],
            set_middle_name ->
                middle_name[Option<LocalizedClaim<EndUserMiddleName>>],
            set_nickname -> nickname[Option<LocalizedClaim<EndUserNickname>>],
            set_preferred_username -> preferred_username[Option<EndUserUsername>],
            set_profile -> profile[Option<LocalizedClaim<EndUserProfileUrl>>],
            set_picture -> picture[Option<LocalizedClaim<EndUserPictureUrl>>],
            set_website -> website[Option<LocalizedClaim<EndUserWebsiteUrl>>],
            set_email -> email[Option<EndUserEmail>],
            set_email_verified -> email_verified[Option<bool>],
            set_gender -> gender[Option<GC>],
            set_birthday -> birthday[Option<EndUserBirthday>],
            set_birthdate -> birthdate[Option<EndUserBirthday>],
            set_zoneinfo -> zoneinfo[Option<EndUserTimezone>],
            set_locale -> locale[Option<LanguageTag>],
            set_phone_number -> phone_number[Option<EndUserPhoneNumber>],
            set_phone_number_verified -> phone_number_verified[Option<bool>],
            set_address -> address[Option<AddressClaim>],
            set_updated_at -> updated_at[Option<DateTime<Utc>>],
        }
    ];

    /// Returns additional ID token claims.
    pub fn additional_claims(&self) -> &AC {
        self.additional_claims.as_ref()
    }
    /// Returns mutable additional ID token claims.
    pub fn additional_claims_mut(&mut self) -> &mut AC {
        self.additional_claims.as_mut()
    }
}
impl<AC, GC> AudiencesClaim for JwtAccessTokenClaims<AC, GC>
where
    AC: AdditionalClaims,
    GC: GenderClaim,
{
    fn audiences(&self) -> Option<&Vec<Audience>> {
        Some(JwtAccessTokenClaims::audiences(self))
    }
}
impl<'a, AC, GC> AudiencesClaim for &'a JwtAccessTokenClaims<AC, GC>
where
    AC: AdditionalClaims,
    GC: GenderClaim,
{
    fn audiences(&self) -> Option<&Vec<Audience>> {
        Some(JwtAccessTokenClaims::audiences(self))
    }
}
impl<AC, GC> IssuerClaim for JwtAccessTokenClaims<AC, GC>
where
    AC: AdditionalClaims,
    GC: GenderClaim,
{
    fn issuer(&self) -> Option<&IssuerUrl> {
        Some(JwtAccessTokenClaims::issuer(self))
    }
}
impl<'a, AC, GC> IssuerClaim for &'a JwtAccessTokenClaims<AC, GC>
where
    AC: AdditionalClaims,
    GC: GenderClaim,
{
    fn issuer(&self) -> Option<&IssuerUrl> {
        Some(JwtAccessTokenClaims::issuer(self))
    }
}

/// Extends the base OAuth2 token response with an access token.
#[cfg_attr(
    any(test, feature = "timing-resistant-secret-traits"),
    derive(PartialEq)
)]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct JwtAccessTokenFields<AC, EF, GC, JE, JS>
where
    AC: AdditionalClaims,
    EF: ExtraTokenFields,
    GC: GenderClaim,
    JE: JweContentEncryptionAlgorithm<KeyType = JS::KeyType>,
    JS: JwsSigningAlgorithm,
{
    #[serde(bound = "AC: AdditionalClaims")]
    access_token: Option<JwtAccessToken<AC, GC, JE, JS>>,
    #[serde(bound = "EF: ExtraTokenFields", flatten)]
    extra_fields: EF,
}
impl<AC, EF, GC, JE, JS> JwtAccessTokenFields<AC, EF, GC, JE, JS>
where
    AC: AdditionalClaims,
    EF: ExtraTokenFields,
    GC: GenderClaim,
    JE: JweContentEncryptionAlgorithm<KeyType = JS::KeyType>,
    JS: JwsSigningAlgorithm,
{
    /// Initializes new access token fields containing the specified [`JwtAccessToken`] and extra fields.
    pub fn new(access_token: Option<JwtAccessToken<AC, GC, JE, JS>>, extra_fields: EF) -> Self {
        Self {
            access_token,
            extra_fields,
        }
    }

    /// Returns the [`JwtAccessToken`] contained in the OAuth2 token response.
    pub fn access_token(&self) -> Option<&JwtAccessToken<AC, GC, JE, JS>> {
        self.access_token.as_ref()
    }
    /// Returns the extra fields contained in the OAuth2 token response.
    pub fn extra_fields(&self) -> &EF {
        &self.extra_fields
    }
}
impl<AC, EF, GC, JE, JS> ExtraTokenFields for JwtAccessTokenFields<AC, EF, GC, JE, JS>
where
    AC: AdditionalClaims,
    EF: ExtraTokenFields,
    GC: GenderClaim,
    JE: JweContentEncryptionAlgorithm<KeyType = JS::KeyType>,
    JS: JwsSigningAlgorithm,
{
}
