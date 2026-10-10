//! Independent MSVC/header measurements, required by Windows CI.
use super::bindings::*;
#[test]
#[ignore = "requires an independent MSVC/header reference; explicitly executed in Windows CI"]
fn generated_layout_matches_the_pinned_microsoft_c_header() {
    use std::{
        collections::BTreeMap,
        mem::{offset_of, size_of},
    };
    let path = std::env::var("WEBAUTHN_ABI_REFERENCE")
        .expect("Run tests/hello/webauthn-layout.ps1 before Windows native tests");
    let expected: BTreeMap<String, usize> = std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|line| {
            let (name, value) = line.split_once(' ').unwrap();
            (name.into(), value.parse().unwrap())
        })
        .collect();
    let mut actual = BTreeMap::new();
    macro_rules! layout { ($t:ty, [$($field:ident),*]) => {
        actual.insert(format!("{}.size", stringify!($t)), size_of::<$t>());
        $(actual.insert(format!("{}.{}", stringify!($t), stringify!($field)), offset_of!($t, $field));)*
    }; }
    layout!(
        CTAPCBOR_HYBRID_STORAGE_LINKED_DATA,
        [
            dwVersion,
            cbContactId,
            pbContactId,
            cbLinkId,
            pbLinkId,
            cbLinkSecret,
            pbLinkSecret,
            cbPublicKey,
            pbPublicKey,
            pwszAuthenticatorName,
            wEncodedTunnelServerDomain
        ]
    );
    layout!(
        WEBAUTHN_GET_CREDENTIALS_OPTIONS,
        [dwVersion, pwszRpId, bBrowserInPrivateMode]
    );
    layout!(
        WEBAUTHN_CREDENTIAL_DETAILS_LIST,
        [cCredentialDetails, ppCredentialDetails]
    );
    layout!(
        WEBAUTHN_CREDENTIAL_DETAILS,
        [
            dwVersion,
            cbCredentialID,
            pbCredentialID,
            pRpInformation,
            pUserInformation,
            bRemovable,
            bBackedUp,
            pwszAuthenticatorName,
            cbAuthenticatorLogo,
            pbAuthenticatorLogo,
            bThirdPartyPayment,
            dwTransports
        ]
    );

    layout!(GUID, [data1, data2, data3, data4]);
    layout!(WEBAUTHN_X5C, [cbData, pbData]);
    layout!(
        WEBAUTHN_COMMON_ATTESTATION,
        [
            dwVersion,
            pwszAlg,
            lAlg,
            cbSignature,
            pbSignature,
            cX5c,
            pX5c,
            pwszVer,
            cbCertInfo,
            pbCertInfo,
            cbPubArea,
            pbPubArea
        ]
    );
    layout!(
        WEBAUTHN_ASSERTION,
        [
            dwVersion,
            cbAuthenticatorData,
            pbAuthenticatorData,
            cbSignature,
            pbSignature,
            Credential,
            cbUserId,
            pbUserId,
            Extensions,
            cbCredLargeBlob,
            pbCredLargeBlob,
            dwCredLargeBlobStatus,
            pHmacSecret,
            dwUsedTransport,
            cbUnsignedExtensionOutputs,
            pbUnsignedExtensionOutputs,
            cbClientDataJSON,
            pbClientDataJSON,
            cbAuthenticationResponseJSON,
            pbAuthenticationResponseJSON
        ]
    );
    layout!(
        WEBAUTHN_AUTHENTICATOR_DETAILS,
        [
            dwVersion,
            cbAuthenticatorId,
            pbAuthenticatorId,
            pwszAuthenticatorName,
            cbAuthenticatorLogo,
            pbAuthenticatorLogo,
            bLocked
        ]
    );
    layout!(
        WEBAUTHN_AUTHENTICATOR_DETAILS_LIST,
        [cAuthenticatorDetails, ppAuthenticatorDetails]
    );
    layout!(WEBAUTHN_AUTHENTICATOR_DETAILS_OPTIONS, [dwVersion]);
    layout!(
        WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS,
        [
            dwVersion,
            dwTimeoutMilliseconds,
            CredentialList,
            Extensions,
            dwAuthenticatorAttachment,
            dwUserVerificationRequirement,
            dwFlags,
            pwszU2fAppId,
            pbU2fAppId,
            pCancellationId,
            pAllowCredentialList,
            dwCredLargeBlobOperation,
            cbCredLargeBlob,
            pbCredLargeBlob,
            pHmacSecretSaltValues,
            bBrowserInPrivateMode,
            pLinkedDevice,
            bAutoFill,
            cbJsonExt,
            pbJsonExt,
            cCredentialHints,
            ppwszCredentialHints,
            pwszRemoteWebOrigin,
            cbPublicKeyCredentialRequestOptionsJSON,
            pbPublicKeyCredentialRequestOptionsJSON,
            cbAuthenticatorId,
            pbAuthenticatorId
        ]
    );
    layout!(
        WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS,
        [
            dwVersion,
            dwTimeoutMilliseconds,
            CredentialList,
            Extensions,
            dwAuthenticatorAttachment,
            bRequireResidentKey,
            dwUserVerificationRequirement,
            dwAttestationConveyancePreference,
            dwFlags,
            pCancellationId,
            pExcludeCredentialList,
            dwEnterpriseAttestation,
            dwLargeBlobSupport,
            bPreferResidentKey,
            bBrowserInPrivateMode,
            bEnablePrf,
            pLinkedDevice,
            cbJsonExt,
            pbJsonExt,
            pPRFGlobalEval,
            cCredentialHints,
            ppwszCredentialHints,
            bThirdPartyPayment,
            pwszRemoteWebOrigin,
            cbPublicKeyCredentialCreationOptionsJSON,
            pbPublicKeyCredentialCreationOptionsJSON,
            cbAuthenticatorId,
            pbAuthenticatorId
        ]
    );
    layout!(
        WEBAUTHN_CLIENT_DATA,
        [dwVersion, cbClientDataJSON, pbClientDataJSON, pwszHashAlgId]
    );
    layout!(
        WEBAUTHN_COSE_CREDENTIAL_PARAMETER,
        [dwVersion, pwszCredentialType, lAlg]
    );
    layout!(
        WEBAUTHN_COSE_CREDENTIAL_PARAMETERS,
        [cCredentialParameters, pCredentialParameters]
    );
    layout!(
        WEBAUTHN_CREDENTIAL,
        [dwVersion, cbId, pbId, pwszCredentialType]
    );
    layout!(WEBAUTHN_CREDENTIALS, [cCredentials, pCredentials]);
    layout!(
        WEBAUTHN_CREDENTIAL_ATTESTATION,
        [
            dwVersion,
            pwszFormatType,
            cbAuthenticatorData,
            pbAuthenticatorData,
            cbAttestation,
            pbAttestation,
            dwAttestationDecodeType,
            pvAttestationDecode,
            cbAttestationObject,
            pbAttestationObject,
            cbCredentialId,
            pbCredentialId,
            Extensions,
            dwUsedTransport,
            bEpAtt,
            bLargeBlobSupported,
            bResidentKey,
            bPrfEnabled,
            cbUnsignedExtensionOutputs,
            pbUnsignedExtensionOutputs,
            pHmacSecret,
            bThirdPartyPayment,
            dwTransports,
            cbClientDataJSON,
            pbClientDataJSON,
            cbRegistrationResponseJSON,
            pbRegistrationResponseJSON
        ]
    );
    layout!(
        WEBAUTHN_CREDENTIAL_EX,
        [dwVersion, cbId, pbId, pwszCredentialType, dwTransports]
    );
    layout!(WEBAUTHN_CREDENTIAL_LIST, [cCredentials, ppCredentials]);
    layout!(
        WEBAUTHN_CRED_WITH_HMAC_SECRET_SALT,
        [cbCredID, pbCredID, pHmacSecretSalt]
    );
    layout!(
        WEBAUTHN_EXTENSION,
        [pwszExtensionIdentifier, cbExtension, pvExtension]
    );
    layout!(WEBAUTHN_EXTENSIONS, [cExtensions, pExtensions]);
    layout!(
        WEBAUTHN_HMAC_SECRET_SALT,
        [cbFirst, pbFirst, cbSecond, pbSecond]
    );
    layout!(
        WEBAUTHN_HMAC_SECRET_SALT_VALUES,
        [
            pGlobalHmacSalt,
            cCredWithHmacSecretSaltList,
            pCredWithHmacSecretSaltList
        ]
    );
    layout!(
        WEBAUTHN_RP_ENTITY_INFORMATION,
        [dwVersion, pwszId, pwszName, pwszIcon]
    );
    layout!(
        WEBAUTHN_USER_ENTITY_INFORMATION,
        [dwVersion, cbId, pbId, pwszName, pwszIcon, pwszDisplayName]
    );
    assert_eq!(actual, expected);
}
