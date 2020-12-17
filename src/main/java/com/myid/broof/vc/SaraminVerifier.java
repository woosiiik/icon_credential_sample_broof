package com.myid.broof.vc;

import com.google.gson.JsonObject;
import foundation.icon.did.Credential;
import foundation.icon.did.Presentation;
import foundation.icon.did.core.AlgorithmProvider;
import foundation.icon.did.core.DidKeyHolder;
import foundation.icon.did.document.Document;
import foundation.icon.did.document.EncodeType;
import foundation.icon.did.document.PublicKeyProperty;
import foundation.icon.did.exceptions.AlgorithmException;
import foundation.icon.did.jwe.ECDHKey;
import foundation.icon.did.jwe.EphemeralPublicKey;
import foundation.icon.did.jwt.Jwt;
import foundation.icon.did.protocol.ClaimRequest;
import foundation.icon.did.protocol.ProtocolMessage;
import foundation.icon.did.protocol.ProtocolType;
import foundation.icon.did.protocol.jsonld.Claim;
import foundation.icon.did.protocol.jsonld.JsonLdVpr;
import foundation.icon.did.protocol.jsonld.VpCriteria;
import foundation.icon.did.protocol.jsonld.VprCondition;
import foundation.icon.myid.VerifierService;

import java.security.PublicKey;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;

public class SaraminVerifier {


    private String mNonce;
    // ECDHKey of Issuer
    private ECDHKey mServerECDHKey;
    private DidKeyHolder mVerifierKeyHolder;
    private VerifierService mVerifierService;

    // IL망에서는 WAS에 다녀오지를 못한다. (https인증서 이슈)
    // iv.zzeung.id 혹은 iv-test.zzeung.id는 Guest망에서 접근이 안 된다.
    // 때문에 Guest망에서 holder.zzeung.id를 사용해서 테스트 해야 한다.
    private static final String IV_WAS_URL = "https://holder.zzeung.id/";

    public SaraminVerifier() {
        mVerifierKeyHolder = makeKeyHolder();
        mVerifierService = VerifierService.create(IV_WAS_URL);
        try {
            mNonce = EncodeType.HEX.encode(AlgorithmProvider.secureRandom().generateSeed(16));
            mServerECDHKey = ECDHKey.generateKey(ECDHKey.CURVE_P256K);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private DidKeyHolder makeKeyHolder() {
        String did = "did:icon:02:7cf1ba22ca867efe4693ba3bdc2c610275e47b52203e0dcd";
        String keyId = "dyms_dev";
        String privateKeyString = "c78da213e547f7ab39132e8ba9cb1c89456ddb0b2998bf00523211a8bfa8a45b";
        DidKeyHolder keyHolder = VcpUtil.makeDidKeyHolder(did, keyId, privateKeyString);
        return keyHolder;
    }

    public JsonObject getRequestPresentation() {
        EphemeralPublicKey verifierPublicKey = new EphemeralPublicKey.Builder()
                .kid(mNonce)
                .epk(mServerECDHKey)
                .build();

        // 제출 요청할 항목
        List<String> requireProperty = Arrays.asList("broofTitle", "broofNumber", "issueOrg", "recipient", "issueDate", "broofType", "broofContent", "imageUrl", "imageHash", "broofUrl");
        // 조건 작성
        VprCondition condition = new VprCondition.SimpleBuilder()   // SimpleCondition
                .conditionId("uuid-requisite-0000-1111-2222")       // 아무값이나 입력
                .context(Arrays.asList(
                        "http://vc.zzeung.id/credentials/broof/v1.json"))
                .credentialType("BroofCertificateCredential")
                .property(requireProperty)
                .build();

        JsonLdVpr vpr = null;
        try {
            vpr = new JsonLdVpr.Builder()
                    .context(Arrays.asList("https://vc.zzeung.id/credentials/v1.json"))
                    .id("https://www.saramin.com/vpr/broof")
                    .purpose("이력서 작성")
                    .verifier(mVerifierKeyHolder.getDid())
                    .condition(condition)
                    .build();
        } catch (Exception e) {
            e.printStackTrace();
        }

        ClaimRequest reqPresentation = new ClaimRequest.PresentationBuilder()
                .didKeyHolder(mVerifierKeyHolder)
                .requestDate(new Date())
                .nonce(mNonce)
                .publicKey(verifierPublicKey)
                .version("2.0")
                .vpr(vpr)
                .build();

        ProtocolMessage reqPresentationPm = null;
        try {
            reqPresentationPm = new ProtocolMessage.RequestBuilder()
                    .type(ProtocolType.REQUEST_PRESENTATION)
                    .claimRequest(reqPresentation)
                    .build();
        } catch (Exception e) {
            e.printStackTrace();
        }
        ProtocolMessage.SignResult reqPresentationSignResult =
                reqPresentationPm.signEncrypt(mVerifierKeyHolder);

        if (!reqPresentationSignResult.isSuccess()) {
            System.out.println("Signing RequestPresentation failed.");
            // mDidKeyHolder의 key store파일이 문제가 없는지 확인 필요.
            return null;
        }

        JsonObject reqPresentationObject = reqPresentationSignResult.getResult();
        //System.out.println("VPR : " + reqPresentationObject.toString());

        return reqPresentationObject;
    }


    public boolean submitPresentation(String presentationMessageJwe) {
        ProtocolMessage presentationPm = ProtocolMessage.valueOf(presentationMessageJwe);
        String keyId = presentationPm.getJweKid();
        if (presentationPm.isProtected()) {
            presentationPm.decryptJwe(mServerECDHKey);
        }
        //System.out.println("decryptJWT :" + presentationPm.getJwtToken());
        Presentation presentation = presentationPm.getPresentationJwt();

        String holderDid = presentation.getDid();
        String holderKeyId = presentation.getKeyId();
        Document holderDoc = null;

        try {
            // Blockchain에서 Holder DID Document 조회
            holderDoc = mVerifierService.getDid(holderDid);
        } catch (Exception e) {
            e.printStackTrace();
        }

        if (holderDoc == null) {
            System.out.println("Presentation holder document is null:DID > " + holderDid);
            // blockchain에서 Holder의 DID 확인 실패
            return false;
        }

        PublicKeyProperty publicKeyProperty =
                holderDoc.getPublicKeyProperty(holderKeyId);
        if (publicKeyProperty == null || publicKeyProperty.isRevoked()) {
            System.out.println("Presentation holderDid revoked");
            // Holder의 public key가 없거나 폐기되어서 서명 확인 불가.
            return false;
        }
        PublicKey publicKey = publicKeyProperty.getPublicKey();
        presentation.getJwt();

        try {
            Jwt.VerifyResult verifyResult = presentation.getJwt().verify(publicKey);
            if (!verifyResult.isSuccess()) {
                System.out.println(verifyResult.getFailMessage());  // verify fail
                // Holder의 서명 확인 실패.
                // 즉 이 presentation은 위조 되었거나 holder의 서명에 문제가 있음.
                //return false;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        // presentation내의 VC 검증 시작
        for (VpCriteria criteria : presentation.getVp().getFulfilledCriteria()) {
            Credential credential = Credential.valueOf(criteria.getVc());
            // presentation을 제출한 주체가 VC의 발급받은 자와 동일한지만 확인
            if (!credential.getTargetDid().equals(holderDid)) {
                System.out.println("VC's targetDid does not match holderDid.");
                return false;
            }

            Document issuerDocument = null;
            String issuerDid = credential.getIssuerDid().getDid();
            try {
                issuerDocument = mVerifierService.getDid(issuerDid);

            } catch (Exception e) {
                e.printStackTrace();
                return false;
            }

            if (issuerDocument == null) {
                // blockchain에서 Holder의 DID 확인 실패
                return false;
            }
            PublicKeyProperty issuerKeyProperty =
                    issuerDocument.getPublicKeyProperty(credential.getKeyId());
            if (issuerKeyProperty.isRevoked()) {
                // Issuer의 key가 폐기 되었음.
                return false;
            }

            try {
                PublicKey issuerPublicKey = issuerKeyProperty.getPublicKey();
                Jwt.VerifyResult credVerifyResult = credential.getJwt().verify(issuerPublicKey);
                if (!credVerifyResult.isSuccess()) {
                    // Issuer key로 VC 서명 검증 실패.
                    return false;
                }
                if (!holderDid.equals(credential.getTargetDid())) {
                    // VC에 있는 Holder DID와 presentation을 제출한 Holder의 DID가 다름.
                    return false;
                }
            } catch (AlgorithmException e) {
                e.printStackTrace();
                return false;
            }

            // 크레덴셜의 신원정보 무결성 체크: VC 내의 claim hash 값과 전달받은 실제 값을 hash하여 비교
            if (!criteria.isVerifyParam()) {
                System.out.println("Claim parameter hash is invalid.");
                // credential 신원정보 무결성 체크 실패!
                // credential 내의 claim hash 값과 param으로 전달받은 실제 값의 hash를 비교 실패.
                // 즉 credential의 신원정보가 위변조 되었을 수 있음.
                return false;
            }

            // 휴대폰 본인인증의 claim 정보.
            Map<String, Claim> claimMap = criteria.getVcParam().getClaim();

            // 요청한 항목이 presentation에 포함 되어 있는지 확인
            if (!claimMap.containsKey("broofTitle")) {
                System.out.println("Claim parameter does not have `name`");
            }
            if (!claimMap.containsKey("broofNumber")) {
                System.out.println("Claim parameter does not have `birthDate`");
            }

            System.out.println(" ------------------------- Claim Information ---------------------------");
            for(String name : claimMap.keySet()) {
                Claim obj = claimMap.get(name);
                Object value = obj.getClaimValue();
                String displayValue = obj.getDisplayValue();

                System.out.println("Claim Name=[" + name + "], value=[" + value + "], displayValue=[" + displayValue + "]");
            }

            System.out.println(" ----------------------------------------------------------------------");
        }
        return true;
    }

}
