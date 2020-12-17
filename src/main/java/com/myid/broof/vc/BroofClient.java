package com.myid.broof.vc;

import com.google.gson.JsonObject;
import foundation.icon.did.Presentation;
import foundation.icon.did.core.DidKeyHolder;
import foundation.icon.did.jwe.ECDHKey;
import foundation.icon.did.protocol.ClaimRequest;
import foundation.icon.did.protocol.ProtocolMessage;
import foundation.icon.did.protocol.ProtocolType;
import foundation.icon.did.protocol.jsonld.JsonLdVp;
import foundation.icon.did.protocol.jsonld.JsonLdVpr;
import foundation.icon.did.protocol.jsonld.VpCriteria;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

public class BroofClient {

    private DidKeyHolder mClientKeyHolder;
    private BroofIssuer mBroofIssuer;
    private SaraminVerifier mVerifier;

    public BroofClient() {
        mClientKeyHolder = makeClientDid();
        mBroofIssuer = new BroofIssuer();
        mVerifier = new SaraminVerifier();
    }



    public boolean submitPresentation(String presentationMessageJwe) {
        return mVerifier.submitPresentation(presentationMessageJwe);
    }


    /**
     * Returns Presentation json object.
     * @return
     * @throws Exception
     */
    public JsonObject makeBroofPresentation() throws Exception {
        // 1. make VC
        JsonObject credentialObject = mBroofIssuer.makeBroofCredential(mClientKeyHolder.getDid());
        ProtocolMessage credentialPm = ProtocolMessage.valueOf(credentialObject);

        // 2. Get VPR
        JsonObject vprObject = mVerifier.getRequestPresentation();

        // 2. make VP
        ProtocolMessage protocolMessageVpr = ProtocolMessage.valueOf(vprObject);
        ClaimRequest reqPresentation = protocolMessageVpr.getClaimRequestJwt();
        JsonLdVpr jsonLdVpr = reqPresentation.getVpr();

        //System.out.println("VPR Condition ID: " + jsonLdVpr.getCondition().getConditionId());

        List<VpCriteria> vpList = new ArrayList<>();
        VpCriteria criteria = new VpCriteria.Builder()
                .conditionId(jsonLdVpr.getCondition().getConditionId())     // VPR's condition ID
                .vc(credentialPm.getMsg())            // VC JWT
                .param(credentialPm.getLdParam())     // VC plain param
                .build();
        vpList.add(criteria);

        JsonLdVp jsonLdVp = new JsonLdVp.Builder()
                .context(Arrays.asList("http://vc.zzeung.id/credentials/v1.json"))
                .id("https://www.iconloop.com/vp/broof/123623")
                .type(Arrays.asList("PresentationResponse"))
                .presenter(mClientKeyHolder.getDid())
                .criteria(vpList)
                .build();

        Presentation presentation = new Presentation.Builder()
                .didKeyHolder(mClientKeyHolder)
                .nonce(reqPresentation.getNonce())
                .version("2.0")
                .vp(jsonLdVp)
                .build();

        ProtocolMessage prsntPm = new ProtocolMessage.PresentationBuilder()
                .type(ProtocolType.RESPONSE_PROTECTED_PRESENTATION)
                .presentation(presentation)
                .requestPublicKey(reqPresentation.getPublicKey())     // receiveKey from verifier
                .issued(new Date())
                .expiration(new Date(System.currentTimeMillis() + (60*60*24L * 1000L)))
                .build();

        ECDHKey ecdhKey = ECDHKey.generateKey(ECDHKey.CURVE_P256K);
        ProtocolMessage.SignResult prsntSignResult = prsntPm.signEncrypt(mClientKeyHolder, ecdhKey);
        JsonObject presentationObject = prsntSignResult.getResult();

        return presentationObject;
    }

    /**
     * Client 용 DID
     */
    private DidKeyHolder makeClientDid() {
        String did = "did:icon:02:24b2c4aa72fbe06abe5c83b804aeab4b597db2570812af45";
        String keyId = "key-1";
        String privateKeyString = "128e504f15160a61fd9abef2e4dadbadb67e35758b980bf79a61f8045bed23fd";
        DidKeyHolder keyHolder = VcpUtil.makeDidKeyHolder(did, keyId, privateKeyString);
        return keyHolder;
    }

}
