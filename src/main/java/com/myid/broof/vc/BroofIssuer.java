package com.myid.broof.vc;

import com.google.gson.JsonObject;
import foundation.icon.did.Credential;
import foundation.icon.did.core.AlgorithmProvider;
import foundation.icon.did.core.DidKeyHolder;
import foundation.icon.did.document.EncodeType;
import foundation.icon.did.protocol.ProtocolMessage;
import foundation.icon.did.protocol.ProtocolType;
import foundation.icon.did.protocol.jsonld.Claim;
import foundation.icon.did.protocol.jsonld.DisplayLayout;
import foundation.icon.did.protocol.jsonld.JsonLdParam;

import java.util.*;

public class BroofIssuer {

    private DidKeyHolder mIssuerKeyHolder;

    public BroofIssuer() {
        mIssuerKeyHolder = makeKeyHolder();
    }

    private DidKeyHolder makeKeyHolder() {
        String did = "did:icon:02:afe691a38e40da660ea5dddabb799c5810dd913d82a73c84";
        String keyId = "key-1";
        String privateKeyString = "362fb868b46f53fe9287bd7d87d1d43be332003d9f637368a476207985a6fcda";
        DidKeyHolder keyHolder = VcpUtil.makeDidKeyHolder(did, keyId, privateKeyString);
        return keyHolder;
    }


    private Map<String, Claim> makeClaim1() {
        Map<String, Claim> claims = new LinkedHashMap<>();
        claims.put("broofTitle", new Claim("논문"));
        claims.put("broofNumber", new Claim("bfx-edf9fb2d"));
        claims.put("issueOrg", new Claim("sk"));
        claims.put("recipient", new Claim("고슬링"));
        claims.put("issueDate", new Claim("2000-01-01"));
        claims.put("broofType", new Claim("찍은증서"));
        claims.put("imageUrl", new Claim("https://www.broof.io/search/edf9fb2d?readToken=e578cefc-4302-4d1e-b7e3-244db03944ff"));
        claims.put("imageHash", new Claim("hash000000000"));
        claims.put("broofUrl", new Claim("https://www.broof.io/search/edf9fb2d?readToken=e578cefc-4302-4d1e-b7e3-244db03944ff"));

        return claims;
    }

    private Map<String, Claim> makeClaim2() {
        Map<String, Claim> claims = new LinkedHashMap<>();
        claims.put("broofTitle", new Claim("길고양이 연구실적 초록"));
        claims.put("broofNumber", new Claim("bfx-5fbe8171"));
        claims.put("issueOrg", new Claim("MIT"));
        claims.put("recipient", new Claim("이우식"));
        claims.put("issueDate", new Claim("2020-09-02"));
        claims.put("broofType", new Claim("받은증서"));
        claims.put("imageUrl", new Claim("https://www.broof.io/search/5fbe8171?readToken=78cd0f5a-61af-47b5-b7bb-b7898a88e311"));
        claims.put("imageHash", new Claim("hash000000001"));
        claims.put("broofUrl", new Claim("https://www.broof.io/search/5fbe8171?readToken=78cd0f5a-61af-47b5-b7bb-b7898a88e311"));

        return claims;
    }


    public JsonObject makeBroofCredential(String holderDid) throws Exception {
        Map<String, Claim> claims = makeClaim2();
        List<String> layoutList = Arrays.asList("broofTitle", "broofNumber", "issueOrg", "recipient", "issueDate", "broofType", "imageUrl", "imageHash", "broofUrl");
        DisplayLayout displayLayout = new DisplayLayout.StrBuilder().displayLayout(layoutList).build();

        JsonLdParam credentialParam = new JsonLdParam.Builder()
                .context(Arrays.asList("https://vc.zzeung.id/credentials/v1.json",
                        "http://vc.zzeung.id/credentials/broof/v1.json"))
                .type(Arrays.asList("CredentialParam", "BroofCertificateCredential"))
                .proofType("hash")
                .hashAlgorithm("SHA-256")
                .claim(claims)
                .displayLayout(displayLayout)
                .build();

        String nonce = EncodeType.HEX.encode(AlgorithmProvider.secureRandom().generateSeed(16));

        Credential credential = new Credential.Builder()
                .didKeyHolder(mIssuerKeyHolder)     // Issuer DID
                .nonce(nonce)
                .targetDid(holderDid)   // Holder DID
                .vcParam(credentialParam)
                .id("https://broof.io/vc/0000001")            // optional
                .version("2.0")
                .build();

        Date issued = new Date();
        // 365일짜리 유효기간을 만듬.
        long duration = credential.getDuration() * 365 * 1000L;
        Date expiration = new Date(issued.getTime() + duration);

        ProtocolMessage credentialPm = new ProtocolMessage.CredentialBuilder()
                .type(ProtocolType.RESPONSE_CREDENTIAL)
                .credential(credential)
                .issued(issued)
                .expiration(expiration)
                .build();

        ProtocolMessage.SignResult credentialSignResult = credentialPm.signEncrypt(mIssuerKeyHolder);
        JsonObject credentialObj = credentialSignResult.getResult();
        if (!credentialSignResult.isSuccess()) {
            System.out.println("Signing Credential failed.");
            throw new Exception("Signing credential failed");

        }
        return credentialObj;
    }


    /*
    public static void main(String...args) {
        BroofIssuer bissuer = new BroofIssuer();

        try {
            JsonObject phoneVC = bissuer.makeBroofCredential("did:icon:01bad0b10a1fc469ea2f0100529ab83a591c80ba78010ae208");
            System.out.println("VC:" + phoneVC.toString());
            String fullMessage = phoneVC.toString();
            System.out.println("VC bytes : " + fullMessage.getBytes().length);
            JsonElement paramObj = phoneVC.get("param");
            System.out.println("VC Param size:" + paramObj.toString().getBytes().length);
            JsonElement jwt = phoneVC.get("message");
            System.out.println("VC JWT size:" + jwt.toString().getBytes().length);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
     */
}
