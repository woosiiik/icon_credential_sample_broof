package com.myid.broof.vc;

import foundation.icon.did.core.Algorithm;
import foundation.icon.did.core.AlgorithmProvider;
import foundation.icon.did.core.DidKeyHolder;
import foundation.icon.did.document.EncodeType;

import java.security.PrivateKey;

public class VcpUtil {

    public static DidKeyHolder makeDidKeyHolder(String did, String keyId, String privateKey) {
        try {
            Algorithm algorithm = AlgorithmProvider.create(AlgorithmProvider.Type.ES256K);
            PrivateKey holderPrivKey = algorithm.byteToPrivateKey(EncodeType.HEX.decode(privateKey));

            DidKeyHolder didKeyHolder = new DidKeyHolder.Builder()
                    .did(did)
                    .keyId(keyId)
                    .type(AlgorithmProvider.Type.ES256K)
                    .privateKey(holderPrivKey)
                    .build();

            return didKeyHolder;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}