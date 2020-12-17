package com.myid.broof.vc;

import com.google.gson.JsonObject;

public class Test {
    public static void main(String...args) {
        BroofClient broofClient = new BroofClient();
        try {
            JsonObject presentationJsonObject = broofClient.makeBroofPresentation();

            String presentationJweMsg = presentationJsonObject.toString();
            System.out.println("===================== Make Presentation =====================");
            System.out.println(presentationJweMsg);

            System.out.println("===================== Submit Presentation =====================");
            boolean submit = broofClient.submitPresentation(presentationJweMsg);

            System.out.println ("Submit Result : " + submit);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
