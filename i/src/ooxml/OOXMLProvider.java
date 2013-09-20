package ooxml;

import java.security.Provider;
import java.security.Security;

public class OOXMLProvider extends Provider {

    private static final long serialVersionUID = 1L;
    public static final String NAME = "OOXMLProvider";

    private OOXMLProvider() {
        super("OOXMLProvider", 1.0D, "OOXML Security Provider");
        String temp = RelationshipTransformService.class.getName();
        put("TransformService.http://schemas.openxmlformats.org/package/2006/RelationshipTransform", RelationshipTransformService.class.getName());

        put("TransformService.http://schemas.openxmlformats.org/package/2006/RelationshipTransform MechanismType", "DOM");
    }

    public static void install() {
        Provider provider = Security.getProvider("OOXMLProvider");
        if (null == provider) {
            Security.addProvider(new OOXMLProvider());
        }
    }
}