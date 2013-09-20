package ooxml;

import java.util.LinkedList;
import java.util.List;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;

public class RelationshipTransformParameterSpec
        implements TransformParameterSpec {

    private final List<String> sourceIds;

    public RelationshipTransformParameterSpec() {
        this.sourceIds = new LinkedList();
    }

    public void addRelationshipReference(String sourceId) {
        this.sourceIds.add(sourceId);
    }

    List<String> getSourceIds() {
        return this.sourceIds;
    }
}