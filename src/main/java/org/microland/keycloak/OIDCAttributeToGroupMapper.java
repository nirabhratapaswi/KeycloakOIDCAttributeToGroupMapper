package org.microland.keycloak;

import org.keycloak.broker.oidc.KeycloakOIDCIdentityProviderFactory;
import org.keycloak.broker.oidc.OIDCIdentityProviderFactory;
import org.keycloak.broker.oidc.mappers.AbstractClaimMapper;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.IdentityProviderSyncMode;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.saml.common.util.StringUtil;
import org.keycloak.models.GroupModel;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
//import java.util.function.Consumer;
import java.util.stream.Collectors;

/**
 * @author <a href="mailto:*@gmail.com">Nirabhra Tapaswi</a>
 * @version $Revision: 1 $
 */
public class OIDCAttributeToGroupMapper extends AbstractClaimMapper {

    public static final String[] COMPATIBLE_PROVIDERS = {KeycloakOIDCIdentityProviderFactory.PROVIDER_ID, OIDCIdentityProviderFactory.PROVIDER_ID};

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

    public static final String SOURCE_ATTRIBUTE_VALUE = "source.attribute.value";
    public static final String TARGET_GROUP_VALUE = "target.group.value";
    private static final Set<IdentityProviderSyncMode> IDENTITY_PROVIDER_SYNC_MODES = new HashSet<>(Arrays.asList(IdentityProviderSyncMode.values()));

    static {
        ProviderConfigProperty property1;
        ProviderConfigProperty property2;
        ProviderConfigProperty property3;
        property1 = new ProviderConfigProperty();
        property1.setName(CLAIM);
        property1.setLabel("Claim");
        property1.setHelpText("Name of claim to search for in token. You can reference nested claims using a '.', i.e. 'address.locality'. To use dot (.) literally, escape it with backslash (\\.)");
        property1.setType(ProviderConfigProperty.STRING_TYPE);
        configProperties.add(property1);
        property2 = new ProviderConfigProperty();
        property2.setName(SOURCE_ATTRIBUTE_VALUE);
        property2.setLabel("Source Attribute Value");
        property2.setHelpText("Source attribute value to match against(check the presence of).");
        property2.setType(ProviderConfigProperty.STRING_TYPE);
        configProperties.add(property2);
        property3 = new ProviderConfigProperty();
        property3.setName(TARGET_GROUP_VALUE);
        property3.setLabel("Target Group Name");
        property3.setHelpText("Target Group Name. This group should be already existing in Keycloak realm groups.");
        property3.setType(ProviderConfigProperty.STRING_TYPE);
        configProperties.add(property3);
    }

    public static final String PROVIDER_ID = "oidc-user-attribute-idp-mapper";

    @Override
    public boolean supportsSyncMode(IdentityProviderSyncMode syncMode) {
        return IDENTITY_PROVIDER_SYNC_MODES.contains(syncMode);
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String[] getCompatibleProviders() {
        return COMPATIBLE_PROVIDERS;
    }

    @Override
    public String getDisplayCategory() {
//        return "Attribute Importer";
        return "Attribute Mapper";
    }

    @Override
    public String getDisplayType() {
        return "Attribute to Group Mapper";
    }

    @Override
    public void preprocessFederatedIdentity(KeycloakSession session, RealmModel realm, IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        /*String attribute = mapperModel.getConfig().get(TOKEN_ATTRIBUTE);
        if (StringUtil.isNullOrEmpty(attribute)) {
            return;
        }
        Object value = getClaimValue(mapperModel, context);
        List<String> values = toList(value);

        if (EMAIL.equalsIgnoreCase(attribute)) {
            setIfNotEmpty(context::setEmail, values);
        } else if (FIRST_NAME.equalsIgnoreCase(attribute)) {
            setIfNotEmpty(context::setFirstName, values);
        } else if (LAST_NAME.equalsIgnoreCase(attribute)) {
            setIfNotEmpty(context::setLastName, values);
        } else {
            List<String> valuesToString = values.stream()
                    .filter(Objects::nonNull)
                    .map(Object::toString)
                    .collect(Collectors.toList());
        }*/
    }

//    private void setIfNotEmpty(Consumer<String> consumer, List<String> values) {
//        if (values != null && !values.isEmpty()) {
//            consumer.accept(values.get(0));
//        }
//    }

    private List<String> toList(Object value) {
        List<Object> values = (value instanceof List)
                ? (List) value
                : Collections.singletonList(value);
        return values.stream()
                .filter(Objects::nonNull)
                .map(Object::toString)
                .collect(Collectors.toList());
    }

    @Override
    public void updateBrokeredUser(KeycloakSession session, RealmModel realm, UserModel user, IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        String sourceAttributeValue = mapperModel.getConfig().get(SOURCE_ATTRIBUTE_VALUE);
        String targetGroupValue = mapperModel.getConfig().get(TARGET_GROUP_VALUE);
        if(StringUtil.isNullOrEmpty(sourceAttributeValue) || StringUtil.isNullOrEmpty(targetGroupValue)) {
            return;
        }
        Object value = getClaimValue(mapperModel, context);
        List<String> values = toList(value);

        GroupModel group = KeycloakModelUtils.findGroupByPath(realm, targetGroupValue);

        if (values.contains(sourceAttributeValue)) {
            if (group != null) {
                user.joinGroup(group);
            }
        } else {
            if (group != null) {
                user.leaveGroup(group);
            }
        }
    }

    @Override
    public String getHelpText() {
        return "Import declared claim if it exists in ID, access token or the claim set returned by the user profile endpoint into the specified user property or attribute.";
    }

}