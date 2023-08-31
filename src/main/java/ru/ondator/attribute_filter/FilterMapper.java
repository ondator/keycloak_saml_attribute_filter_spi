package ru.ondator.attribute_filter;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.broker.provider.IdentityProviderMapper;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.saml.SAMLIdentityProviderFactory;
import org.keycloak.dom.saml.v2.assertion.AssertionType;
import org.keycloak.dom.saml.v2.assertion.AttributeStatementType;
import org.keycloak.dom.saml.v2.assertion.AttributeType;
import org.keycloak.models.*;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.function.Predicate;
import java.util.stream.Collectors;

public class FilterMapper implements IdentityProviderMapper {

    private static final List<ProviderConfigProperty> configProperties = new ArrayList();

    public static final String ATTRIBUTE_NAME = "attribute.name";

    public static final String ATTRIBUTE_VALUE = "attribute.value";

    private static final Logger logger = Logger.getLogger(FilterMapper.class);

    static {
        var nameProperty = new ProviderConfigProperty();
        nameProperty.setName(ATTRIBUTE_NAME);
        nameProperty.setLabel("Assertion Attribute Name");
        nameProperty.setHelpText("Name of attribute to search for in assertion");
        nameProperty.setType("String");
        configProperties.add(nameProperty);

        var valueProperty = new ProviderConfigProperty();
        valueProperty.setName(ATTRIBUTE_VALUE);
        valueProperty.setLabel("Expected Value");
        valueProperty.setHelpText("Value filtering by");
        valueProperty.setType("String");
        configProperties.add(valueProperty);
    }

    @Override
    public String[] getCompatibleProviders() {
        return new String[]{ SAMLIdentityProviderFactory.PROVIDER_ID };
    }

    @Override
    public String getDisplayCategory() {
        return "User Attribute Validator";
    }

    @Override
    public String getDisplayType() {
        return "User Attribute Validator";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public String getId() {
        return "keycloak-saml-attribute-filter-spi";
    }

    @Override
    public String getHelpText() {
        return "Check if user has specific group claim in assertion. Explodes if not so";
    }

    private boolean isNullOrEmpty(String str) {
        return str == null || str.isEmpty();
    }

    public void updateBrokeredUser(KeycloakSession session, RealmModel realm, UserModel user, IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        var attribute = (String)mapperModel.getConfig().get(ATTRIBUTE_NAME);
        var group = mapperModel.getConfig().get(ATTRIBUTE_VALUE);

        if(isNullOrEmpty(attribute) || isNullOrEmpty(group)) return;

        var values = findAttributeValuesInContext(attribute, context);
        if(values.stream().anyMatch(group::equalsIgnoreCase)) {
            logger.infof("value %s found", group);
            return;
        }
        throw new IdentityBrokerException(String.format("value %s not found. Only found %s", group, String.join(", ", values)));
    }

    public void preprocessFederatedIdentity(KeycloakSession session, RealmModel realm, IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        var attribute = (String)mapperModel.getConfig().get(ATTRIBUTE_NAME);
        var group = mapperModel.getConfig().get(ATTRIBUTE_VALUE);

        if(isNullOrEmpty(attribute) || isNullOrEmpty(group)) return;

        var values = findAttributeValuesInContext(attribute, context);
        if(values.stream().anyMatch(group::equalsIgnoreCase)) {
            logger.infof("value %s found", group);
            return;
        }
        throw new IdentityBrokerException(String.format("value %s not found. Only found %s", group, String.join(", ", values)));
    }

    private Predicate<AttributeStatementType.ASTChoiceType> elementWith(String attributeName) {
        return attributeType -> {
            AttributeType attribute = attributeType.getAttribute();
            return Objects.equals(attribute.getName(), attributeName)
                    || Objects.equals(attribute.getFriendlyName(), attributeName);
        };
    }

    private List<String> findAttributeValuesInContext(String attributeName, BrokeredIdentityContext context) {
        AssertionType assertion = (AssertionType)context.getContextData().get("SAML_ASSERTION");
        return assertion.getAttributeStatements()
                        .stream()
                        .flatMap((statement) -> statement.getAttributes().stream())
                        .filter(this.elementWith(attributeName))
                        .flatMap((attributeType) -> attributeType.getAttribute().getAttributeValue().stream())
                        .filter(Objects::nonNull)
                        .map(Object::toString)
                        .collect(Collectors.toList());
    }


    @Override
    public void importNewUser(KeycloakSession keycloakSession, RealmModel realmModel, UserModel userModel, IdentityProviderMapperModel identityProviderMapperModel, BrokeredIdentityContext brokeredIdentityContext) {
        logger.info("new user");
    }

    @Override
    public void updateBrokeredUserLegacy(KeycloakSession keycloakSession, RealmModel realmModel, UserModel userModel, IdentityProviderMapperModel identityProviderMapperModel, BrokeredIdentityContext brokeredIdentityContext) {

    }

    @Override
    public IdentityProviderMapper create(KeycloakSession keycloakSession) {
        return new FilterMapper();
    }

    @Override
    public void init(Config.Scope scope) {
        logger.info("mapper init");
    }

    @Override
    public void postInit(KeycloakSessionFactory keycloakSessionFactory) {

    }

    @Override
    public void close() {

    }
}
