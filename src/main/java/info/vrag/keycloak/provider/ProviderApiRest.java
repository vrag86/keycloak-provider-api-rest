package info.vrag.keycloak.provider;

import org.jboss.logging.Logger;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;

import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.IdentityProviderFactory;
import org.keycloak.broker.provider.IdentityProviderMapper;
import org.keycloak.broker.provider.IdentityProviderMapperSyncModeDelegate;
import org.keycloak.common.util.ObjectUtil;

import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.IdentityProviderSyncMode;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.validation.Validation;


import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Response;

import java.util.Optional;
import java.util.Set;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import static org.keycloak.services.resources.IdentityBrokerService.getIdentityProviderFactory;
import static org.keycloak.utils.MediaType.APPLICATION_JSON_TYPE;

public class ProviderApiRest implements RealmResourceProvider {

    private static final Logger logger = Logger.getLogger(ProviderApiRest.class);

    private final KeycloakSession session;

    private final RealmModel realm;

    private ObjectMapper mapper = new ObjectMapper();

    public ProviderApiRest(KeycloakSession session) {
        this.session = session;
        this.realm = session.getContext().getRealm();
    }

    @Override
    public Object getResource() {
        return this;
    }

    /*
        Link user by provider access token
     */
    @POST
    @Path("/{provider_id}/link-access-token")
    public Response linkByProviderAccessToken(@PathParam("provider_id") String providerId,
                                              @QueryParam("access_token") String access_token
    ) {
        //IdentityProviderModel identityProviderModel = realm.getIdentityProviderByAlias(providerId);
        AbstractOAuth2IdentityProvider provider;
        try {
            provider = getIdentityProvider(providerId);
        }
        catch (IdentityBrokerException e) {
            return response_error(e.getMessage());
        }

        IdentityProviderModel identityProviderConfig = provider.getConfig();

        // Original token {"access_token":"3d0317aa0293f6a63d0c471e8c342fa5f7608c9dcad1109f2cb455a9f8879ddb6e897181441a5fa56c784","expires_in":0,"user_id":12127217,"email":"vrag86@mail.ru"}
        String providerRequest = mapper.createObjectNode().put("access_token", access_token).toString();

        BrokeredIdentityContext context = null;
        try {
            context = provider.getFederatedIdentity(providerRequest);
        }
        catch (Exception e) {
            logger.errorf(e, "");
            return response_error("Token processing error");
        }

        try {
            if (identityProviderConfig.isStoreToken() && context.getToken() == null) {
                context.setToken(providerRequest);
            }
            context.setIdpConfig(identityProviderConfig);
            context.setIdp(provider);

            UserModel user = authenticated(context);
            return response_ok(user);
        }
        catch (IdentityBrokerException e) {
            return response_error(e.getMessage());
        }
        catch (Exception e) {
            logger.errorf(e, "");
            return response_error("Unknown error");
        }

    }

    private UserModel authenticated(BrokeredIdentityContext context) {
        context.getIdp().preprocessFederatedIdentity(this.session, this.realm, context);
        KeycloakSessionFactory sessionFactory = this.session.getKeycloakSessionFactory();

        // Вызов preprocessFederatedIdentity для каждого Attribute mapper провайдера (маппинг аттрибутов)
        this.realm.getIdentityProviderMappersByAliasStream(context.getIdpConfig().getAlias()).forEach(mapper -> {
            IdentityProviderMapper target = (IdentityProviderMapper) sessionFactory
                    .getProviderFactory(IdentityProviderMapper.class, mapper.getIdentityProviderMapper());
            target.preprocessFederatedIdentity(this.session, this.realm, mapper, context);
        });

        UserModel federatedUser = getFederatedUserFromContext(context);

        if (federatedUser != null) {
            updateFederatedIdentity(context, federatedUser);
        } else {
            federatedUser = createFederatedUserFromContext(context);
        }

        return federatedUser;
    }

    /*
        Метод для получения юзера Keycloak по авторизационному context (если юзер существует)
        Поиск идет по полям realm + ".idp." + identityProviderAlias + "." + socialUserId
     */
    private UserModel getFederatedUserFromContext (BrokeredIdentityContext context) {
        FederatedIdentityModel federatedIdentityModel = new FederatedIdentityModel(context.getIdpConfig().getAlias(), context.getId(),
                context.getUsername(), context.getToken());
        UserModel federatedUser = this.session.users().getUserByFederatedIdentity(this.realm, federatedIdentityModel);

        // try to find the user using legacy ID
        if (federatedUser == null && context.getLegacyId() != null) {
            federatedIdentityModel = new FederatedIdentityModel(federatedIdentityModel, context.getLegacyId());
            federatedUser = this.session.users().getUserByFederatedIdentity(this.realm, federatedIdentityModel);
        }

        return federatedUser;
    }

    /*
        Создание нового юзера Keycloak, если его нет
     */
    private UserModel createFederatedUserFromContext(BrokeredIdentityContext context) {
        String username = getUsername(context);
        context.setModelUsername(username);

        if (context.getEmail() != null && !this.realm.isDuplicateEmailsAllowed()) {
            UserModel existingUser = this.session.users().getUserByEmail(this.realm, context.getEmail());
            if (existingUser != null) {
                throw new IdentityBrokerException("User with email: \"" + context.getEmail() + "\" already exists");
            }
        }

        UserModel user = null;
        try {
            user = this.session.users().addUser(this.realm, context.getModelUsername());
        } catch (Exception e) {
            throw new IdentityBrokerException("Can't create user with username: \"" + context.getModelUsername() + "\"");
        }

        user.setEnabled(true);
        user.setEmail(context.getEmail());
        user.setFirstName(context.getFirstName());
        user.setLastName(context.getLastName());

        FederatedIdentityModel federatedIdentityModel = new FederatedIdentityModel(context.getIdpConfig().getAlias(), context.getId(),
                context.getUsername(), context.getToken());
        this.session.users().addFederatedIdentity(this.realm, user, federatedIdentityModel);

        context.getIdp().importNewUser(this.session, this.realm, user, context);

        Set<IdentityProviderMapperModel> mappers = this.realm.getIdentityProviderMappersByAliasStream(context.getIdpConfig().getAlias())
                .collect(Collectors.toSet());
        KeycloakSessionFactory sessionFactory = this.session.getKeycloakSessionFactory();

        // Вызов методов importNewUser в каждом классе IdentityProviderMapper (маппер аттрибутов)
        for (IdentityProviderMapperModel mapper : mappers) {
            IdentityProviderMapper target = (IdentityProviderMapper)sessionFactory.getProviderFactory(IdentityProviderMapper.class, mapper.getIdentityProviderMapper());
            target.importNewUser(this.session, this.realm, user, mapper, context);
        }

        if (context.getIdpConfig().isTrustEmail() && !Validation.isBlank(user.getEmail())) {
            this.logger.debugf("Email verified automatically after registration of user '%s' through Identity provider '%s' ", user.getUsername(), context.getIdpConfig().getAlias());
            user.setEmailVerified(true);
        }
        updateFederatedIdentity(context, user);
        return user;
    }

    private String getUsername(BrokeredIdentityContext context) {
        String username = context.getModelUsername();
        if (username == null) {
            String usernameFromAttribute = context.getUserAttribute("username");
            if (!Validation.isBlank(usernameFromAttribute)) {
                username = usernameFromAttribute;
            }
            else if (this.realm.isRegistrationEmailAsUsername() && !Validation.isBlank(context.getEmail())) {
                username = context.getEmail();
            } else if (context.getUsername() == null) {
                username = context.getIdpConfig().getAlias() + "." + context.getId();
            } else {
                username = context.getUsername();
            }
        }
        username = username.trim();
        return username;
    }

    /*
        Обновление значений полей из attribute mappers
     */
    private void updateFederatedIdentity(BrokeredIdentityContext context, UserModel federatedUser) {
        FederatedIdentityModel federatedIdentityModel = this.session.users().getFederatedIdentity(this.realm, federatedUser, context.getIdpConfig().getAlias());

        if (context.getIdpConfig().getSyncMode() == IdentityProviderSyncMode.FORCE) {
            setBasicUserAttributes(context, federatedUser);
        }

        // Skip DB write if tokens are null or equal
        updateToken(context, federatedUser, federatedIdentityModel);
        context.getIdp().updateBrokeredUser(this.session, this.realm, federatedUser, context);
        KeycloakSessionFactory sessionFactory = this.session.getKeycloakSessionFactory();
        this.realm.getIdentityProviderMappersByAliasStream(context.getIdpConfig().getAlias()).forEach(mapper -> {
            IdentityProviderMapper target = (IdentityProviderMapper) sessionFactory
                    .getProviderFactory(IdentityProviderMapper.class, mapper.getIdentityProviderMapper());
            IdentityProviderMapperSyncModeDelegate.delegateUpdateBrokeredUser(this.session, this.realm, federatedUser, mapper, context, target);
        });
    }

    private void setBasicUserAttributes(BrokeredIdentityContext context, UserModel federatedUser) {
        setDiffAttrToConsumer(federatedUser.getEmail(), context.getEmail(), federatedUser::setEmail);
        setDiffAttrToConsumer(federatedUser.getFirstName(), context.getFirstName(), federatedUser::setFirstName);
        setDiffAttrToConsumer(federatedUser.getLastName(), context.getLastName(), federatedUser::setLastName);
    }

    private void setDiffAttrToConsumer(String actualValue, String newValue, Consumer<String> consumer) {
        String actualValueNotNull = Optional.ofNullable(actualValue).orElse("");
        if (newValue != null && !newValue.equals(actualValueNotNull)) {
            consumer.accept(newValue);
        }
    }

    private void updateToken(BrokeredIdentityContext context, UserModel federatedUser, FederatedIdentityModel federatedIdentityModel) {
        if (context.getIdpConfig().isStoreToken() && !ObjectUtil.isEqualOrBothNull(context.getToken(), federatedIdentityModel.getToken())) {
            federatedIdentityModel.setToken(context.getToken());

            this.session.users().updateFederatedIdentity(this.realm, federatedUser, federatedIdentityModel);

            this.logger.debugf("Identity [%s] update with response from identity provider [%s].", federatedUser, context.getIdpConfig().getAlias());
        }
    }

    private AbstractOAuth2IdentityProvider getIdentityProvider(String alias) {
        IdentityProviderModel identityProviderModel = this.realm.getIdentityProviderByAlias(alias);

        if (identityProviderModel != null) {
            IdentityProviderFactory providerFactory = getIdentityProviderFactory(this.session, identityProviderModel);

            if (providerFactory == null) {
                throw new IdentityBrokerException("Could not find factory for identity provider [" + alias + "].");
            }

            try {
                AbstractOAuth2IdentityProvider prov = (AbstractOAuth2IdentityProvider) providerFactory.create(this.session, identityProviderModel);
                return prov;
            }
            catch (Exception e) {
                throw new IdentityBrokerException("Could not convert provider to AbstractOAuth2IdentityProvider" +  e.getMessage());
            }
        }

        throw new IdentityBrokerException("Identity Provider [" + alias + "] not found.");
    }

    private Response response_error (String msg)  {
        JsonNode node = mapper
                .createObjectNode()
                .put("success", 0)
                .set("error", mapper.createObjectNode().put("msg", msg));

        return Response.status(500).type(APPLICATION_JSON_TYPE).entity(node.toString()).build();
    }

    private Response response_ok (UserModel user)  {
        JsonNode node = mapper
                .createObjectNode()
                .put("success", 1)
                .set("user", mapper.createObjectNode().put("id", user.getId()));

        return Response.status(200).type(APPLICATION_JSON_TYPE).entity(node.toString()).build();
    }

    @Override
    public void close() {
    }
}
