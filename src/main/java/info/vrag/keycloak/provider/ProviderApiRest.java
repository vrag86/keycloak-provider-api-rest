package info.vrag.keycloak.provider;

import org.jboss.logging.Logger;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;

import org.keycloak.broker.provider.*;
import org.keycloak.models.*;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.sessions.AuthenticationSessionModel;

import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Response;

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
        BrokeredIdentityContext context;
        try {
            context = provider.getFederatedIdentity(providerRequest);
        }
        catch (Exception e) {
            return response_error(e.getMessage());
        }

        if (identityProviderConfig.isStoreToken() && context.getToken() == null) {
            context.setToken(providerRequest);
        }
        context.setIdpConfig(identityProviderConfig);
        context.setIdp(provider);

        return authenticated(context, provider);

     //   return response_error("Hello " + context.getId());
    }



    private Response authenticated(BrokeredIdentityContext context, AbstractOAuth2IdentityProvider provider) {
        IdentityProviderModel identityProviderConfig = provider.getConfig();
        AuthenticationSessionModel authenticationSession = context.getAuthenticationSession();


        //   this.session.getContext().setClient(client);

        // Вызов preprocessFederatedIdentity для каждого Attribute mapper провайдера (маппинг аттрибутов)
        context.getIdp().preprocessFederatedIdentity(this.session, this.realm, context);
        KeycloakSessionFactory sessionFactory = this.session.getKeycloakSessionFactory();
        this.realm.getIdentityProviderMappersByAliasStream(context.getIdpConfig().getAlias()).forEach(mapper -> {
            IdentityProviderMapper target = (IdentityProviderMapper) sessionFactory
                    .getProviderFactory(IdentityProviderMapper.class, mapper.getIdentityProviderMapper());
            target.preprocessFederatedIdentity(this.session, this.realm, mapper, context);
        });

        UserModel federatedUser = getFederatedUserFromContext(context, provider);
        String userInfo = "Username: " + context.getUserAttribute("username") + " Id: " + context.getId() + " Token: " + context.getToken() + " Legacuy id: " + context.getLegacyId();

        if (federatedUser != null) {
            return response_error("Federated user found " + userInfo);
        }
        return response_error("Federated user not found. " + userInfo);

        /*
        context.getIdp().importNewUser(session, realm, federatedUser, context);

        if (federatedUser == null) {

            logger.debugf("Federated user not found for provider '%s' and broker username '%s'", providerId, context.getUsername());

            String username = context.getModelUsername();
            if (username == null) {
                if (realm.isRegistrationEmailAsUsername() && !Validation.isBlank(context.getEmail())) {
                    username = context.getEmail();
                } else if (context.getUsername() == null) {
                    username = context.getIdpConfig().getAlias() + "." + context.getId();
                } else {
                    username = context.getUsername();
                }
            }
            username = username.trim();
            context.setModelUsername(username);


            SerializedBrokeredIdentityContext ctx0 = SerializedBrokeredIdentityContext.readFromAuthenticationSession(authenticationSession, AbstractIdpAuthenticator.BROKERED_CONTEXT_NOTE);
            if (ctx0 != null) {
                SerializedBrokeredIdentityContext ctx1 = SerializedBrokeredIdentityContext.serialize(context);
                ctx1.saveToAuthenticationSession(authenticationSession, AbstractIdpAuthenticator.NESTED_FIRST_BROKER_CONTEXT);
                logger.warnv("Nested first broker flow detected: {0} -> {1}", ctx0.getIdentityProviderId(), ctx1.getIdentityProviderId());
                logger.debug("Resuming last execution");
                URI redirect = new AuthenticationFlowURLHelper(session, realmModel, session.getContext().getUri())
                        .getLastExecutionUrl(authenticationSession);
                return Response.status(Status.FOUND).location(redirect).build();
            }

            logger.debug("Redirecting to flow for firstBrokerLogin");

            boolean forwardedPassiveLogin = "true".equals(authenticationSession.getAuthNote(AuthenticationProcessor.FORWARDED_PASSIVE_LOGIN));
            // Redirect to firstBrokerLogin after successful login and ensure that previous authentication state removed
            AuthenticationProcessor.resetFlow(authenticationSession, LoginActionsService.FIRST_BROKER_LOGIN_PATH);

            // Set the FORWARDED_PASSIVE_LOGIN note (if needed) after resetting the session so it is not lost.
            if (forwardedPassiveLogin) {
                authenticationSession.setAuthNote(AuthenticationProcessor.FORWARDED_PASSIVE_LOGIN, "true");
            }

            SerializedBrokeredIdentityContext ctx = SerializedBrokeredIdentityContext.serialize(context);
            ctx.saveToAuthenticationSession(authenticationSession, AbstractIdpAuthenticator.BROKERED_CONTEXT_NOTE);

            URI redirect = LoginActionsService.firstBrokerLoginProcessor(session.getContext().getUri())
                    .queryParam(Constants.CLIENT_ID, authenticationSession.getClient().getClientId())
                    .queryParam(Constants.TAB_ID, authenticationSession.getTabId())
                    .build(realmModel.getName());
            return Response.status(302).location(redirect).build();

        }
        /*
        else {
            Response response = validateUser(authenticationSession, federatedUser, realmModel);
            if (response != null) {
                return response;
            }

            updateFederatedIdentity(context, federatedUser);
            if (shouldMigrateId) {
                migrateFederatedIdentityId(context, federatedUser);
            }
            authenticationSession.setAuthenticatedUser(federatedUser);

            return finishOrRedirectToPostBrokerLogin(authenticationSession, context, false);
        }
         */
    }

    /*
        Метод для получег=ния юзера Keycloak по авторизационному context (если юзер существует)
        Поиск идет по полям realm + ".idp." + identityProviderAlias + "." + socialUserId
     */
    private UserModel getFederatedUserFromContext (BrokeredIdentityContext context, AbstractOAuth2IdentityProvider provider) {
        IdentityProviderModel identityProviderConfig = provider.getConfig();
        String providerId = identityProviderConfig.getAlias();

        // try to find the user using legacy ID
        FederatedIdentityModel federatedIdentityModel = new FederatedIdentityModel(providerId, context.getId(),
                context.getUsername(), context.getToken());
        UserModel federatedUser = this.session.users().getUserByFederatedIdentity(realm, federatedIdentityModel);

        // try to find the user using legacy ID
        if (federatedUser == null && context.getLegacyId() != null) {
            federatedIdentityModel = new FederatedIdentityModel(federatedIdentityModel, context.getLegacyId());
            federatedUser = this.session.users().getUserByFederatedIdentity(realm, federatedIdentityModel);
        }

        return federatedUser;
    }

    private Response response_error (String msg)  {
        JsonNode node = mapper
                .createObjectNode()
                .put("success", 0)
                .set("error", mapper.createObjectNode().put("msg", msg));

        return Response.status(500).type(APPLICATION_JSON_TYPE).entity(node.toString()).build();
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


    @Override
    public void close() {
    }

}
