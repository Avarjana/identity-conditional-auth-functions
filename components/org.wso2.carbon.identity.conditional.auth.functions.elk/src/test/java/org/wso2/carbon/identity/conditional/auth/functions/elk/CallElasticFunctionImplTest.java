/*
 *  Copyright (c) 2021, WSO2 Inc. (http://www.wso2.com).
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.wso2.carbon.identity.conditional.auth.functions.elk;


import com.google.gson.Gson;
import org.json.JSONObject;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.config.model.SequenceConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.dao.impl.CacheBackedLongWaitStatusDAO;
import org.wso2.carbon.identity.application.authentication.framework.dao.impl.LongWaitStatusDAOImpl;
import org.wso2.carbon.identity.application.authentication.framework.internal.FrameworkServiceDataHolder;
import org.wso2.carbon.identity.application.authentication.framework.store.LongWaitStatusStoreService;
import org.wso2.carbon.identity.application.common.model.LocalAndOutboundAuthenticationConfig;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.model.script.AuthenticationScriptConfig;
import org.wso2.carbon.identity.common.testng.InjectMicroservicePort;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithH2Database;
import org.wso2.carbon.identity.common.testng.WithMicroService;
import org.wso2.carbon.identity.common.testng.WithRealmService;
import org.wso2.carbon.identity.conditional.auth.functions.common.utils.ConfigProvider;
import org.wso2.carbon.identity.conditional.auth.functions.test.utils.sequence.JsSequenceHandlerAbstractTest;
import org.wso2.carbon.identity.conditional.auth.functions.test.utils.sequence.JsTestException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.msf4j.Response;

import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.*;
import javax.ws.rs.core.Context;

import static org.testng.Assert.assertEquals;

@WithCarbonHome
@WithMicroService
@WithH2Database(files = {"dbscripts/h2_http.sql"})
@WithRealmService(injectToSingletons = {IdentityTenantUtil.class, FrameworkServiceDataHolder.class})
@Path("/")
public class CallElasticFunctionImplTest extends JsSequenceHandlerAbstractTest {

    private static final String TEST_SP_CONFIG = "http-post-test-sp.xml";
    private static final String TENANT_DOMAIN = "carbon.super";
    private static final String FAILED = "FAILED";
    private static final String ALLOWED_DOMAIN = "abc";
    private static final String ELASTIC_PAYLOAD_TEMPLATE = "{\"risk_score\":{\"value\":%d}}";
    private static final Gson gsonInstance = new Gson();

    @InjectMicroservicePort
    private int microServicePort;

    @BeforeClass
    protected void initClass() throws Exception {

        super.setUp();
        LongWaitStatusDAOImpl daoImpl = new LongWaitStatusDAOImpl();
        CacheBackedLongWaitStatusDAO cacheBackedDao = new CacheBackedLongWaitStatusDAO(daoImpl);
        int connectionTimeout = 5000;
        LongWaitStatusStoreService longWaitStatusStoreService =
                new LongWaitStatusStoreService(cacheBackedDao, connectionTimeout);
        FrameworkServiceDataHolder.getInstance().setLongWaitStatusStoreService(longWaitStatusStoreService);
        sequenceHandlerRunner.registerJsFunction("callElastic", new CallElasticFunctionImpl() {
        });
    }

    @AfterClass
    protected void tearDown() {

        unsetAllowedDomains();
    }

    @Test(dataProvider = "elasticAuthDataProvider")
    public void testCallElasticMethodAuth(String username, String elasticUsername, String elasticPassword) throws JsTestException {

        String requestUrl = getRequestUrl();
        String result = executeCallElasticFunction(requestUrl, username, elasticUsername, elasticPassword);

        assertEquals(result, FAILED, "The elasticsearch request was not successful. Result from request: ");
    }

    @Test(dataProvider = "elasticPayloadDataProvider")
    public void testCallElasticMethodPayload(String username, String elasticUsername, String elasticPassword, String riskScore) throws JsTestException {

        String requestUrl = getRequestUrl();

        String result = executeCallElasticFunction(requestUrl, username, elasticUsername, elasticPassword);

        assertEquals(result, riskScore, "The elasticsearch score value is wrong.");
    }

    @Test(dependsOnMethods = {"testCallElasticMethodAuth", "testCallElasticMethodPayload"}, dataProvider = "elasticDefaultDataProvider")
    public void testCallElasticMethodUrlValidation(String username, String elasticUsername, String elasticPassword) throws JsTestException {

        setAllowedDomain();
        String requestUrl = getRequestUrl();
        String result = executeCallElasticFunction(requestUrl, username, elasticUsername, elasticPassword);

        assertEquals(result, FAILED, "The elasticsearch request should fail but it was successful.");
    }

    private void setAllowedDomain() {

        ConfigProvider.getInstance().getAllowedDomainsForHttpFunctions().add(ALLOWED_DOMAIN);
    }

    private void unsetAllowedDomains() {

        ConfigProvider.getInstance().getAllowedDomainsForHttpFunctions().clear();
    }

    private String getRequestUrl() {

        return "http://localhost:" + microServicePort;
    }

    private String executeCallElasticFunction(String requestUrl, String username, String elasticUsername, String elasticPassword) throws JsTestException {

        ServiceProvider sp = sequenceHandlerRunner.loadServiceProviderFromResource(TEST_SP_CONFIG, this);
        updateSPAuthScript(sp, requestUrl, username, elasticUsername, elasticPassword);

        AuthenticationContext context = sequenceHandlerRunner.createAuthenticationContext(sp);
        SequenceConfig sequenceConfig = sequenceHandlerRunner.getSequenceConfig(context, sp);
        context.setSequenceConfig(sequenceConfig);
        context.initializeAnalyticsData();

        HttpServletRequest req = sequenceHandlerRunner.createHttpServletRequest();
        HttpServletResponse resp = sequenceHandlerRunner.createHttpServletResponse();

        sequenceHandlerRunner.handle(req, resp, context, TENANT_DOMAIN);

        // Using selected acr as a mechanism to relay the
        // auth script execution state back to the context.
        return context.getSelectedAcr();
    }

    private void updateSPAuthScript(ServiceProvider sp, String url, String username, String elasticUsername, String elasticPassword) {

        LocalAndOutboundAuthenticationConfig localAndOutboundAuthenticationConfig =
                sp.getLocalAndOutBoundAuthenticationConfig();
        AuthenticationScriptConfig authenticationScriptConfig = localAndOutboundAuthenticationConfig
                .getAuthenticationScriptConfig();
        String script = authenticationScriptConfig.getContent();
        authenticationScriptConfig.setContent(String.format(script, url, username, elasticUsername, elasticPassword));
        localAndOutboundAuthenticationConfig.setAuthenticationScriptConfig(authenticationScriptConfig);
        sp.setLocalAndOutBoundAuthenticationConfig(localAndOutboundAuthenticationConfig);
    }

    private String elsticPayloadGenerator(String username) {
        if (username.equals("riskyUser")) {
            return String.format(ELASTIC_PAYLOAD_TEMPLATE, 2);
        } else {
            return String.format(ELASTIC_PAYLOAD_TEMPLATE, 0);
        }
    }

    @POST
    @Path("/auth-wso2-is/_search")
    @Consumes("application/json")
    public String dummyPost(Map<String, Object> data, @Context Response res, @HeaderParam("Authorization") String authHeader) {

        Map<String, Object> response = new HashMap<>();

        if (!isValidElasticCredentials(authHeader)) {
            res.setStatus(401);
            return "{}";
        }

        String jsonQuery = gsonInstance.toJson(data.get("query"));
        JSONObject query = new JSONObject(jsonQuery);

        String username = query
                .getJSONObject("bool")
                .getJSONArray("must")
                .getJSONObject(0)
                .getJSONObject("match")
                .getString("event.payloadData.username.keyword");

        Object aggregations = gsonInstance.fromJson(elsticPayloadGenerator(username), Object.class);

        response.put("aggregations", aggregations);

        return gsonInstance.toJson(response);
    }

    private boolean isValidElasticCredentials(String authHeader) {
        String authHeaderDecoded = new String(Base64.getDecoder().decode(authHeader.split(" ")[1]));
        return authHeaderDecoded.equals("elasticUsername:elasticPassword");
    }

    @DataProvider(name = "elasticAuthDataProvider")
    public Object[][] elasticDataProvider() {

        return new Object[][]{
                {"user", "otherUsername", "elasticPassword"},
                {"user", "elasticUsername", "otherPassword"},
                {"user", "otherUsername", "otherPassword"}
        };
    }

    @DataProvider(name = "elasticPayloadDataProvider")
    public Object[][] elasticPayloadDataProvider() {

        return new Object[][]{
                {"nonRiskyUser", "elasticUsername", "elasticPassword", "0.0"},
                {"riskyUser", "elasticUsername", "elasticPassword", "2.0"}
        };
    }

    @DataProvider(name = "elasticDefaultDataProvider")
    public Object[][] elasticDefaultDataProvider() {

        return new Object[][]{
                {"user", "elasticUsername", "elasticPassword"}
        };
    }
}
